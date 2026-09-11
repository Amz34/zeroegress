"""Minimal local-model client (standard library only).

Talks to an OpenAI-compatible or Ollama-native endpoint that MUST be loopback.
The guard is deliberate: this module physically refuses to be pointed at a cloud
endpoint, so a bad environment variable cannot silently turn "local" mode into a
cloud call.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .jail import is_loopback_host

DEFAULT_HOST = os.environ.get("ZEROEGRESS_LLM_HOST", os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))
DEFAULT_MODEL = os.environ.get("ZEROEGRESS_MODEL", os.environ.get("OLLAMA_MODEL", "llama3.2:3b"))


class NonLocalEndpoint(RuntimeError):
    """Raised when a non-loopback model endpoint is configured."""


@dataclass
class Reply:
    text: str
    model: str
    host: str
    done_reason: str = ""
    raw: dict | None = None


def _assert_local(host: str) -> str:
    parsed = urllib.parse.urlparse(host if "://" in host else f"http://{host}")
    if parsed.scheme not in ("http", "https"):
        raise NonLocalEndpoint(f"unsupported scheme: {parsed.scheme!r}")
    if not is_loopback_host(parsed.hostname):
        raise NonLocalEndpoint(
            f"refusing non-loopback model endpoint {host!r}: zeroegress only talks to a "
            "local server (Ollama on 127.0.0.1, llama.cpp, vLLM, LM Studio)"
        )
    return host.rstrip("/")


def _post(url: str, payload: dict, timeout: float) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - loopback only
        return json.loads(resp.read().decode("utf-8"))


def available(host: str = DEFAULT_HOST, timeout: float = 4.0) -> list[str]:
    """List models served by the local runtime (empty list when it is down)."""
    host = _assert_local(host)
    try:
        req = urllib.request.Request(f"{host}/api/tags")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []
    return sorted(m.get("name", "") for m in data.get("models", []) if m.get("name"))


def chat(
    messages: list[dict],
    model: str = DEFAULT_MODEL,
    host: str = DEFAULT_HOST,
    timeout: float = 900.0,
    temperature: float = 0.2,
    num_ctx: int | None = None,
    keep_alive: str | int | None = None,
) -> Reply:
    """Send a chat request to the local model server."""
    host = _assert_local(host)
    options: dict = {"temperature": temperature}
    if num_ctx:
        options["num_ctx"] = num_ctx
    payload: dict = {"model": model, "messages": messages, "stream": False, "options": options}
    if keep_alive is not None:
        payload["keep_alive"] = keep_alive
    try:
        data = _post(f"{host}/api/chat", payload, timeout)
    except urllib.error.HTTPError as exc:  # surface a readable message
        body = exc.read().decode("utf-8", "replace")[:400]
        raise RuntimeError(f"local model server returned HTTP {exc.code}: {body}") from exc
    msg = data.get("message") or {}
    return Reply(
        text=(msg.get("content") or "").strip(),
        model=data.get("model", model),
        host=host,
        done_reason=data.get("done_reason", ""),
        raw=data,
    )


def ask(
    prompt: str,
    system: str | None = None,
    model: str = DEFAULT_MODEL,
    host: str = DEFAULT_HOST,
    **kwargs,
) -> Reply:
    """Single-turn convenience wrapper around :func:`chat`."""
    messages: list[dict] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    return chat(messages, model=model, host=host, **kwargs)


def health(host: str = DEFAULT_HOST) -> dict:
    """Report whether the local runtime is reachable and which models it serves."""
    host = _assert_local(host)
    models = available(host)
    return {"host": host, "up": bool(models), "models": models, "default_model": DEFAULT_MODEL}
