"""Socket-level egress jail.

Most "local AI" setups are local *by configuration*. A configuration flag is a
promise; this module is enforcement.

While the jail is active it patches the socket layer so that:

* any TCP connection to a non-loopback address fails immediately, and
* any hostname lookup for a non-loopback name fails immediately (a DNS query is
  itself egress and leaks the domain you were about to contact),

and every blocked attempt is recorded, so the block is auditable rather than
merely asserted. Loopback and UNIX-domain sockets keep working, which is all a
local model server (Ollama, llama.cpp, vLLM, LM Studio) needs.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

__all__ = ["EgressBlocked", "EgressJail", "is_loopback_target", "is_loopback_host"]

# Names that resolve to the loopback interface without touching the network.
LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


class EgressBlocked(RuntimeError):
    """Raised when code inside the jail tries to reach the network."""


def _loopback_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def is_loopback_host(host: Any) -> bool:
    """True when *host* is loopback without needing a DNS lookup."""
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("utf-8", "replace")
    host = str(host).strip().strip("[]")
    if host == "" or host in LOCAL_NAMES:
        return True
    return _loopback_ip(host)


def is_loopback_target(address: Any) -> bool:
    """True when a socket address (``(host, port)`` or a UNIX path) is local."""
    if isinstance(address, (str, bytes)):
        # AF_UNIX path -> local by definition
        return True
    if isinstance(address, tuple) and address:
        return is_loopback_host(address[0])
    return False


@dataclass
class EgressJail:
    """Context manager that hard-blocks non-loopback egress.

    Example
    -------
    >>> with EgressJail() as jail:            # doctest: +SKIP
    ...     answer = ask_local("summarise this clause")
    ...     print(jail.report())
    """

    audit_path: Path | None = None
    label: str = "jail"
    blocked: list[dict] = field(default_factory=list)
    allowed_loopback: int = 0
    _active: bool = False
    _original_connect: Any = None
    _original_connect_ex: Any = None
    _original_create_connection: Any = None
    _original_getaddrinfo: Any = None

    # ---------------------------------------------------------------- lifecycle
    def __enter__(self) -> "EgressJail":
        if self._active:  # already inside a jail: nesting is a no-op
            return self
        self._original_connect = socket.socket.connect
        self._original_connect_ex = socket.socket.connect_ex
        self._original_create_connection = socket.create_connection
        self._original_getaddrinfo = socket.getaddrinfo
        jail = self  # closures below must be plain functions: they are installed
        # on the socket class, so Python passes the socket instance as the first
        # positional argument (installing a bound method here breaks the call).

        def connect_patch(sock, address):  # noqa: ANN001
            return jail._guarded_connect(sock, address)

        def connect_ex_patch(sock, address):  # noqa: ANN001
            return jail._guarded_connect_ex(sock, address)

        def create_connection_patch(address, *args, **kwargs):  # noqa: ANN001
            return jail._guarded_create_connection(address, *args, **kwargs)

        def getaddrinfo_patch(host, *args, **kwargs):  # noqa: ANN001
            return jail._guarded_getaddrinfo(host, *args, **kwargs)

        socket.socket.connect = connect_patch          # type: ignore[assignment]
        socket.socket.connect_ex = connect_ex_patch    # type: ignore[assignment]
        socket.create_connection = create_connection_patch  # type: ignore[assignment]
        socket.getaddrinfo = getaddrinfo_patch         # type: ignore[assignment]
        self._active = True
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if not self._active:
            return False
        socket.socket.connect = self._original_connect          # type: ignore[assignment]
        socket.socket.connect_ex = self._original_connect_ex    # type: ignore[assignment]
        socket.create_connection = self._original_create_connection  # type: ignore[assignment]
        socket.getaddrinfo = self._original_getaddrinfo         # type: ignore[assignment]
        self._active = False
        self._flush()
        return False

    # ------------------------------------------------------------------ guards
    def _record(self, kind: str, target: str) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "label": self.label,
            "kind": kind,
            "target": target,
            "action": "blocked",
        }
        self.blocked.append(entry)
        if self.audit_path:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")

    def _flush(self) -> None:
        return None

    def _guarded_connect(self, sock: socket.socket, address: Any):  # noqa: ANN001
        if sock.family in (socket.AF_INET, socket.AF_INET6) and not is_loopback_target(address):
            self._record("connect", _fmt(address))
            raise EgressBlocked(
                f"egress blocked: {_fmt(address)} is not loopback "
                f"(policy={self.label})"
            )
        self.allowed_loopback += 1
        return self._original_connect(sock, address)

    def _guarded_connect_ex(self, sock: socket.socket, address: Any):  # noqa: ANN001
        if sock.family in (socket.AF_INET, socket.AF_INET6) and not is_loopback_target(address):
            self._record("connect_ex", _fmt(address))
            return 111  # ECONNREFUSED: a connection that never left the machine
        self.allowed_loopback += 1
        return self._original_connect_ex(sock, address)

    def _guarded_create_connection(self, address: Any, *args: Any, **kwargs: Any):  # noqa: ANN001
        if not is_loopback_target(address):
            self._record("create_connection", _fmt(address))
            raise EgressBlocked(f"egress blocked: {_fmt(address)} is not loopback")
        self.allowed_loopback += 1
        return self._original_create_connection(address, *args, **kwargs)

    def _guarded_getaddrinfo(self, host: Any, *args: Any, **kwargs: Any):  # noqa: ANN001
        if not is_loopback_host(host):
            self._record("getaddrinfo", str(host))
            raise EgressBlocked(
                f"DNS lookup blocked: {host!r} is not a loopback name "
                "(a lookup is itself egress)"
            )
        return self._original_getaddrinfo(host, *args, **kwargs)

    # ------------------------------------------------------------------ reports
    @property
    def blocked_count(self) -> int:
        return len(self.blocked)

    def report(self) -> dict:
        return {
            "policy": self.label,
            "loopback_connections": self.allowed_loopback,
            "blocked_attempts": self.blocked_count,
            "blocked": self.blocked,
            "audit_file": str(self.audit_path) if self.audit_path else None,
        }

    def report_text(self) -> str:
        lines = [
            f"egress policy      : {self.label} (loopback only)",
            f"loopback sockets   : {self.allowed_loopback}",
            f"blocked attempts   : {self.blocked_count}",
        ]
        for item in self.blocked:
            lines.append(f"  - {item['kind']:16s} {item['target']}")
        if self.audit_path:
            lines.append(f"audit log          : {self.audit_path}")
        return "\n".join(lines)


def _fmt(address: Any) -> str:
    if isinstance(address, tuple) and len(address) >= 2:
        return f"{address[0]}:{address[1]}"
    return str(address)


def block_probe(hosts: Iterable[str] = ("api.openai.com", "api.deepseek.com", "1.1.1.1"), timeout: float = 3.0) -> list[dict]:
    """Deliberately try to reach the outside world.

    Call this *inside* an active :class:`EgressJail`: each attempt is a real
    ``socket.connect`` / DNS lookup, so the returned records are evidence rather
    than claims. A record with ``blocked: False`` means the jail failed.
    """
    results: list[dict] = []
    for host in hosts:
        entry: dict[str, Any] = {"host": host, "blocked": False, "mechanism": None, "detail": ""}
        # 1) DNS resolution attempt (leaks nothing when blocked).
        try:
            socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            entry["detail"] = "DNS resolution succeeded - jail did NOT block the lookup"
        except EgressBlocked as exc:
            entry["blocked"] = True
            entry["mechanism"] = "socket.getaddrinfo()"
            entry["detail"] = str(exc)
        except OSError as exc:
            entry["detail"] = f"DNS error without jail block: {exc}"
        # 2) Direct connection attempt to a literal address or the hostname.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, 443))
            entry["blocked"] = False
            entry["mechanism"] = None
            entry["detail"] = "connection SUCCEEDED - jail failed"
        except EgressBlocked as exc:
            entry["blocked"] = True
            entry["mechanism"] = (entry["mechanism"] or "") + " socket.connect()"
            entry["detail"] += (" | " if entry["detail"] else "") + str(exc)
        except OSError as exc:
            # No jail in the way (e.g. no route / refused) - not proof of a block.
            entry["detail"] += (" | " if entry["detail"] else "") + f"OS error without jail block: {exc}"
        results.append(entry)
    return results
