"""zeroegress command line interface."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from . import gate as gate_mod
from . import local_llm, trustpack, vault as vault_mod
from .jail import EgressJail, block_probe

VERSION = "0.1.0"
DEFAULT_AUDIT = Path.home() / ".config" / "zeroegress" / "egress-attempts.jsonl"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_LOCAL_ONLY = 10
EXIT_HIGH = 11


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _read_text(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    path = Path(source).expanduser()
    if not path.exists():
        raise SystemExit(f"not found: {path}")
    if path.is_dir():
        raise SystemExit(f"{path} is a directory (use `zeroegress scan`)")
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc


def _client_names(path: str | None) -> list[str]:
    if not path:
        return []
    file = Path(path).expanduser()
    if not file.exists():
        raise SystemExit(f"client name list not found: {file}")
    return [line.strip() for line in file.read_text(encoding="utf-8").splitlines() if line.strip()]


def _jail(args) -> EgressJail:
    audit = None if getattr(args, "no_audit", False) else DEFAULT_AUDIT
    return EgressJail(audit_path=audit, label=getattr(args, "label", "zeroegress"))


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_status(args) -> int:
    health = local_llm.health()
    api_keys = [k for k in os.environ if k.endswith(("_API_KEY", "_TOKEN", "_SECRET"))]
    rows = [
        ("zeroegress", VERSION),
        ("python", sys.version.split()[0]),
        ("gpg", "present" if vault_mod.gpg_available() else "MISSING (vaults disabled)"),
        ("chrome (trust pack pdf)", trustpack.find_chrome() or "not found (HTML output only)"),
        ("local model server", f"{health['host']} | {'UP' if health['up'] else 'DOWN'}"),
        ("models served", ", ".join(health["models"]) or "-"),
        ("default model", health["default_model"]),
        ("vault root", str(vault_mod.DEFAULT_ROOT)),
        ("key directory", str(vault_mod.DEFAULT_KEYDIR)),
        ("egress policy", "loopback-only jail on every `ask`/`prove`"),
        ("provider secrets in env", ", ".join(sorted(api_keys)) or "none"),
        ("egress audit log", str(DEFAULT_AUDIT) if DEFAULT_AUDIT.exists() else "not created yet"),
    ]
    width = max(len(k) for k, _ in rows)
    for key, value in rows:
        print(f"{key.ljust(width)} : {value}")
    return EXIT_OK


def cmd_gate(args) -> int:
    text = _read_text(args.source)
    verdict = gate_mod.classify(text, client_names=_client_names(args.client_names))
    if args.deep:
        verdict = _deep_confirm(text, verdict, model=args.model)
    if args.json:
        print(json.dumps(verdict.as_dict(), indent=2))
    else:
        print(verdict.summary())
    if args.redacted_out and verdict.level != gate_mod.Level.LOW:
        redacted, count = gate_mod.redact(text)
        Path(args.redacted_out).expanduser().write_text(redacted, encoding="utf-8")
        print(f"\nredacted copy written: {args.redacted_out} ({count} identifier(s) replaced)")
    return verdict.exit_code


def _deep_confirm(text: str, verdict: gate_mod.Verdict, model: str | None = None) -> gate_mod.Verdict:
    """Let the local model confirm a borderline verdict (never lowers safety)."""
    if verdict.level is gate_mod.Level.LOW and verdict.score == 0:
        return verdict
    prompt = (
        "You are a data-protection reviewer. Answer with one line only: "
        "'CONFIDENTIAL: yes' or 'CONFIDENTIAL: no', then a 12-word reason.\n\n"
        f"TEXT:\n{text[:6000]}"
    )
    try:
        with _jail(argparse.Namespace(no_audit=False, label="gate-deep")):
            reply = local_llm.ask(prompt, model=model or local_llm.DEFAULT_MODEL)
    except Exception as exc:  # noqa: BLE001 - the deterministic verdict always stands
        print(f"[gate] local confirm unavailable ({exc}); using deterministic verdict")
        return verdict
    verdict.findings.append(
        gate_mod.Finding(kind="local_model_confirm", weight=0, note=reply.text.splitlines()[0][:120] if reply.text else "no answer")
    )
    if "confidential: yes" in reply.text.lower() and verdict.level is gate_mod.Level.LOW:
        verdict.level = gate_mod.Level.MEDIUM
        verdict.score = max(verdict.score, gate_mod.MEDIUM_THRESHOLD)
    return verdict


def cmd_redact(args) -> int:
    text = _read_text(args.source)
    redacted, count = gate_mod.redact(text)
    if args.out:
        Path(args.out).expanduser().write_text(redacted, encoding="utf-8")
        print(f"{count} identifier(s) replaced -> {args.out}")
    else:
        print(redacted)
    return EXIT_OK


def cmd_ask(args) -> int:
    prompt = args.prompt
    if args.file:
        prompt = f"{prompt}\n\nDOCUMENT:\n{_read_text(args.file)}" if prompt else _read_text(args.file)
    if not prompt:
        raise SystemExit("nothing to ask: pass a prompt or --file")
    jail = _jail(args)
    with jail:
        reply = local_llm.ask(
            prompt,
            system=args.system,
            model=args.model,
            host=args.host,
            temperature=args.temperature,
            num_ctx=args.num_ctx,
        )
    print(reply.text)
    if args.report:
        print("\n" + jail.report_text(), file=sys.stderr)
    if jail.blocked_count and not args.allow_blocked:
        print(f"[jail] {jail.blocked_count} blocked egress attempt(s) logged", file=sys.stderr)
    return EXIT_OK


def cmd_prove(args) -> int:
    """Prove the local path: block the network, then answer anyway."""
    print("zeroegress prove - evidence, not a promise\n")
    jail = _jail(args)
    with jail:
        probes = block_probe(args.hosts, timeout=args.timeout)
        reply = None
        error = None
        try:
            reply = local_llm.ask(
                args.prompt,
                model=args.model,
                host=args.host,
                num_ctx=args.num_ctx,
            )
        except Exception as exc:  # noqa: BLE001 - report, don't crash the proof
            error = str(exc)

    print("1) egress attempts made while the jail was active")
    for row in probes:
        mark = "BLOCKED " if row["blocked"] else "ALLOWED!"
        print(f"   {mark} {row['host']:24s} {row['mechanism'] or '-'}")
    print(f"\n2) {jail.report_text()}")
    print("\n3) local model answer produced with the jail active")
    if reply is not None:
        first = (reply.text or "").splitlines()
        print(f"   model : {reply.model} via {reply.host}")
        print(f"   answer: {first[0][:160] if first else '(empty)'}")
    else:
        print(f"   model unavailable: {error}")
        print("   (start the local server, e.g. `ollama serve`, and re-run)")
    blocked_all = all(row["blocked"] for row in probes) if probes else False
    proved = blocked_all and reply is not None and jail.blocked_count >= len(probes)
    print(
        "\nRESULT: "
        + ("PROVED - external endpoints unreachable, local answer delivered."
           if proved else
           "NOT PROVED - see the lines above (a probe or the model call failed).")
    )
    if args.report:
        report_path = Path(args.report).expanduser()
        report_path.write_text(
            json.dumps({"jail": jail.report(), "probes": probes, "model": reply.model if reply else None,
                        "answer": reply.text if reply else None, "error": error}, indent=2),
            encoding="utf-8",
        )
        print(f"report written: {report_path}")
    return EXIT_OK if proved else 1


def cmd_scan(args) -> int:
    root = Path(args.directory).expanduser()
    if not root.exists():
        raise SystemExit(f"not found: {root}")
    names = _client_names(args.client_names)
    suffixes = {".txt", ".md", ".csv", ".json", ".log", ".eml", ".html", ".htm", ".yaml", ".yml"}
    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        verdict = gate_mod.classify(text, client_names=names)
        rows.append((verdict.level.value, verdict.score, str(path)))
    if not rows:
        print("no scannable text files found")
        return EXIT_OK
    worst = max({"LOW": 0, "MEDIUM": 1, "HIGH": 2}[r[0]] for r in rows)
    for level, score, path in sorted(rows, key=lambda r: -r[1]):
        print(f"{level:6s} {score:3d}  {path}")
    print(f"\n{len(rows)} file(s); highest level: {['LOW', 'MEDIUM', 'HIGH'][worst]}")
    return {0: EXIT_OK, 1: EXIT_LOCAL_ONLY, 2: EXIT_HIGH}[worst]


def cmd_vault(args) -> int:
    action = args.action
    if action == "clients":
        rows = vault_mod.clients(args.root)
        if not rows:
            print(f"no vaults under {Path(args.root).expanduser()}")
            return EXIT_OK
        for row in rows:
            print(f"{row['client']:28s} {row['archives']:4d} archive(s)  {row['bytes'] / 1024:.1f} KiB")
        return EXIT_OK
    if not args.client:
        raise SystemExit("--client is required")
    v = vault_mod.Vault(args.client, root=Path(args.root), keydir=Path(args.keydir))
    if action == "init":
        passphrase = v.init(force=args.force)
        print(f"vault ready : {v.dir}")
        print(f"key file    : {v.key_file} (mode 600, keep it in your password manager)")
        print(f"passphrase  : {passphrase}")
        print("\nHand this passphrase to the client for their own copy; store it yourself now.")
        return EXIT_OK
    if action == "add":
        if not args.files:
            raise SystemExit("pass at least one file to add")
        entry = v.add(args.files, label=args.label)
        print(f"added {len(entry['files'])} file(s) -> {entry['archive']}")
        print(f"sha256 {entry['sha256']}  size {entry['bytes']} bytes")
        return EXIT_OK
    if action == "list":
        entries = v.entries()
        if not entries:
            print(f"vault {v.slug} is empty")
            return EXIT_OK
        for entry in entries:
            print(f"{entry['ts']}  {entry['archive']}  {entry['bytes']:>9} B  {entry['label'] or '-'}")
        return EXIT_OK
    if action == "verify":
        results = v.verify(no_decrypt=args.no_decrypt)
        ok = sum(1 for r in results if r["ok"])
        for row in results:
            print(f"{'OK  ' if row['ok'] else 'FAIL'} {row['archive']:44s} {row['detail']}")
        print(f"\n{ok}/{len(results)} archive(s) verified")
        return EXIT_OK if ok == len(results) else 1
    if action == "extract":
        if not args.archive or not args.dest:
            raise SystemExit("extract needs --archive and --dest")
        names = v.extract(args.archive, args.dest)
        print(f"extracted {len(names)} member(s) to {Path(args.dest).expanduser()}")
        for name in names:
            print(f"  {name}")
        return EXIT_OK
    if action == "passphrase":
        print(v.passphrase())
        return EXIT_OK
    if action == "destroy":
        result = v.destroy(confirm=args.confirm or "", keep_key=args.keep_key)
        print(f"destroyed vault: {result['client']}")
        for name in result["archives"]:
            print(f"  removed {name}")
        print(f"  passphrase removed: {'yes' if result['key_removed'] else 'no (kept)'}")
        print("\nRemember: encrypted off-site backups keep their own retention window.")
        return EXIT_OK
    raise SystemExit(f"unknown vault action: {action}")


def cmd_trustpack(args) -> int:
    pack = trustpack.TrustPack(
        org=args.org,
        client=args.client_name,
        contact=args.contact,
        retention_days=args.retention_days,
        sub_processors=args.sub_processor or trustpack.TrustPack(org=args.org).sub_processors,
    )
    archives = 0
    if args.vault_client:
        try:
            archives = len(vault_mod.Vault(args.vault_client).entries())
        except Exception:  # noqa: BLE001
            archives = 0
    out = pack.render_pdf(args.out, vault_archives=archives)
    print(f"trust pack written: {out}")
    guide = Path(args.out).expanduser().with_name("CLIENT-VERIFICATION-STEPS.txt")
    guide.write_text(trustpack.audit_guide(args.org), encoding="utf-8")
    print(f"verification note : {guide}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
class _StrictParser(argparse.ArgumentParser):
    """Argument parser with no flag abbreviation.

    ``--conf`` must never be silently accepted as ``--confirm``: in a tool that
    deletes encrypted archives, ambiguous shorthand is a footgun.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    parser = _StrictParser(
        prog="zeroegress",
        description="Local-only AI for confidential work: egress jail, sensitivity gate, encrypted vaults, client trust pack.",
    )
    parser.add_argument("--version", action="version", version=f"zeroegress {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_StrictParser)

    p_status = sub.add_parser("status", help="environment and model-server report")
    p_status.set_defaults(func=cmd_status)

    p_gate = sub.add_parser("gate", help="decide whether content may leave the machine")
    p_gate.add_argument("source", help="file path or - for stdin")
    p_gate.add_argument("--json", action="store_true")
    p_gate.add_argument("--deep", action="store_true", help="ask the local model to confirm")
    p_gate.add_argument("--model", default=None)
    p_gate.add_argument("--client-names", default=None, help="file with one client name per line")
    p_gate.add_argument("--redacted-out", default=None, help="write a redacted copy when the verdict is not LOW")
    p_gate.set_defaults(func=cmd_gate)

    p_redact = sub.add_parser("redact", help="strip identifiers from a document")
    p_redact.add_argument("source")
    p_redact.add_argument("-o", "--out", default=None)
    p_redact.set_defaults(func=cmd_redact)

    p_ask = sub.add_parser("ask", help="ask the local model (egress jail enforced)")
    p_ask.add_argument("prompt", nargs="?", default="")
    p_ask.add_argument("--file", default=None, help="attach a document to the prompt")
    p_ask.add_argument("--system", default=None)
    p_ask.add_argument("--model", default=local_llm.DEFAULT_MODEL)
    p_ask.add_argument("--host", default=local_llm.DEFAULT_HOST)
    p_ask.add_argument("--temperature", type=float, default=0.2)
    p_ask.add_argument("--num-ctx", type=int, default=None)
    p_ask.add_argument("--report", action="store_true", help="print the jail report on stderr")
    p_ask.add_argument("--no-audit", action="store_true", help="do not write the egress audit log")
    p_ask.add_argument("--allow-blocked", action="store_true", help="suppress the blocked-attempt warning")
    p_ask.set_defaults(func=cmd_ask)

    p_prove = sub.add_parser("prove", help="show blocked egress + a local answer in one run")
    p_prove.add_argument("--prompt", default="In one sentence, what does confidentiality mean for a bid document?")
    p_prove.add_argument("--model", default=local_llm.DEFAULT_MODEL)
    p_prove.add_argument("--host", default=local_llm.DEFAULT_HOST)
    p_prove.add_argument("--num-ctx", type=int, default=None)
    p_prove.add_argument("--hosts", nargs="+", default=["api.openai.com", "api.deepseek.com", "1.1.1.1"])
    p_prove.add_argument("--timeout", type=float, default=3.0)
    p_prove.add_argument("--report", default=None, help="write a JSON evidence file")
    p_prove.add_argument("--no-audit", action="store_true")
    p_prove.set_defaults(func=cmd_prove)

    p_scan = sub.add_parser("scan", help="gate every text file under a directory")
    p_scan.add_argument("directory")
    p_scan.add_argument("--client-names", default=None)
    p_scan.set_defaults(func=cmd_scan)

    p_vault = sub.add_parser("vault", help="per-client encrypted document vaults")
    p_vault.add_argument(
        "action",
        choices=["init", "add", "list", "verify", "extract", "passphrase", "clients", "destroy"],
    )
    p_vault.add_argument("--client", default=None)
    p_vault.add_argument("files", nargs="*")
    p_vault.add_argument("--label", default="")
    p_vault.add_argument("--archive", default=None)
    p_vault.add_argument("--dest", default=None)
    p_vault.add_argument("--force", action="store_true")
    p_vault.add_argument("--confirm", default=None, help="destroy: repeat the client slug to confirm")
    p_vault.add_argument("--keep-key", action="store_true", help="destroy: keep the passphrase file")
    p_vault.add_argument("--no-decrypt", action="store_true", help="verify integrity without the passphrase")
    p_vault.add_argument("--root", default=str(vault_mod.DEFAULT_ROOT))
    p_vault.add_argument("--keydir", default=str(vault_mod.DEFAULT_KEYDIR))
    p_vault.set_defaults(func=cmd_vault)

    p_pack = sub.add_parser("trustpack", help="render a client-facing data-handling + NDA pack")
    p_pack.add_argument("--org", required=True)
    p_pack.add_argument("--client-name", default="the Client")
    p_pack.add_argument("--contact", default="")
    p_pack.add_argument("--retention-days", type=int, default=90)
    p_pack.add_argument("--sub-processor", action="append", default=None)
    p_pack.add_argument("--vault-client", default=None, help="include the archive count for this client")
    p_pack.add_argument("--out", required=True, help="output PDF path")
    p_pack.set_defaults(func=cmd_trustpack)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    # argparse cannot mix optionals with a trailing nargs="*" positional (bpo-15112),
    # so collect the leftovers and give them back to `vault add` as file arguments.
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        files = getattr(args, "files", None)
        looks_like_flag = [u for u in unknown if u.startswith("-")]
        if isinstance(files, list) and not looks_like_flag:
            args.files = list(files) + list(unknown)
        else:
            parser.error(f"unrecognized arguments: {' '.join(unknown)}")
    try:
        return args.func(args)
    except vault_mod.VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
