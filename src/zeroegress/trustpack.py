"""Client-auditable trust pack.

Every confidentiality claim in a sales call should be a document the client can
read, sign, and check. This module renders that document -- data-handling
statement, sub-processor list, NDA-ready clauses, verification steps -- from
Markdown templates, using the same renderer you already have on the machine
(Chrome/Chromium headless). No cloud service is involved in producing it.
"""

from __future__ import annotations

import html
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
CHROME_CANDIDATES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
)


def find_chrome() -> str | None:
    for name in CHROME_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


@dataclass
class TrustPack:
    org: str
    client: str = "the Client"
    contact: str = ""
    retention_days: int = 90
    sub_processors: list[str] = field(
        default_factory=lambda: [
            "Cloud hosting provider of our own account (dedicated instance)",
            "Object storage provider used for encrypted backups (client-side encrypted)",
        ]
    )
    extra_notes: str = ""

    def context(self, vault_archives: int = 0) -> dict[str, str]:
        return {
            "ORG": html.escape(self.org),
            "CLIENT": html.escape(self.client),
            "CONTACT": html.escape(self.contact or "the address on file"),
            "DATE": time.strftime("%d %B %Y", time.gmtime()),
            "RETENTION_DAYS": str(self.retention_days),
            "SUBPROCESSORS": "\n".join(f"<li>{html.escape(s)}</li>" for s in self.sub_processors),
            "VAULT_ARCHIVES": str(vault_archives),
            "EXTRA_NOTES": self.extra_notes,
        }

    def render_html(self, vault_archives: int = 0) -> str:
        template = (TEMPLATE_DIR / "trust_pack.html").read_text(encoding="utf-8")
        ctx = self.context(vault_archives)
        for key, value in ctx.items():
            template = template.replace("{{" + key + "}}", value)
        return template

    def render_pdf(self, out_path: str, vault_archives: int = 0) -> Path:
        """Render the pack to PDF. Falls back to HTML when Chrome is absent."""
        out = Path(out_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        chrome = find_chrome()
        html_path = out.with_suffix(".html")
        html_path.write_text(self.render_html(vault_archives), encoding="utf-8")
        if not chrome:
            return html_path
        cmd = [
            chrome,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--no-pdf-header-footer",
            f"--print-to-pdf={out}",
            f"file://{html_path}",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0 or not out.exists():
            return html_path
        return out


def audit_guide(org: str = "the provider") -> str:
    """A short, copy-pasteable 'how to verify these claims' note for clients."""
    return f"""Verification steps any client can run (no cooperation from us required):

1. Encrypted vaults - ask {org} to run `zeroegress vault verify --client <your-name>`
   in front of you. It decrypts each archive, checks SHA-256 against the manifest
   and prints the member list. Nothing readable is produced unless the passphrase
   is supplied.
2. Local-only processing - ask for `zeroegress prove`. It starts a socket jail,
   tries to reach three external endpoints, and prints the blocked attempts
   together with a local model answer produced while the block was active.
3. No third-party AI - the processing host holds no API keys for external model
   providers; the model server is bound to 127.0.0.1 only.
4. Backups - the off-site copy is produced after client-side encryption
   (AES-256); the storage provider holds ciphertext only.
5. Deletion - written request triggers deletion and a deletion confirmation
   naming the archives removed, within {5} business days.
"""
