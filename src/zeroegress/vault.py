"""Per-client encrypted vaults.

One passphrase per client, AES-256 symmetric encryption via GnuPG, plus a
manifest that records the SHA-256 of every archive. The point is the separation:
client A cannot be decrypted with client B's key, a stolen laptop yields
ciphertext, and an auditor can verify integrity without being given the
passphrase (``verify --no-decrypt``).

Passphrases live in a key file with mode 0600 -- back it up to your password
manager, because there is no recovery path by design.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ROOT = Path(os.environ.get("ZEROEGRESS_VAULT_ROOT", "~/vaults")).expanduser()
DEFAULT_KEYDIR = Path(os.environ.get("ZEROEGRESS_KEY_DIR", "~/.config/zeroegress/keys")).expanduser()


class VaultError(RuntimeError):
    pass


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    if not slug:
        raise VaultError(f"invalid client name: {name!r}")
    return slug


def new_passphrase(words: int = 7) -> str:
    """Readable passphrase: memorable for a human, ~77 bits for an attacker."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(words))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=False, **kwargs)
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "replace").strip()
        raise VaultError(f"{cmd[0]} failed ({proc.returncode}): {err}")
    return proc


@dataclass
class Vault:
    client: str
    root: Path = DEFAULT_ROOT
    keydir: Path = DEFAULT_KEYDIR

    def __post_init__(self) -> None:
        self.slug = slugify(self.client)
        self.dir = Path(self.root).expanduser() / self.slug
        self.vault_dir = self.dir / "vault"
        self.work_dir = self.dir / "work"
        self.key_file = Path(self.keydir).expanduser() / f"{self.slug}.key"
        self.manifest = self.dir / "manifest.jsonl"

    # ------------------------------------------------------------------ setup
    @property
    def initialised(self) -> bool:
        return self.key_file.exists()

    def init(self, force: bool = False) -> str:
        if self.initialised and not force:
            raise VaultError(f"vault for {self.slug!r} already exists (use force to rotate)")
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        passphrase = new_passphrase()
        fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(passphrase + "\n")
        self.manifest.touch(mode=0o600, exist_ok=True)
        return passphrase

    def passphrase(self) -> str:
        if not self.initialised:
            raise VaultError(f"no key for {self.slug!r}: run `zeroegress vault init`")
        return self.key_file.read_text(encoding="utf-8").strip()

    # ------------------------------------------------------------------- data
    def add(self, paths: list[str], label: str = "") -> dict:
        if not self.initialised:
            raise VaultError(f"no key for {self.slug!r}: run `zeroegress vault init`")
        files: list[Path] = []
        for raw in paths:
            p = Path(raw).expanduser()
            if not p.exists():
                raise VaultError(f"not found: {p}")
            files.append(p)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        archive = self.vault_dir / f"{self.slug}_{stamp}.tar.gz.gpg"
        members = [str(p) for p in files]
        tmp_dir = Path(tempfile.mkdtemp(prefix="zeroegress-"))
        staging = tmp_dir / f"{self.slug}_{stamp}.tar.gz"
        try:
            used: set[str] = set()
            with tarfile.open(staging, "w:gz") as tar:
                for p in files:
                    name = p.name
                    if name in used:  # avoid silent collisions in the archive
                        name = f"{len(used)}-{name}"
                    used.add(name)
                    tar.add(p, arcname=name)
            _run(
                [
                    "gpg", "--batch", "--yes", "--quiet", "--pinentry-mode", "loopback",
                    "--passphrase-file", str(self.key_file),
                    "--symmetric", "--cipher-algo", "AES256", "--s2k-mode", "3",
                    "--s2k-digest-algo", "SHA512",
                    "--output", str(archive), str(staging),
                ]
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client": self.slug,
            "archive": archive.name,
            "label": label,
            "files": members,
            "bytes": archive.stat().st_size,
            "sha256": _sha256(archive),
            "cipher": "AES-256 (OpenPGP symmetric, S2K SHA-512)",
        }
        with self.manifest.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    def entries(self) -> list[dict]:
        if not self.manifest.exists():
            return []
        out = []
        for line in self.manifest.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def _decrypt(self, archive: Path) -> bytes:
        proc = _run(
            [
                "gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
                "--passphrase-file", str(self.key_file), "--decrypt", str(archive),
            ]
        )
        return proc.stdout

    def verify(self, no_decrypt: bool = False) -> list[dict]:
        """Verify every archive. ``no_decrypt=True`` checks integrity only."""
        results = []
        for entry in self.entries():
            archive = self.vault_dir / entry["archive"]
            row = {"archive": entry["archive"], "ok": False, "detail": ""}
            if not archive.exists():
                row["detail"] = "missing"
                results.append(row)
                continue
            if _sha256(archive) != entry.get("sha256"):
                row["detail"] = "sha256 mismatch (archive modified)"
                results.append(row)
                continue
            if no_decrypt:
                row["ok"] = True
                row["detail"] = "sha256 ok (not decrypted)"
                results.append(row)
                continue
            try:
                raw = self._decrypt(archive)
                with tarfile.open(fileobj=_BytesReader(raw)) as tar:
                    names = tar.getnames()
                row["ok"] = True
                row["detail"] = f"decrypt ok, {len(names)} member(s)"
                row["members"] = names
            except Exception as exc:  # noqa: BLE001 - report, never crash the audit
                row["detail"] = f"decrypt/extract failed: {exc}"
            results.append(row)
        return results

    def extract(self, archive_name: str, dest: str) -> list[str]:
        archive = self.vault_dir / archive_name
        if not archive.exists():
            raise VaultError(f"no such archive: {archive_name}")
        dest_path = Path(dest).expanduser()
        dest_path.mkdir(parents=True, exist_ok=True)
        raw = self._decrypt(archive)
        with tarfile.open(fileobj=_BytesReader(raw)) as tar:
            tar.extractall(dest_path)  # noqa: S202 - archives are produced locally
            return tar.getnames()

    def destroy(self, confirm: str, keep_key: bool = False) -> dict:
        """Delete the archives (and, by default, the passphrase) for this client.

        Requires the client slug as an explicit confirmation string: a deletion
        that can be triggered by a typo is a deletion that will happen by accident.
        Returns a summary of what was removed.
        """
        if confirm != self.slug:
            raise VaultError(
                f"refusing to destroy: confirmation must be the client slug '{self.slug}'"
            )
        removed_files = []
        if self.vault_dir.exists():
            for archive in sorted(self.vault_dir.glob("*")):
                if archive.is_file():
                    removed_files.append(archive.name)
                    archive.unlink()
            self.vault_dir.rmdir()
        for staging in (self.work_dir, self.vault_dir):
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
        if self.manifest.exists():
            self.manifest.unlink()
        key_removed = False
        if not keep_key and self.key_file.exists():
            self.key_file.unlink()
            key_removed = True
        try:
            self.dir.rmdir()
        except OSError:
            pass
        return {"client": self.slug, "archives": removed_files, "key_removed": key_removed}

    def size(self) -> int:
        if not self.vault_dir.exists():
            return 0
        return sum(f.stat().st_size for f in self.vault_dir.glob("*") if f.is_file())


class _BytesReader:
    """Minimal file-like wrapper so tarfile can read decrypted bytes."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunk = self._data[self._pos:]
            self._pos = len(self._data)
            return chunk
        chunk = self._data[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        else:
            self._pos = len(self._data) + offset
        return self._pos

    def tell(self) -> int:
        return self._pos


def clients(root: Path = DEFAULT_ROOT) -> list[dict]:
    """List every vault with archive count and size."""
    root = Path(root).expanduser()
    if not root.exists():
        return []
    out = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        manifest = child / "manifest.jsonl"
        count = 0
        if manifest.exists():
            count = sum(1 for line in manifest.read_text(encoding="utf-8").splitlines() if line.strip())
        vault_dir = child / "vault"
        size = (
            sum(f.stat().st_size for f in vault_dir.glob("*.gpg"))
            if vault_dir.exists()
            else 0
        )
        out.append({"client": child.name, "archives": count, "bytes": size})
    return out


def gpg_available() -> bool:
    return shutil.which("gpg") is not None
