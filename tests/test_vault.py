"""Vault tests: encryption, integrity, isolation, round trip."""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zeroegress.vault import Vault, VaultError, clients, new_passphrase, slugify  # noqa: E402

GPG = shutil.which("gpg") is not None


@unittest.skipUnless(GPG, "gpg not installed")
class VaultRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name) / "vaults"
        keys = Path(self.tmp.name) / "keys"
        self.src = Path(self.tmp.name) / "docs"
        self.src.mkdir(parents=True)
        (self.src / "tender.txt").write_text("TENDER 4412/2026 - client confidential pricing SAR 1,250,000\n")
        (self.src / "boq.csv").write_text("item,qty\nchiller,3\n")
        self.vault = Vault("Gamma Facilities Co", root=root, keydir=keys)

    def tearDown(self):
        self.tmp.cleanup()

    def test_init_creates_protected_key(self):
        passphrase = self.vault.init()
        self.assertGreaterEqual(len(passphrase), 20)
        self.assertTrue(self.vault.key_file.exists())
        mode = oct(self.vault.key_file.stat().st_mode & 0o777)
        self.assertEqual(mode, "0o600", mode)
        with self.assertRaises(VaultError):
            self.vault.init()  # no silent re-init

    def test_add_encrypts_and_manifests(self):
        self.vault.init()
        entry = self.vault.add([str(self.src / "tender.txt"), str(self.src / "boq.csv")], label="initial pack")
        archive = self.vault.vault_dir / entry["archive"]
        self.assertTrue(archive.exists())
        self.assertEqual(len(entry["files"]), 2)
        # the ciphertext must not contain the plaintext
        blob = archive.read_bytes()
        self.assertNotIn(b"TENDER 4412/2026", blob)
        self.assertNotIn(b"1,250,000", blob)
        manifest_lines = self.vault.manifest.read_text().strip().splitlines()
        self.assertEqual(len(manifest_lines), 1)

    def test_verify_and_extract_round_trip(self):
        self.vault.init()
        self.vault.add([str(self.src / "tender.txt")])
        results = self.vault.verify()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["ok"], results[0])
        out = Path(self.tmp.name) / "restored"
        names = self.vault.extract(results[0]["archive"], str(out))
        self.assertEqual(names, ["tender.txt"])
        self.assertIn("TENDER 4412/2026", (out / "tender.txt").read_text())

    def test_tampering_is_detected(self):
        self.vault.init()
        self.vault.add([str(self.src / "boq.csv")])
        archive = next(self.vault.vault_dir.glob("*.gpg"))
        data = bytearray(archive.read_bytes())
        data[-40] ^= 0xFF  # flip bits near the end of the ciphertext
        archive.write_bytes(bytes(data))
        results = self.vault.verify(no_decrypt=True)
        self.assertFalse(results[0]["ok"])
        self.assertIn("sha256 mismatch", results[0]["detail"])

    def test_client_keys_are_isolated(self):
        other = Vault("Delta Contracting", root=self.vault.root, keydir=self.vault.keydir)
        self.vault.init()
        other.init()
        self.vault.add([str(self.src / "tender.txt")])
        archive = next(self.vault.vault_dir.glob("*.gpg"))
        other.vault_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(archive, other.vault_dir / archive.name)
        # decrypting client A's archive with client B's key must fail
        with self.assertRaises(Exception):
            other._decrypt(other.vault_dir / archive.name)

    def test_destroy_needs_explicit_confirmation(self):
        self.vault.init()
        self.vault.add([str(self.src / "tender.txt")])
        with self.assertRaises(VaultError):
            self.vault.destroy(confirm="gamma")  # wrong confirmation string
        self.assertTrue(next(self.vault.vault_dir.glob("*.gpg")).exists())
        result = self.vault.destroy(confirm=self.vault.slug)
        self.assertEqual(len(result["archives"]), 1)
        self.assertTrue(result["archives"][0].endswith(".gpg"))
        self.assertTrue(result["key_removed"])
        self.assertFalse(self.vault.key_file.exists())
        self.assertFalse(self.vault.dir.exists())

    def test_clients_listing(self):
        self.vault.init()
        self.vault.add([str(self.src / "boq.csv")])
        rows = clients(self.vault.root)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["client"], "gamma-facilities-co")
        self.assertEqual(rows[0]["archives"], 1)


class Helpers(unittest.TestCase):
    def test_slugify(self):
        self.assertEqual(slugify("Gamma Facilities Co."), "gamma-facilities-co")
        with self.assertRaises(VaultError):
            slugify("!!!")

    def test_passphrase_shape(self):
        phrase = new_passphrase(words=5)
        self.assertEqual(len(phrase.split("-")), 5)
        self.assertNotIn("l", phrase)
        self.assertNotIn("1", phrase)


if __name__ == "__main__":
    unittest.main()
