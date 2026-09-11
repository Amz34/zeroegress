"""CLI tests: the documented commands must actually work as written."""

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zeroegress.cli import main  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def run(*argv: str) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(argv))
    return code, buf.getvalue()


class CliContract(unittest.TestCase):
    def test_gate_exit_code_for_confidential_sample(self):
        code, out = run("gate", str(ROOT / "examples" / "sample-tender.txt"))
        self.assertEqual(code, 11, out)
        self.assertIn("HIGH", out)

    def test_scan_returns_verdicts(self):
        code, out = run("scan", str(ROOT / "examples"))
        self.assertEqual(code, 11)
        self.assertIn("sample-tender.txt", out)

    def test_vault_add_accepts_trailing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = str(Path(tmp) / "vaults")
            keys = str(Path(tmp) / "keys")
            self.assertEqual(run("vault", "init", "--client", "Cli Co", "--root", root, "--keydir", keys)[0], 0)
            code, out = run(
                "vault", "add", "--client", "Cli Co", "--root", root, "--keydir", keys,
                str(ROOT / "examples" / "sample-tender.txt"),
            )
            self.assertEqual(code, 0, out)
            self.assertEqual(run("vault", "verify", "--client", "Cli Co", "--root", root, "--keydir", keys)[0], 0)
            self.assertTrue(list((Path(root) / "cli-co" / "vault").glob("*.gpg")))

    def test_unknown_flag_is_still_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                main([
                    "vault", "init", "--clien", "Cli Co",
                    "--root", str(Path(tmp) / "vaults"), "--keydir", str(Path(tmp) / "keys"),
                ])

    def test_destroy_wrong_confirmation_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = str(Path(tmp) / "vaults")
            keys = str(Path(tmp) / "keys")
            self.assertEqual(run("vault", "init", "--client", "Cli Co", "--root", root, "--keydir", keys)[0], 0)
            code, _ = run(
                "vault", "destroy", "--client", "Cli Co", "--confirm", "not-the-slug",
                "--root", root, "--keydir", keys,
            )
            self.assertEqual(code, 1)
            self.assertTrue((Path(root) / "cli-co").exists(), "vault must survive a wrong confirmation")

    def test_trustpack_writes_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_pdf = str(Path(tmp) / "pack.pdf")
            code, out = run(
                "trustpack", "--org", "Test Org", "--client-name", "Acme", "--out", out_pdf,
            )
            self.assertEqual(code, 0, out)
            produced = list(Path(tmp).glob("pack.*"))
            self.assertTrue(produced, "no trust pack artefact produced")
            self.assertGreater(produced[0].stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
