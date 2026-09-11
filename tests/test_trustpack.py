"""Trust pack rendering tests."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zeroegress.trustpack import TrustPack, audit_guide, find_chrome  # noqa: E402


class Rendering(unittest.TestCase):
    def setUp(self):
        self.pack = TrustPack(org="Northline Advisory", client="Gamma Facilities Co.", contact="security@example.com")

    def test_html_substitutes_placeholders(self):
        html = self.pack.render_html(vault_archives=4)
        self.assertNotIn("{{ORG}}", html)
        self.assertNotIn("{{CLIENT}}", html)
        self.assertIn("Northline Advisory", html)
        self.assertIn("Gamma Facilities Co.", html)
        self.assertIn("4 archive(s)", html)

    def test_html_has_the_honest_sections(self):
        html = self.pack.render_html()
        for needle in (
            "Boundaries we do not hide",
            "What this statement does not claim",
            "No third-party AI processing",
            "Verification",
        ):
            self.assertIn(needle, html)

    def test_subprocessors_are_listed(self):
        html = self.pack.render_html()
        self.assertIn("<li>", html)
        self.assertIn("Cloud hosting provider", html)

    def test_render_pdf_writes_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pack.pdf"
            produced = self.pack.render_pdf(str(out))
            self.assertTrue(produced.exists())
            self.assertGreater(produced.stat().st_size, 2000)
            if find_chrome():
                self.assertEqual(produced.suffix, ".pdf")
                self.assertEqual(produced.read_bytes()[:4], b"%PDF")

    def test_audit_guide_lists_runnable_checks(self):
        guide = audit_guide("Northline Advisory")
        self.assertIn("zeroegress vault verify", guide)
        self.assertIn("zeroegress prove", guide)


if __name__ == "__main__":
    unittest.main()
