"""Gate tests: verdicts must be explainable and conservative."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zeroegress.gate import Level, classify, redact  # noqa: E402

PUBLIC_TEXT = """How to prepare a competitive technical proposal.
Start with an executive summary, then scope, methodology and a delivery timeline.
Public procurement usually requires the same structure in every market."""

TENDER_TEXT = """TENDER 4412/2026 - MEP maintenance for three hospitals.
Scope of work: chillers, medical gas, elevators and generators.
Bid bond 2 percent, performance bond 10 percent, liquidated damages per day apply.
Submit the prequalification pack before 12 October. Bidder must hold CR 1010xxxxxx.
"""

IDENTIFIER_TEXT = """Contact: facilities.director@example-hospital.sa, mobile 0551234567.
VAT 300123456700003 and our bank details SA0380000000608010167519.
"""


class GateLevels(unittest.TestCase):
    def test_public_text_is_low(self):
        verdict = classify(PUBLIC_TEXT)
        self.assertIs(verdict.level, Level.LOW)
        self.assertEqual(verdict.exit_code, 0)

    def test_tender_text_is_not_safe_for_cloud(self):
        verdict = classify(TENDER_TEXT)
        self.assertIn(verdict.level, (Level.MEDIUM, Level.HIGH))
        self.assertIn(verdict.exit_code, (10, 11))
        kinds = {f.kind for f in verdict.findings}
        self.assertIn("tender_marker", kinds)

    def test_identifiers_and_vat_are_high(self):
        verdict = classify(IDENTIFIER_TEXT)
        self.assertIs(verdict.level, Level.HIGH)
        self.assertEqual(verdict.exit_code, 11)
        kinds = {f.kind for f in verdict.findings}
        self.assertTrue({"email", "phone_sa", "sa_vat"} <= kinds, kinds)

    def test_client_name_promotes_score(self):
        plain = classify("Rates for quarterly maintenance visits, per site.")
        named = classify(
            "Rates for quarterly maintenance visits for Gamma Facilities Co.",
            client_names=["Gamma Facilities Co."],
        )
        self.assertGreater(named.score, plain.score)
        self.assertIn("Gamma Facilities Co.", named.client_terms)

    def test_secret_in_text_is_high(self):
        verdict = classify("Server note: api_key = abcdef1234567890 do not share")
        self.assertIs(verdict.level, Level.HIGH)

    def test_summary_is_human_readable(self):
        text = classify(TENDER_TEXT).summary()
        self.assertIn("verdict", text)
        self.assertIn("route", text)


class Redaction(unittest.TestCase):
    def test_identifiers_are_replaced(self):
        out, count = redact(IDENTIFIER_TEXT)
        self.assertGreaterEqual(count, 3)
        for token in ("[EMAIL]", "[PHONE]", "[IBAN]"):
            self.assertIn(token, out)
        self.assertNotIn("facilities.director@example-hospital.sa", out)

    def test_redaction_keeps_business_meaning(self):
        out, _ = redact("Total amount SAR 1,250,000 payable on completion.")
        self.assertIn("1,250,000", out)


if __name__ == "__main__":
    unittest.main()
