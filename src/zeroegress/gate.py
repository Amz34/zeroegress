"""Sensitivity gate: decide whether a document may leave this machine.

The gate is the cheapest possible control and the one people skip. It runs before
anything is pasted into a chat box, uploaded to a web tool, or handed to a cloud
API, and it answers one question:

    LOW     -> safe to use with cloud tooling (public / generic content)
    MEDIUM  -> keep on the local model only (business-sensitive)
    HIGH    -> local model only AND vault it; never paste anywhere (identifiers,
               prices, client names, anything with regulatory exposure)

Detection is deterministic first (regex, weight-scored) so the verdict is
explainable and reproducible; a local model can be asked to confirm in ``--deep``
mode, but the model never changes a LOW verdict into something unsafe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

HIGH_WEIGHT = 3
MEDIUM_WEIGHT = 2
LOW_WEIGHT = 1
MEDIUM_THRESHOLD = 4

# --------------------------------------------------------------------------- #
# Deterministic detectors. Each entry: (kind, weight, compiled pattern, note)
# Patterns are intentionally conservative: a false "local-only" verdict costs a
# little convenience, a false "safe" verdict can cost a contract.
# --------------------------------------------------------------------------- #
_DETECTORS: list[tuple[str, int, re.Pattern, str]] = [
    ("email", HIGH_WEIGHT + 1, re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"), "personal or corporate email address"),
    ("phone_sa", HIGH_WEIGHT + 1, re.compile(r"(?:\+966|00966|0)5\d{8}\b"), "Saudi mobile number"),
    ("phone_intl", HIGH_WEIGHT + 1, re.compile(r"\+(?!966)\d[\d\s().-]{7,}\d"), "international phone number"),
    ("iban", HIGH_WEIGHT + 2, re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"), "IBAN / bank account string"),
    ("sa_vat", HIGH_WEIGHT + 2, re.compile(r"\b3\d{13}3\b"), "Saudi VAT registration number"),
    ("sa_cr", HIGH_WEIGHT + 1, re.compile(r"\b(?:CR|C\.R\.|Commercial Registration)\D{0,4}\d{7,10}\b", re.I), "commercial registration number"),
    ("api_key", HIGH_WEIGHT + 2, re.compile(r"\b(?:sk|gho|ghp|xox[bap])[-_A-Za-z0-9]{16,}\b"), "API key / token"),
    ("secret_kv", HIGH_WEIGHT + 2, re.compile(r"(?i)\b(?:password|passphrase|secret|api[_ -]?key)\s*[:=]\s*\S{6,}"), "credential in plain text"),
    ("confidential_marker", MEDIUM_WEIGHT + 1, re.compile(r"(?i)\b(?:confidential|proprietary|restricted|internal use only|do not distribute|non[- ]disclosure)\b"), "confidentiality marking"),
    ("tender_marker", MEDIUM_WEIGHT + 1, re.compile(r"(?i)\b(?:tender|rfp|rfq|itt|eoi|bid|bidder|boq|bill of quantities|scope of work|bid bond|performance bond|award|prequalification)\b"), "tender / bid language"),
    ("pricing", MEDIUM_WEIGHT, re.compile(r"(?i)(?:[A-Z]{3}|\$|€|£|﷼|SAR|USD|EUR)\s?\d[\d,.\s]{2,}|(?:\brate|price|quotation|discount|margin)\b\D{0,12}\d"), "commercial terms or rates"),
    ("contract_terms", MEDIUM_WEIGHT, re.compile(r"(?i)\b(?:liquidated damages|retention|warranty|indemnif|liquidated|termination for cause|governing law|arbitration|penalty clause)\b"), "contract and liability terms"),
    ("person_name_hint", LOW_WEIGHT, re.compile(r"(?i)\b(?:mr|mrs|ms|eng|dr|sheikh)\b\.?\s+[A-Z][a-z]+"), "personal name form"),
    ("identity_doc", HIGH_WEIGHT + 2, re.compile(r"(?i)\b(?:iqama|passport|national id|visa)\D{0,6}\d{6,}\b"), "identity document reference"),
    ("address", LOW_WEIGHT, re.compile(r"(?i)\b(?:p\.?o\.?\s?box|street|st\.|district|plot no|building no|zip|postal code)\b"), "address detail"),
    ("internal_host", MEDIUM_WEIGHT + 1, re.compile(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?:\.\d{1,3})?\b"), "internal network address"),
]


class Level(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def exit_code(self) -> int:
        return {Level.LOW: 0, Level.MEDIUM: 10, Level.HIGH: 11}[self]

    @property
    def route(self) -> str:
        return {
            Level.LOW: "cloud tools allowed",
            Level.MEDIUM: "local model only",
            Level.HIGH: "local model only + encrypted vault (never paste)",
        }[self]


@dataclass
class Finding:
    kind: str
    weight: int
    note: str
    samples: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"kind": self.kind, "weight": self.weight, "note": self.note, "samples": self.samples}


@dataclass
class Verdict:
    level: Level
    score: int
    findings: list[Finding]
    chars: int
    client_terms: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return self.level.exit_code

    @property
    def route(self) -> str:
        return self.level.route

    def as_dict(self) -> dict:
        return {
            "level": self.level.value,
            "score": self.score,
            "route": self.route,
            "chars": self.chars,
            "findings": [f.as_dict() for f in self.findings],
            "client_terms": self.client_terms,
        }

    def summary(self) -> str:
        lines = [
            f"verdict : {self.level.value}  (score {self.score})",
            f"route   : {self.route}",
            f"size    : {self.chars} characters",
        ]
        if self.findings:
            lines.append("signals :")
            for f in sorted(self.findings, key=lambda x: -x.weight):
                sample = f"  e.g. {f.samples[0][:60]}" if f.samples else ""
                lines.append(f"  - [{f.weight}] {f.kind}: {f.note}{sample}")
        else:
            lines.append("signals : none")
        if self.client_terms:
            lines.append("client names seen: " + ", ".join(self.client_terms))
        return "\n".join(lines)


def classify(text: str, client_names: list[str] | None = None) -> Verdict:
    """Score *text* and return a :class:`Verdict` (deterministic, no network)."""
    findings: list[Finding] = []
    score = 0
    for kind, weight, pattern, note in _DETECTORS:
        hits = pattern.findall(text)
        if not hits:
            continue
        samples = [h if isinstance(h, str) else " ".join(h) for h in hits[:3]]
        findings.append(Finding(kind=kind, weight=weight, note=note, samples=samples))
        score += weight
    seen_clients: list[str] = []
    for name in client_names or []:
        if name and name.lower() in text.lower():
            seen_clients.append(name)
            findings.append(Finding(kind="client_name", weight=MEDIUM_WEIGHT + 1, note="named client reference", samples=[name]))
            score += MEDIUM_WEIGHT + 1
    if seen_clients and score < MEDIUM_THRESHOLD:
        score = MEDIUM_THRESHOLD
    level = Level.LOW
    if score >= MEDIUM_THRESHOLD + 2:
        level = Level.HIGH
    elif score >= MEDIUM_THRESHOLD:
        level = Level.MEDIUM
    return Verdict(level=level, score=score, findings=findings, chars=len(text), client_terms=seen_clients)


#: Placeholders used by :func:`redact`, keyed by detector kind.
REDACT_TOKENS = {
    "email": "[EMAIL]",
    "phone_sa": "[PHONE]",
    "phone_intl": "[PHONE]",
    "iban": "[IBAN]",
    "sa_cr": "[CR]",
    "sa_vat": "[VAT]",
    "api_key": "[APIKEY]",
    "secret_kv": "[SECRET]",
    "identity_doc": "[ID]",
    "internal_host": "[IP]",
}


def redact(text: str) -> tuple[str, int]:
    """Return (redacted_text, count) with identifiers replaced by placeholders.

    The redacted text still keeps business meaning (amounts, clauses) so a
    non-sensitive draft can be prepared for cloud tooling if the verdict is
    borderline -- but identifiers are gone.
    """
    out = text
    count = 0
    for kind, _weight, pattern, _note in _DETECTORS:
        token = REDACT_TOKENS.get(kind)
        if not token:
            continue
        out, n = pattern.subn(token, out)
        count += n
    return out, count
