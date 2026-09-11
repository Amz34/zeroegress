"""zeroegress - local-only AI for confidential documents.

Four layers, all on one machine:

* :mod:`zeroegress.jail`      - socket-level egress enforcement (not a config flag)
* :mod:`zeroegress.gate`      - sensitivity classification before anything leaves
* :mod:`zeroegress.vault`     - per-client AES-256 encrypted archives + manifest
* :mod:`zeroegress.trustpack` - client-auditable data-handling + NDA document

The local model runtime (Ollama, llama.cpp, vLLM, LM Studio) is the only thing
:mod:`zeroegress.local_llm` will talk to, and it refuses non-loopback endpoints.
"""

from .gate import Finding, Level, Verdict, classify, redact
from .jail import EgressBlocked, EgressJail, block_probe, is_loopback_host
from .local_llm import NonLocalEndpoint, ask, available, chat, health
from .trustpack import TrustPack, audit_guide
from .vault import Vault, VaultError, clients

__all__ = [
    "EgressBlocked",
    "EgressJail",
    "Finding",
    "Level",
    "NonLocalEndpoint",
    "TrustPack",
    "Vault",
    "VaultError",
    "ask",
    "audit_guide",
    "available",
    "block_probe",
    "chat",
    "classify",
    "clients",
    "health",
    "is_loopback_host",
    "redact",
]

__version__ = "0.1.0"
