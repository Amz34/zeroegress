<div align="center">

# ZeroEgress

**Bid documents in. Nothing out.**

A four-layer, single-machine setup that lets you run AI over confidential documents
(bids, tenders, contracts, client files) while being able to *prove* that nothing
leaves the machine. Not a policy. Not a promise. Enforcement at the socket layer.

[![ci](https://github.com/Amz34/zeroegress/actions/workflows/ci.yml/badge.svg)](https://github.com/Amz34/zeroegress/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![dependencies](https://img.shields.io/badge/runtime%20deps-none-brightgreen)
![cloud calls](https://img.shields.io/badge/cloud%20API%20calls-zero-critical)

</div>

---

## The problem nobody puts in writing

You paste a tender into an AI chat box to summarise it. Now that tender — prices,
client names, CR numbers, the authority's confidential terms — sits in someone
else's infrastructure, under someone else's retention policy, possibly in someone
else's training set.

Vendors have made this easy on purpose: the free tiers of many AI services reserve
the right to use your inputs to improve their products, and "enterprise-grade"
does not always mean "no retention". **Check your own tier's terms — that is the
whole point.** If your business is built on other people's confidential documents,
"we use a very trustworthy AI provider" is not an answer you can put in a
capability statement.

## The four layers

| # | Layer | What it does | Command |
|---|-------|--------------|---------|
| 1 | **Gate** | Classifies a document before it goes anywhere. Hard identifiers, client names, commercial terms → verdict + exit code. | `zeroegress gate file.pdf` |
| 2 | **Jail** | Patches the socket layer so any connection to a non-loopback address *fails*, and records the attempt. | built into `ask` / `prove` |
| 3 | **Vault** | Per-client AES-256 encrypted storage with a SHA-256 manifest, so client A can never read client B. | `zeroegress vault add --client acme bid.pdf` |
| 4 | **Trust pack** | Generates the client-facing data-handling statement + NDA clauses + audit guide as a PDF you can hand over and sign. | `zeroegress trustpack --org "You" --client-name "Acme" --out ./pack.pdf` |

## The proof (this is the whole point)

```console
$ zeroegress prove

1) egress attempts made while the jail was active
   BLOCKED  api.openai.com           socket.getaddrinfo() socket.connect()
   BLOCKED  api.deepseek.com         socket.getaddrinfo() socket.connect()
   BLOCKED  1.1.1.1                  socket.getaddrinfo() socket.connect()

2) egress policy      : zeroegress (loopback only)
loopback sockets   : 2
blocked attempts   : 6
audit log          : ~/.config/zeroegress/egress-attempts.jsonl

3) local model answer produced with the jail active
   model : llama3.2:3b via http://127.0.0.1:11434
   answer: For a bid document, confidentiality refers to the requirement that ...

RESULT: PROVED - external endpoints unreachable, local answer delivered.
```

Two things happened there. The tool tried to reach three well-known AI endpoints
**and could not** — the attempts are blocked and logged. Then a local model answered
the question anyway. Run it on your own machine, in front of your client, with the
Wi-Fi off. That is a different category of claim from a privacy policy.

## Install

```bash
git clone https://github.com/Amz34/zeroegress.git
cd zeroegress
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/zeroegress status          # checks gpg, chrome, local model server
```

You need:

* Python 3.10+ (no runtime dependencies — standard library only)
* a local model server — [Ollama](https://ollama.com) is what the default client
  targets: `ollama pull llama3.2:3b`
* `gpg` for the vault, `google-chrome`/`chromium` for PDF rendering (both optional)

## Use

```bash
# 1. classify before it leaves the machine (exit 0 safe / 10 local-only / 11 high)
zeroegress gate examples/sample-tender.txt

# 1b. optional: ask the local model to confirm, then get a redacted copy
zeroegress gate confidential.docx --deep
zeroegress gate confidential.docx --redacted-out /tmp/redacted.txt

# 2. ask questions with egress hard-blocked
zeroegress ask "What are the payment terms and the liquidated damages cap?" \
  --file examples/sample-tender.txt

# 3. per-client encrypted vault
zeroegress vault init --client "Acme Facilities"
zeroegress vault passphrase --client "Acme Facilities"   # store it in your password manager
zeroegress vault add --client "Acme Facilities" tender.pdf boq.xlsx
zeroegress vault verify --client "Acme Facilities"          # decrypt + tar + sha256 check
zeroegress vault extract --client "Acme Facilities" --archive acme-facilities_20260911_101500.tar.gz.gpg --dest ./restored

# 4. the document your client signs
zeroegress trustpack --org "Your Firm" --client "Acme Facilities" --out ./trust-pack
```

`zeroegress scan ./incoming` walks a directory and prints one verdict per file, so a
whole tender inbox can be triaged in one pass.

## What this does NOT do

Being precise here is what makes the rest believable:

* **It does not encrypt your disk.** If the machine is stolen, an unencrypted
  filesystem is readable. Fix that at the OS level (LUKS/FileVault/BitLocker).
* **It does not stop you from pasting into a browser.** The jail guards code paths
  that go through this tool; a human with a chat window is still the largest risk.
  That is what layer 1 is for.
* **It does not make a local model smart.** A 3B model on a small VM is weaker than a
  frontier API. The trade-off is deliberate: quality for confidentiality, per document.
* **It does not certify you.** No ISO 27001, no SOC 2. It produces evidence of the
  specific controls it implements — nothing more.

## Who verifies it

The client, not you. `zeroegress trustpack` emits an audit guide they can run
themselves: inspect the vault's header, re-run `verify` against the manifest,
run `prove` and watch the blocked attempts, and take away the passphrase to their
own copy. See [docs/AUDIT-GUIDE.md](docs/AUDIT-GUIDE.md) and
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), and the NDA-ready clauses in
[docs/NDA-CLAUSES.md](docs/NDA-CLAUSES.md).

## Free, and how it pays for itself

MIT licensed, no paid tier, no telemetry, no account. Both sides win when the
controls are standard:

* **If you handle confidential documents for clients** → use it, ship the trust
  pack, and cite it in your proposals. Referencing an auditable tool beats
  asserting good intentions.
* **If you sell services on top of it** → you are welcome to. Attribution is
  required (MIT) and the trust pack is the artifact that closes deals.

If you would rather not build it yourself, or you want it deployed with your own
branding and a client-ready trust pack:
**[turnkey setup →](https://az-consultants.pages.dev/funnel)**

Contributions that make this genuinely stronger are welcome — more detectors
(regions, languages), OCR intake, Windows/macOS vault paths, and translations of the
trust pack. Open an issue with the threat you are covering, not just the patch.

## Repository layout

```
src/zeroegress/jail.py        egress enforcement (blocked + logged)
src/zeroegress/gate.py        sensitivity classification and redaction
src/zeroegress/local_llm.py   loopback-only model client (stdlib)
src/zeroegress/vault.py       per-client AES-256 vault + manifest
src/zeroegress/trustpack.py   client-facing statement/NDA/audit PDF
src/zeroegress/cli.py         zeroegress command line
tests/                        38 unit tests, no network, no cloud
docs/                         threat model, audit guide, NDA clauses, template
```

## License

MIT © 2026 Aamir Malik Zameer. See [LICENSE](LICENSE).

---

Part of [my always-on agent stack](https://github.com/Amz34) · [Awesome Agent Infrastructure](https://github.com/Amz34/awesome-agent-infrastructure) (135 live-checked building blocks).
