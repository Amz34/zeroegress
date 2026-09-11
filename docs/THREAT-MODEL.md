# Threat model

What actually leaves your machine when you "use AI on documents", and which layer
of this repository covers it.

## 1. The documents themselves

A tender, a BOQ, a contract, a client spreadsheet. Most of the confidential value
in a bid is concentrated here: prices, margins, client names, registration numbers,
the authority's terms, sometimes the authority's own internal problems.

*Primary risk:* upload/paste into a third-party service.
*Covered by:* **gate** (classify first), **local_llm** (answer on the machine),
**jail** (make the upload impossible from the tool), **vault** (encrypt at rest).

## 2. Prompt and output logs at the provider

Every hosted model request passes through infrastructure you do not control:
request logs, abuse-monitoring pipelines, retention windows, and — depending on the
tier — training corpora. Free and consumer tiers of many providers reserve the right
to use inputs to improve their products; some tiers include human review of flagged
content. Retention and training behaviour differ per vendor **and per tier**, and
they change. The correct engineering response is not to pick the "nicer" vendor, it
is to not send the document.

*Covered by:* keeping the whole loop on loopback (`jail` + `local_llm`).

## 3. Embeddings and vector stores

A subtle one: you can keep the *chat* local and still leak the document by pushing
it through a hosted embedding endpoint to build a search index. Embeddings are
invertible enough to leak substantial content, and they are stored somewhere.

*Covered by:* local embeddings (`bge-m3`, `nomic-embed-text`) in the same Ollama
runtime the local client talks to. If you point this stack at a hosted embedding
service, you have re-opened the hole.

## 4. Local storage and physical access

Disk theft, backup drives, shared VMs, snapshots, and "temporary" copies in
`/tmp`, mail attachments downloaded twice, and the export somebody forgot.

*Covered by:* **vault** (AES-256 per client, manifest-verified) and encrypted
off-site backups. **Not covered by this repository:** full-disk encryption. Do that
at the OS level.

## 5. Cross-client contamination

The consultant's own risk. Client A's rates sitting in a folder next to client B's
folder, one shared passphrase, one shared index. This is usually the finding that
kills a deal during a security review.

*Covered by:* **vault** — one passphrase per client, separate archives, separate
keys, separate manifests.

## 6. The human

Paste into a personal account "just this once", forwarding to a personal email,
screenshotting into a group chat, running an unvetted plugin. No tool fixes this.
What a tool can do is make the safe path the fast path, and produce a log that
makes the unsafe path visible.

*Covered by:* **gate** exit codes in scripts, `scan` for a whole inbox,
`egress-attempts.jsonl` as an audit trail.

## 7. Model providers inside your own infrastructure

If you run local models, the model weights are still third-party artifacts, and a
provider could in principle ship something that phones home. Two mitigations: run
the jail (blocks it), and verify with `zeroegress prove` periodically so a
regression shows up as a blocked-attempt count changing, not as a surprise.

## What is explicitly out of scope

* Insider with root on the machine.
* A compromised OS or supply chain below the socket layer.
* Anything you type into a service that is not this tool.
* Compliance certification. This repository implements controls and produces
  evidence; it does not audit you.
