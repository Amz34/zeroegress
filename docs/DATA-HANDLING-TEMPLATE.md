# Data handling template

The PDF a client reads. Generate it with your own organisation and client names:

```bash
zeroegress trustpack --org "Your Firm" --client-name "Acme Facilities" --out ./trust-pack/acme-data-handling.pdf
```

That produces `Data-Handling-and-Confidentiality-<Client>.pdf` from
`src/zeroegress/templates/trust_pack.html`, with the client name, your
organisation, and the date substituted.

## What the template commits to

Fill it in to match what you actually do — every claim is supposed to be
verifiable, so an accurate document beats an impressive one:

| Section | Typical content |
|---------|-----------------|
| Scope | defines "confidential information", including derivatives and extracts |
| Where processing happens | named machine/region under your control; local models |
| What never leaves | documents, embeddings, prompts, outputs, file names |
| Sub-processors | only those you actually use, with purpose; "none" is a valid answer |
| Encryption at rest | AES-256 archives, manifest with SHA-256, key custody |
| Retention and deletion | engagement + N days, backups window, deletion confirmation |
| Cross-client isolation | one key per client, no shared index |
| Breach notice | 72 hours, with the information the client needs |
| Verification | the client runs the audit steps themselves |
| Limits | disk encryption, human behaviour, model quality, no certification |

## Editing the template

1. Copy `src/zeroegress/templates/trust_pack.html` and edit the HTML text.
2. Keep the print CSS (`@page` rules) so the PDF paginates correctly.
3. Keep the placeholders `{{ORG}}`, `{{CLIENT}}`, `{{DATE}}` — they are substituted
   at render time.
4. Re-render and check page breaks:

```bash
zeroegress trustpack --org "Your Firm" --client "Acme" --out /tmp/tp
```

## Do not ship it with claims you cannot demonstrate

If your statement says "no third-party AI services are used", then do not use one —
not even for a quick translation. The audit guide gives the client the commands to
check, and the first contradiction is the end of the conversation.
