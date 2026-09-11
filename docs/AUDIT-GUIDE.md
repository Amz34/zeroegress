# Audit guide — for the client, not the vendor

Hand this to the party whose documents you hold. Every step runs on the machine
that holds the files, is read-only except where stated, and produces evidence
rather than reassurance.

## 1. Confirm the egress block is real

```bash
zeroegress prove
```

Expected: a table of **BLOCKED** attempts against well-known AI endpoints with the
mechanism shown (`socket.getaddrinfo()`, `socket.connect()`), followed by an answer
produced by a local model. Ask for the Wi-Fi to be switched off and run it again —
the answer still arrives.

## 2. Inspect the audit log

```bash
cat ~/.config/zeroegress/egress-attempts.jsonl
```

Append-only JSON lines: timestamp, host, port, mechanism, and the label of the
operation that tried. If a blocked attempt appears with an unexpected label, that is
the conversation to have.

## 3. Verify the vault against its manifest

```bash
zeroegress vault list "Your Company"      # archives + sizes
zeroegress vault verify "Your Company"    # decrypt, untar, sha256 vs manifest
```

`verify` fails loudly if any archive was modified after it was written. The
manifest lives next to the archives; compare the counts with the file list you
handed over.

## 4. Inspect the archive without the key

```bash
gpg --list-packets ~/vaults/<client>/vault/<archive>.tar.gz.gpg | head -20
```

You will see the cipher (`AES256`), the salt, and the S2K parameters — and no
filenames, no sizes, no content. Metadata is inside the encrypted payload. This is
the check that distinguishes real encryption from a password-protected archive that
still leaks its file names.

## 5. Hold the key yourself

```bash
zeroegress vault passphrase "Your Company"
```

Take this value into your own password manager. From that point, the vendor
retaining your documents is a *storage* fact, not a *disclosure* fact: without your
copy of the passphrase the archives are not readable, and revoking access means
rotating the key, not asking for a promise.

## 6. Ask for deletion, and verify it

```bash
zeroegress vault destroy "Your Company"        # archives + key, with confirmation
```

Then verify the backups: encrypted off-site copies have a retention window — ask
for it in writing (this repository's template states **5 days** for operational
backups; change it to what you actually do).

## 7. Read the paperwork against the code

```bash
zeroegress trustpack --org "<Vendor>" --client "Your Company" --out ./trust-pack
```

The generated statement lists the sub-processors actually used, the retention
window, and the breach-notice commitment. Anything in the document that the code
does not implement is a finding. That comparison is the audit — not the document.

## What you should not accept

* "We use a very secure AI provider" without a name, a tier, and a retention term.
* Encryption claims without a cipher, a key owner, and a verification command.
* A confidentiality document that makes claims nobody can run.
