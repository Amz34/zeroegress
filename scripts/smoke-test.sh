#!/usr/bin/env bash
# Smoke test: run every command documented in the README against a temp root.
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=/tmp/zeroegress_smoke.txt
BIN=.venv/bin/zeroegress
T=/tmp/zg_smoke
rm -rf "$T"; mkdir -p "$T"
run() { echo; echo "\$ $*"; "$@" 2>&1 | sed 's/^/    /'; echo "    [exit=$?]"; }
{
  echo "== status =="; $BIN status | head -12
  echo "== gate (expect exit 11) =="; $BIN gate examples/sample-tender.txt; echo "gate exit=$?"
  echo "== gate --json =="; $BIN gate examples/sample-tender.txt --json | head -12
  echo "== redact =="; $BIN gate examples/sample-tender.txt --redacted-out "$T/redacted.txt" >/dev/null; \
    grep -c -E "EMAIL|PHONE|VAT|CR\]" "$T/redacted.txt" | sed 's/^/    placeholders: /'
  echo "== scan =="; $BIN scan examples | head -6
  echo "== vault =="
  run $BIN vault init --client "Acme Facilities" --root "$T/vaults" --keydir "$T/keys"
  run $BIN vault add --client "Acme Facilities" --root "$T/vaults" --keydir "$T/keys" examples/sample-tender.txt
  run $BIN vault verify --client "Acme Facilities" --root "$T/vaults" --keydir "$T/keys"
  run $BIN vault list --client "Acme Facilities" --root "$T/vaults" --keydir "$T/keys"
  run $BIN vault clients --root "$T/vaults" --keydir "$T/keys"
  ARC=$(ls "$T/vaults/acme-facilities/vault" | head -1)
  run $BIN vault extract --client "Acme Facilities" --archive "$ARC" --dest "$T/restored" --root "$T/vaults" --keydir "$T/keys"
  run $BIN vault destroy --client "Acme Facilities" --confirm wrong-slug --root "$T/vaults" --keydir "$T/keys"
  run $BIN vault destroy --client "Acme Facilities" --confirm acme-facilities --root "$T/vaults" --keydir "$T/keys"
  echo "== trustpack =="
  run $BIN trustpack --org "ZeroEgress Demo" --client-name "Acme Facilities" --contact "demo@example.com" --retention-days 30 --out "$T/pack.pdf"
  ls -l "$T" 2>/dev/null | sed 's/^/    /'
} > "$OUT" 2>&1
echo "written $OUT"
