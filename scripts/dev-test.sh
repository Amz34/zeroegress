#!/usr/bin/env bash
# Install zeroegress in a local venv and run the full unit suite.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=/tmp/zeroegress_test.txt
{
  echo "== python =="; python3 -V
  if [ ! -d .venv ]; then python3 -m venv .venv; fi
  ./.venv/bin/python -m pip install -q --upgrade pip
  ./.venv/bin/python -m pip install -q -e .
  echo "== unittest =="
  ./.venv/bin/python -m unittest discover -s tests 2>&1 | tail -25
  echo "== cli status =="
  ./.venv/bin/zeroegress status
  echo "== gate demo (expect exit 11) =="
  set +e
  ./.venv/bin/zeroegress gate examples/sample-tender.txt
  echo "gate exit=$?"
  echo "== vault demo =="
  TMPV=$(mktemp -d)
  ./.venv/bin/zeroegress vault init --client "Demo Client" --root "$TMPV/vaults" --keydir "$TMPV/keys" | tail -4
  ./.venv/bin/zeroegress vault add --client "Demo Client" --root "$TMPV/vaults" --keydir "$TMPV/keys" examples/sample-tender.txt
  ./.venv/bin/zeroegress vault verify --client "Demo Client" --root "$TMPV/vaults" --keydir "$TMPV/keys"
  rm -rf "$TMPV"
} > "$OUT" 2>&1
echo "written: $OUT"
