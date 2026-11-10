#!/bin/bash
# Verify SHA256 digests of all pack files (except SHA256SUMS itself).
# Usage: scripts/verify_digests.sh   (run from the repo root)
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK"
if [ ! -f SHA256SUMS ]; then
  echo "SHA256SUMS missing — run scripts/make_sha256sums.sh first" >&2
  exit 1
fi
# Verify, excluding the SHA256SUMS file's own entry if present.
grep -v " SHA256SUMS$" SHA256SUMS | sha256sum -c -
