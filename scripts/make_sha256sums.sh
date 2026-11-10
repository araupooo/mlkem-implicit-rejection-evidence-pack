#!/bin/bash
# Regenerate SHA256SUMS over all pack files except itself.
# Usage: scripts/make_sha256sums.sh   (run from the repo root)
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK"
find . -type f ! -name SHA256SUMS ! -path "./.git/*" -print0 | sort -z |
  xargs -0 sha256sum > SHA256SUMS
echo "SHA256SUMS regenerated: $(wc -l < SHA256SUMS) files"
