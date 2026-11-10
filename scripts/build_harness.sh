#!/bin/bash
# Compile the harness and the test oracle against both pinned installs.
# Usage: scripts/build_harness.sh   (run from the repo root, or set PACK)
set -euo pipefail
PACK="$(cd "$(dirname "$0")/.." && pwd)"
# WORK is the sibling work dir in the task folder; override with WORK env.
WORK="${WORK:-$(cd "$PACK/../.." && pwd)/work}"
# In a fresh clone there is no sibling work dir: fall back to ./work.
if [ ! -d "$WORK/install-ref" ]; then
  WORK="$PACK/work"
fi
mkdir -p "$WORK/bin"
built=0
if [ -d "$WORK/install-ref/include" ]; then
cc -O2 -DBUILD_LABEL='"reference"' -I"$WORK/install-ref/include" \
  "$PACK/src/mlkem_ir_harness.c" \
  "$WORK/install-ref/lib/liboqs.a" -lcrypto -o "$WORK/bin/mlkem_ir_harness_ref"
built=$((built+1))
else echo "SKIP reference harness: $WORK/install-ref not present yet"; fi
if [ -d "$WORK/install-opt/include" ]; then
cc -O2 -DBUILD_LABEL='"optimized"' -I"$WORK/install-opt/include" \
  "$PACK/src/mlkem_ir_harness.c" \
  "$WORK/install-opt/lib/liboqs.a" -lcrypto -o "$WORK/bin/mlkem_ir_harness_opt"
built=$((built+1))
else echo "SKIP optimized harness: $WORK/install-opt not present yet"; fi
if [ -d "$WORK/install-ref/include" ]; then
cc -O2 -I"$WORK/install-ref/include" \
  "$PACK/src/explicit_rejection_oracle.c" \
  "$WORK/install-ref/lib/liboqs.a" -lcrypto -o "$WORK/bin/explicit_rejection_oracle"
built=$((built+1))
else echo "SKIP oracle: $WORK/install-ref not present yet"; fi
echo "harness binaries built: $built"
ls -l "$WORK/bin/"
