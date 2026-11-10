#!/bin/bash
# Compile the re-encryption observation harness against the UNMODIFIED
# mlkem-native reference sources from the pinned liboqs 0.16.0 tree.
# Same compiler flags/defines liboqs itself uses for the ML-KEM-768 ref
# target, minus -fvisibility=hidden so the test main can link the
# internal symbols. No liboqs source file is modified.
# Usage: scripts/build_internal.sh   (run from the repo root)
set -euo pipefail
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(cd "$PACK/../.." && pwd)/work}"
if [ ! -d "$WORK/install-ref" ]; then WORK="$PACK/work"; fi
SRC="$WORK/liboqs-0.16.0"
[ -d "$SRC" ] || SRC="$WORK/liboqs-0.16.0-src"
MLK="$SRC/src/kem/ml_kem/mlkem-native_ml-kem-768_ref"
mkdir -p "$WORK/bin"
cc -O2 -DNDEBUG -std=gnu11 \
  -DMLK_CONFIG_PARAMETER_SET=768 \
  -DMLK_CONFIG_FILE='"../../integration/liboqs/config_c.h"' \
  -I"$WORK/build-ref/include" \
  -I"$WORK/install-ref/include" \
  -I"$MLK" \
  -I"$MLK/mlkem/src" \
  -I"$SRC/src/common/pqclean_shims" \
  "$PACK/src/reenc_observation.c" \
  "$MLK/mlkem/src/compress.c" \
  "$MLK/mlkem/src/debug.c" \
  "$MLK/mlkem/src/indcpa.c" \
  "$MLK/mlkem/src/kem.c" \
  "$MLK/mlkem/src/poly.c" \
  "$MLK/mlkem/src/poly_k.c" \
  "$MLK/mlkem/src/sampling.c" \
  "$MLK/mlkem/src/verify.c" \
  "$WORK/install-ref/lib/liboqs.a" -lcrypto \
  -o "$WORK/bin/reenc_observation"
echo "built: $WORK/bin/reenc_observation"
