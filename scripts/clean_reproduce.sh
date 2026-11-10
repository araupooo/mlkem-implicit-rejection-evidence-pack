#!/bin/bash
# Clean reproduction: from a fresh copy of this repository, rebuild both
# pinned liboqs 0.16.0 configurations from fixtures/, rebuild the harness
# and oracle, re-run the ML-KEM-768 battery on both builds plus the
# re-encryption observation, and compare the headline numbers against the
# shipped outputs/ logs (excluding timestamps and build labels).
#
# This takes a full liboqs build twice (~15-30 min on a 4-vCPU machine).
# Usage: scripts/clean_reproduce.sh [workdir]
#   workdir defaults to a fresh directory under /tmp.
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
R="${1:-/tmp/mlkem-ir-repro}"
echo "clean_reproduce: workdir=$R"
rm -rf "$R"
mkdir -p "$R"
cp -r "$PACK" "$R/pack"
cd "$R/pack"
mkdir -p work
tar xzf fixtures/liboqs-0.16.0.tar.gz -C work
mv work/liboqs-0.16.0 work/liboqs-0.16.0-src
# Build both configs (same flags as the shipped builds).
cmake -S work/liboqs-0.16.0-src -B work/build-ref \
  -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic \
  -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX="$R/pack/work/install-ref" \
  > work/repro-ref-cmake.log 2>&1
cmake --build work/build-ref -j2 > work/repro-ref-make.log 2>&1
cmake --install work/build-ref > work/repro-ref-install.log 2>&1
cmake -S work/liboqs-0.16.0-src -B work/build-opt \
  -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=auto \
  -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX="$R/pack/work/install-opt" \
  > work/repro-opt-cmake.log 2>&1
cmake --build work/build-opt -j2 > work/repro-opt-make.log 2>&1
cmake --install work/build-opt > work/repro-opt-install.log 2>&1
grep -h OQS_VERSION_TEXT work/install-ref/include/oqs/oqsconfig.h work/install-opt/include/oqs/oqsconfig.h
# Harness + oracle + internal observation, built against the fresh installs.
WORK="$R/pack/work" bash scripts/build_harness.sh
WORK="$R/pack/work" bash scripts/build_internal.sh
mkdir -p "$R/out"
"$R/pack/work/bin/mlkem_ir_harness_ref" ML-KEM-768 battery > "$R/out/battery-768-reference.log" 2>&1
"$R/pack/work/bin/mlkem_ir_harness_opt" ML-KEM-768 battery > "$R/out/battery-768-optimized.log" 2>&1
"$R/pack/work/bin/reenc_observation" > "$R/out/reenc-observation.log" 2>&1
"$R/pack/work/bin/explicit_rejection_oracle" ML-KEM-768 > "$R/out/oracle-768.log" 2>&1
echo "=== headline comparison (reproduced vs shipped) ==="
for f in reference optimized; do
  echo "--- battery-ml-kem-768-$f"
  echo "reproduced: $(grep -E '^battery_summary:|^RESULT:' "$R/out/battery-768-$f.log" | tr '\n' ' ')"
  echo "shipped:    $(grep -E '^battery_summary:|^RESULT:' "outputs/battery-ml-kem-768-$f.log" | tr '\n' ' ')"
  if diff <(grep -v "^utc_start=" "$R/out/battery-768-$f.log") <(grep -v "^utc_start=" "outputs/battery-ml-kem-768-$f.log") > /dev/null; then
    echo "log diff: IDENTICAL (excluding utc_start)"
  else
    echo "log diff: DIFFERS — inspect manually"
  fi
done
echo "--- reenc-observation"
grep -E "^reenc_summary:|^RESULT:" "$R/out/reenc-observation.log"
grep -E "^reenc_summary:|^RESULT:" outputs/reenc-observation-ml-kem-768-reference.log
echo "--- oracle"
grep -E "^oracle_battery_summary:|^RESULT:" "$R/out/oracle-768.log"
echo "clean_reproduce.sh DONE (workdir kept at $R)"
