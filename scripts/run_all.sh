#!/bin/bash
# Run the full measurement battery and save UNEDITED logs under outputs/.
# Usage: scripts/run_all.sh   (run from the repo root; WORK env override ok)
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(cd "$PACK/../.." && pwd)/work}"
if [ ! -d "$WORK/install-ref" ]; then WORK="$PACK/work"; fi
BIN="$WORK/bin"
OUT="$PACK/outputs"
mkdir -p "$OUT"
cd "$PACK"

fail=0
run() { # run <outfile> <cmd...>
  local out="$1"; shift
  echo "--- $out"
  "$@" > "$OUT/$out" 2>&1
  local rc=$?
  echo "    rc=$rc"
  if [ $rc -ne 0 ]; then echo "    NOTE: non-zero rc (see log)"; fi
  return 0
}

# --- Battery: 3 parameter sets x 2 builds (200 random invalid cts each) ---
for alg in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do
  lower=$(echo "$alg" | tr 'A-Z' 'a-z')
  run "battery-${lower}-reference.log" "$BIN/mlkem_ir_harness_ref" "$alg" battery
  run "battery-${lower}-optimized.log" "$BIN/mlkem_ir_harness_opt" "$alg" battery
done

# --- Determinism re-run: same battery, second process, same seeds ---
run "battery-ml-kem-768-reference-run2.log" "$BIN/mlkem_ir_harness_ref" ML-KEM-768 battery

# --- Timing: 3 parameter sets x 2 builds (20000 iters each) ---
for alg in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do
  lower=$(echo "$alg" | tr 'A-Z' 'a-z')
  run "timing-${lower}-reference.log" "$BIN/mlkem_ir_harness_ref" "$alg" timing "" "" 200 20000 "$OUT/timing-${lower}-reference.csv"
  run "timing-${lower}-optimized.log" "$BIN/mlkem_ir_harness_opt" "$alg" timing "" "" 200 20000 "$OUT/timing-${lower}-optimized.csv"
done

# --- Test oracle (before side of the before/after case), ML-KEM-768 ---
run "oracle-ml-kem-768.log" "$BIN/explicit_rejection_oracle" ML-KEM-768

# --- Re-encryption observation (internal API, reference sources), ML-KEM-768 ---
if [ -x "$BIN/reenc_observation" ]; then
  run "reenc-observation-ml-kem-768-reference.log" "$BIN/reenc_observation"
else
  echo "NOTE: reenc_observation binary missing (run scripts/build_internal.sh); skipping"
fi

# --- Cross-run / cross-build consistency checks (stdout only; logs untouched) ---
echo "=== determinism check: run1 vs run2 (ML-KEM-768 reference battery) ==="
if diff <(grep -v "^utc_start=" "$OUT/battery-ml-kem-768-reference.log") \
        <(grep -v "^utc_start=" "$OUT/battery-ml-kem-768-reference-run2.log") \
        > "$OUT/diff-run1-run2.txt" 2>&1; then
  echo "IDENTICAL (excluding utc_start)"
else
  echo "DIFFER (see outputs/diff-run1-run2.txt)"
fi
echo "=== cross-build check: reference vs optimized battery (ML-KEM-768) ==="
if diff <(grep -v "^utc_start=\|^harness=" "$OUT/battery-ml-kem-768-reference.log") \
        <(grep -v "^utc_start=\|^harness=" "$OUT/battery-ml-kem-768-optimized.log") \
        > "$OUT/diff-ref-opt-768.txt" 2>&1; then
  echo "IDENTICAL fallback values across builds (excluding header lines)"
else
  echo "DIFFER (see outputs/diff-ref-opt-768.txt)"
fi
echo "=== cross-build check: ML-KEM-512 and ML-KEM-1024 ==="
for alg in 512 1024; do
  if diff <(grep -v "^utc_start=\|^harness=" "$OUT/battery-ml-kem-${alg}-reference.log") \
          <(grep -v "^utc_start=\|^harness=" "$OUT/battery-ml-kem-${alg}-optimized.log") \
          > "$OUT/diff-ref-opt-${alg}.txt" 2>&1; then
    echo "ML-KEM-${alg}: IDENTICAL across builds"
  else
    echo "ML-KEM-${alg}: DIFFER (see outputs/diff-ref-opt-${alg}.txt)"
  fi
done

# --- Manifest ---
{
  echo "# Run manifest"
  echo
  echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo
  echo "Commands: scripts/run_all.sh (battery + timing + oracle, liboqs 0.16.0)"
  echo
  echo "## Output files (sha256)"
  echo
  (cd "$OUT" && sha256sum battery-*.log timing-*.log timing-*.csv oracle-*.log reenc-*.log build-*.log diff-*.txt 2>/dev/null)
  echo
  echo "## Headline results (from logs)"
  echo
  for f in "$OUT"/battery-*.log; do
    echo "### $(basename "$f")"
    grep -E "^battery_summary:|^RESULT:" "$f"
  done
  for f in "$OUT"/timing-*.log; do
    echo "### $(basename "$f")"
    grep -E "^timing_(blocked|interleaved)" "$f"
  done
  echo "### oracle-ml-kem-768.log"
  grep -E "^oracle_battery_summary:|^RESULT:" "$OUT/oracle-ml-kem-768.log"
  echo "### reenc-observation-ml-kem-768-reference.log"
  grep -E "^reenc_summary:|^RESULT:" "$OUT/reenc-observation-ml-kem-768-reference.log" 2>/dev/null || echo "(missing)"
} > "$OUT/run-manifest.md"
echo "=== manifest written: outputs/run-manifest.md ==="
cat "$OUT/run-manifest.md" | grep -E "^###|^battery_summary|^timing_|^oracle_battery|^RESULT" | head -60
echo "run_all.sh DONE"
