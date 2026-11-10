#!/bin/bash
# Quick test entry point: rebuild harness + oracle and run the ML-KEM-768
# battery on both builds plus the oracle, checking the headline results.
# Usage: scripts/run_tests.sh
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(cd "$PACK/../.." && pwd)/work}"
if [ ! -d "$WORK/install-ref" ]; then WORK="$PACK/work"; fi
cd "$PACK"
bash scripts/build_harness.sh
fail=0
for b in ref opt; do
  if [ "$b" = ref ]; then L=reference; else L=optimized; fi
  "$WORK/bin/mlkem_ir_harness_$b" ML-KEM-768 battery > /tmp/mlkem-test-$b.log 2>&1
  rc=$?
  echo "battery 768 $L rc=$rc $(grep '^RESULT:' /tmp/mlkem-test-$b.log)"
  [ $rc -ne 0 ] && fail=1
done
"$WORK/bin/explicit_rejection_oracle" ML-KEM-768 > /tmp/mlkem-test-oracle.log 2>&1
orc=$?
echo "oracle 768 rc=$orc $(grep '^RESULT:' /tmp/mlkem-test-oracle.log)"
[ $orc -eq 0 ] && { echo "ERROR: oracle unexpectedly passed"; fail=1; }
echo "run_tests.sh: $([ $fail -eq 0 ] && echo PASS || echo FAIL)"
exit $fail
