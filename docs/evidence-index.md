# Evidence index — ML-KEM implicit-rejection evidence pack

Every claim maps to a runnable script and an unedited output log.
"Status" is PASS / FAIL / UNPROVEN. All numbers below come from the
shipped logs; re-run with `scripts/run_all.sh`.

## Specification-derived claims (FIPS 203)

| ID | Claim | Evidence | Source | Status |
|---|---|---|---|---|
| S1 | ML-KEM sizes (FIPS 203 Table 3): 512 → ek 800, dk 1632, ct 768; 768 → 1184/2400/1088; 1024 → 1568/3168/1568; shared secret 32 B | `outputs/battery-*.log` — `sizes_check: ... -> OK` (all 6 runs) | FIPS 203, Table 3 | PASS |
| S2 | Decapsulation of a valid ciphertext returns the encapsulated shared secret | `outputs/battery-*.log` — `valid_decaps: rc=OQS_SUCCESS match_K=YES` | FIPS 203 §7.3, ML-KEM.Decaps | PASS |
| S3 | Decapsulation never returns an error for an invalid ciphertext; it always returns a 32-byte secret | `outputs/battery-*.log` — `battery_summary: rc_fail=0` (246 invalid cts × 3 parameter sets × 2 builds) | FIPS 203 §7.3 (implicit rejection) | PASS |
| S4 | The fallback secret is deterministic for the same (secret key, ciphertext) pair | `outputs/battery-*.log` — `det_fail=0`; run1 vs run2 logs identical (`outputs/diff-run1-run2.txt`, empty) | FIPS 203 §7.3, `K = J(z \|\| c)` | PASS |
| S5 | The fallback secret is never the valid shared secret `K` | `outputs/battery-*.log` — `eqK=0` | FIPS 203 §7.3 | PASS |
| S6 | Fallback secrets are pairwise distinct across different invalid ciphertexts (246 per parameter set, per build) | `outputs/battery-*.log` — `dup_pairs=0` | FIPS 203 §7.3 (fallback binds the full ciphertext); empirical only, see L1 | PASS (empirical) |
| S7 | The implementation performs the re-encryption comparison and rejects on mismatch even when decryption yields the original message | `outputs/reenc-observation-ml-kem-768-reference.log` — 33/46 single-bit flips decrypt to the same message, yet decapsulation returns the fallback; self-check `c'==ct0`, `Kbar==K0` | FIPS 203 §7.3; liboqs 0.16.0 `kem.c` `mlk_kem_dec` (`fail = ct_memcmp(ct, c')`) | PASS (ML-KEM-768 ref sources) |
| S8 | The fallback is `J(z \|\| c)`: it is computed for every decapsulation and selected by a constant-time move, not a branch | Code inspection: `kem.c` — `J(z\|\|c)` always computed, `mlk_ct_cmov_zero` selects `Kbar` only if `fail==0`; comparison via `mlk_ct_memcmp` | liboqs 0.16.0 `kem.c`; FIPS 203 §7.3 | PASS (code inspection; timing side-channel not measured, see L3) |
| S9 | Reference and optimized builds behave identically on the invalid-ciphertext battery (same fallback values) | `outputs/diff-ref-opt-*.txt` (empty for 512/768/1024) | — (cross-build consistency) | PASS |
| S10 | Valid vs invalid decapsulation timing: no detectable difference above the noise floor (interleaved medians, 20,000 iters/case: largest gap 79 ns, 0.04%, ML-KEM-1024 reference) | `outputs/timing-*.log` — blocked + interleaved stats; raw per-call data in `outputs/timing-*.csv` | — (measurement; see L2) | PASS (no detectable difference) |

## Before / after case

| ID | Claim | Evidence | Status |
|---|---|---|---|
| B1 | BEFORE: an explicit-rejection decapsulator fails the FIPS 203 §7.3 battery (returns an error and no secret for invalid ciphertexts) | `outputs/oracle-ml-kem-768.log` — `oracle_battery_summary: pass=0/246` | PASS (test oracle, by design) |
| B2 | AFTER: both pinned liboqs 0.16.0 builds pass the identical battery (246/246) | `outputs/battery-ml-kem-768-reference.log`, `outputs/battery-ml-kem-768-optimized.log` — `RESULT: PASS` | PASS |

The oracle is a test artifact only: a deliberately wrong model of
explicit rejection. It is not a modified liboqs build, not a
vulnerability, and not a real implementation bug.

## Findings (severity-rated; see docs/index.html)

| ID | Severity | Finding |
|---|---|---|
| F1 | Informational | No deviation found in either pinned build: implicit rejection behaves per FIPS 203 §7.3 on all 1,476 invalid-ciphertext decapsulations tested (246 × 3 parameter sets × 2 builds). |
| F2 | Informational | Fallback determinism and distinctness hold exactly, including bit-identical fallback values across the reference and optimized builds. |
| F3 | Low | Failure-handling timing: no valid-vs-invalid difference detectable above the noise floor on this machine (see timing tables); the measurement cannot rule out a sub-noise-floor leak. Remediation: none required; re-measure on quiet, dedicated hardware before any timing-sensitive deployment claim. |
| F4 | Informational | The public `OQS_KEM_decaps` API takes a fixed-length ciphertext, so truncated/malformed-length inputs cannot be tested at this layer; length validation is out of scope for this pack. |
| F5 | Informational | Explicit rejection (returning an error on invalid ciphertext) would break the KEM contract and leak ciphertext validity; the oracle demonstrates the failure mode for implementers who might be tempted by it. Remediation guidance: always return `J(z \|\| c)`; never branch on validity in a caller-visible way. |

## Limitations (see docs/methodology.md)

- L1: Fallback pseudorandomness is checked empirically (distinctness over
  246 inputs per parameter set, determinism over two runs), not proven;
  no statistical test suite was run.
- L2: Timing measured on one shared virtual machine; differences below
  the noise floor are reported as not detectable, not proven absent.
- L3: Constant-time behavior of the comparison/move is verified by code
  inspection only, not by a side-channel measurement.
- L4: The re-encryption observation covers ML-KEM-768 reference sources
  only; 512/1024 and the AVX2 path are covered by the public-API battery
  and cross-build fallback equality.
- L5: Truncated/malformed-length ciphertexts cannot be passed through
  the public API and were not tested.

## Primary sources

- FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*,
  NIST, https://csrc.nist.gov/pubs/fips/203/final (§7.3, Table 3,
  Algorithms 14/15).
- liboqs 0.16.0, `docs/algorithms/kem/ml_kem.yml` (standardization
  status, upstream mlkem-native commit, parameter-set sizes).
- liboqs 0.16.0 source: `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.c`
  (`mlk_kem_dec`), `indcpa.h` (Algorithms 14/15), `symmetric.h`
  (`G` = SHA3-512, `J` = SHAKE-256, `H` = SHA3-256).
