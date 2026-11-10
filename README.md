# ML-KEM Implicit-Rejection Evidence Pack

Measured assessment of decapsulation-failure handling (FIPS 203 §7.3,
implicit rejection) across pinned reference and optimized ML-KEM builds
from liboqs 0.16.0.

## Headline results

- **Battery: PASS on both builds, all three parameter sets.**
  246 invalid ciphertexts per parameter set (200 random, 46 structured
  single/multi-bit flips, all-zero, all-0xFF), 1,476 invalid-ciphertext
  decapsulations total. Every one returned `OQS_SUCCESS` with a 32-byte
  shared secret that is deterministic for the same (secret key,
  ciphertext) pair, different from the valid shared secret `K`, and
  pairwise distinct. Zero failures of any kind.
- **Re-encryption check observed directly (ML-KEM-768, reference
  sources):** 33 of 46 single-bit-flipped ciphertexts decrypt to the
  *same* message as the valid ciphertext, yet decapsulation returns the
  fallback secret — the rejection comes solely from the re-encryption
  comparison (`c' != ct`), exactly as FIPS 203 §7.3 specifies.
- **Cross-build agreement:** the fallback values are bit-identical
  between the reference and optimized builds for all three parameter
  sets.
- **Timing:** no valid-vs-invalid decapsulation time difference
  detectable above the noise floor on this machine (see
  `docs/index.html` for the tables; 20,000 iterations per case).
- **Before/after case:** a deliberately wrong explicit-rejection test
  oracle fails the identical battery 0/246, while both pinned builds
  pass it 246/246. The oracle is a test artifact only — not a real
  implementation or a vulnerability.

No deviation from FIPS 203 §7.3 was found in either pinned build.
Findings, severity ratings, remediation guidance and limitations:
`docs/index.html`. Claims → evidence: `docs/evidence-index.md`.
Methodology (pinned builds, environment, test design):
`docs/methodology.md`.

## Pinned builds

| Build | liboqs | `OQS_OPT_TARGET` | ML-KEM code |
|---|---|---|---|
| reference | 0.16.0 | `generic` | mlkem-native `_ref` only (no AVX2) |
| optimized | 0.16.0 | `auto` | mlkem-native `_ref` + `_x86_64` (AVX2) |

Source tarball: `fixtures/liboqs-0.16.0.tar.gz`
(SHA256 `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`).
Compiler: GCC 13.3.0, CMake 3.28.3, Release. Machine: Intel Xeon
Platinum 8321HC @ 1.40 GHz, 4 vCPU, AVX2/AVX512, Ubuntu 24.04.

## Layout

- `src/mlkem_ir_harness.c` — battery + timing harness (public OQS_KEM API)
- `src/explicit_rejection_oracle.c` — test oracle (explicit rejection, fails by design)
- `src/reenc_observation.c` — re-encryption-check observation (internal mlkem-native API, ML-KEM-768 ref sources)
- `scripts/build_harness.sh`, `scripts/build_internal.sh` — compile the programs
- `scripts/run_all.sh` — run everything, write unedited logs + manifest
- `scripts/clean_reproduce.sh` — from a fresh copy: rebuild liboqs twice, re-run, compare headline numbers
- `scripts/run_tests.sh` — quick ML-KEM-768 battery + oracle check
- `scripts/verify_digests.sh`, `scripts/make_sha256sums.sh` — SHA256SUMS maintenance
- `outputs/` — unedited logs (builds, battery, timing, oracle, re-encryption observation), timing CSVs, diffs, `run-manifest.md`
- `docs/methodology.md`, `docs/evidence-index.md`, `docs/index.html`
- `fixtures/liboqs-0.16.0.tar.gz`

## Reproduce

```sh
# Needs the two liboqs installs (see docs/methodology.md) or run the
# full clean reproduction from a fresh copy:
scripts/clean_reproduce.sh

# Quick check (ML-KEM-768 battery on both builds + oracle):
scripts/run_tests.sh

# Full run (all batteries, timing, oracle, observation, manifest):
scripts/run_all.sh
scripts/verify_digests.sh
```

## Sources

- FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*,
  NIST, https://csrc.nist.gov/pubs/fips/203/final (§7.3, Table 3,
  Algorithms 14/15).
- liboqs 0.16.0, `docs/algorithms/kem/ml_kem.yml`; mlkem-native
  upstream commit `0ba906cb14b1c241476134d7403a811b382ca498`.
- Implementation under test: `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.c`
  (`mlk_kem_dec`), `indcpa.h`, `symmetric.h`.
