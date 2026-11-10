# Methodology — ML-KEM implicit-rejection evidence pack

## Question under test

FIPS 203, Section 7.3 (ML-KEM.Decaps) requires **implicit rejection**: when a
ciphertext fails the re-encryption check, decapsulation must still return a
32-byte shared secret — the pseudorandom fallback `K = J(z || c)` — and must
never signal failure, never return the valid shared secret `K`, and never
return an error. This pack tests that behavior on two pinned builds of
liboqs 0.16.0 (reference and optimized), across ML-KEM-512, ML-KEM-768 and
ML-KEM-1024.

## Pinned builds

| Build | liboqs | `OQS_OPT_TARGET` | ML-KEM code compiled | Compiler |
|---|---|---|---|---|
| reference | 0.16.0 | `generic` | mlkem-native `_ref` only (no AVX2) | GCC 13.3.0 |
| optimized | 0.16.0 | `auto` | mlkem-native `_ref` + `_x86_64` (AVX2, runtime dispatch) | GCC 13.3.0 |

- Source: `fixtures/liboqs-0.16.0.tar.gz`,
  SHA256 `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`.
- Version verified in both installs: `OQS_VERSION_TEXT "0.16.0"` in
  `include/oqs/oqsconfig.h`.
- Build flags (both): `-DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=OFF
  -DOQS_BUILD_ONLY_LIB=ON`. Full unedited build logs: `outputs/build-*.log`.
- The reference build log contains zero AVX2 compilation lines for ML-KEM;
  the optimized build log compiles the `x86_64` ML-KEM targets.
- The ML-KEM implementation in both builds is mlkem-native (upstream
  commit `0ba906cb14b1c241476134d7403a811b382ca498`, per
  `docs/algorithms/kem/ml_kem.yml` in the pinned tree).

## Test environment

- Machine: Intel(R) Xeon(R) Platinum 8321HC @ 1.40 GHz, 4 vCPU, AVX2 and
  AVX512 present (`/proc/cpuinfo`), 8 GB RAM.
- OS: Ubuntu 24.04, Linux kernel 7.0.0-44-generic, x86_64.
- OpenSSL 3.0.13 (libcrypto, linked by liboqs).
- Shared virtual machine: background load is not controlled, so timing
  results carry the noise floor reported with them; see Limitations.

## Test design

### Harness — `src/mlkem_ir_harness.c`

One C program, compiled twice (once per pinned install, `-DBUILD_LABEL`
set accordingly), driven only through the public `OQS_KEM` API. It uses
the liboqs deterministic APIs so every run is reproducible:

- Keypair: `OQS_KEM_keypair_derand` with fixed 64-byte seed
  `00 01 02 … 3f` (printed in every log).
- Encapsulation: `OQS_KEM_encaps_derand` with fixed 32-byte seed
  `a0 a1 … bf` (printed in every log).
- No secret key is ever printed. Public-key prefixes, ciphertexts and
  shared secrets of the ephemeral test keypair are printed; they are test
  data, not real credentials.

### Battery mode (`battery`)

For each parameter set, per build:

1. Size check: `pk`/`sk`/`ct`/`ss` lengths against FIPS 203, Table 3
   (512: 800/1632/768; 768: 1184/2400/1088; 1024: 1568/3168/1568; `ss` 32).
2. Valid round-trip: `decaps(encaps(pk)) == K`.
3. Invalid ciphertexts (246 unique per parameter set):
   - 200 random ciphertexts from a fixed-seed xorshift64 PRNG (test-input
     generation only; not cryptographic randomness).
   - 30 single-bit flips at spread byte positions (0, 1, 2, 3, 7, 15, 31,
     63, 127, 255, 511, ct/2, ct−3, ct−2, ct−1) × bits 0 and 7.
   - 16 single-bit flips (bit 0 of bytes 0–15).
   - 4 multi-bit flips (byte 0 = 0xFF; bytes 100–107 = 0xFF; 8 scattered
     bits; first + last byte = 0xFF).
   - All-zero ciphertext; all-0xFF ciphertext.
4. Per invalid ciphertext, the harness checks and logs:
   - `decaps` returns `OQS_SUCCESS` (never an error);
   - the returned secret differs from the valid `K`;
   - decapsulating the same (sk, ct) pair twice returns the identical
     secret (determinism);
   - the full 32-byte fallback value is printed in the log.
5. Summary: pairwise distinctness of all 246 fallback secrets
   (no duplicates allowed).

Because the seeds are fixed, the entire battery log (except the
`utc_start` line) is bit-identical across runs of the same binary and
across the two builds — the fallback values must agree exactly between
the reference and optimized builds. `scripts/run_all.sh` diffs run 1 vs
run 2 and reference vs optimized for all three parameter sets.

### Timing mode (`timing`)

For each parameter set, per build, `N = 20000` decapsulations each:

- Blocked: N valid decapsulations, then N invalid (single-bit flip,
  byte 0).
- Interleaved: N pairs, alternating valid/invalid, swapping order on odd
  iterations to cancel order bias.
- Encapsulation timing (N iterations) as a reference scale.
- Per-call times use `clock_gettime(CLOCK_MONOTONIC)`; the script reports
  mean, median, min, max and standard deviation (ns/call) and writes the
  raw per-call interleaved times to `outputs/timing-<alg>-<build>.csv`.
- Warmup: 1000 valid + 1000 invalid decapsulations before measurement.

### Re-encryption observation — `src/reenc_observation.c`

The public API cannot show *why* a ciphertext was rejected, so this
program (ML-KEM-768, reference sources only) links the **unmodified**
mlkem-native reference sources from the pinned tree and replays the exact
steps of `mlk_kem_dec` (FIPS 203 §7.3) with instrumentation:

```
m      = K-PKE.Decrypt(ct)          (FIPS 203 Algorithm 15)
(Kbar, r) = G(m || H(ek))           (SHA3-512)
c'     = K-PKE.Encrypt(m, r)        (FIPS 203 Algorithm 14)
fail   = (c' != ct)
ss     = J(z || ct) if fail else Kbar
```

For each single-bit flip it reports whether the decrypted message `m` is
unchanged from the valid ciphertext's message. A flip with unchanged `m`
has `c'` equal to the *original* ciphertext, so `c' != ct_flip` and the
rejection can only come from the re-encryption comparison. The program
self-checks the replication first: for the valid ciphertext it verifies
`c' == ct` and `Kbar == K` against the public API. Build:
`scripts/build_internal.sh` (same defines liboqs uses for the ML-KEM-768
ref target, minus `-fvisibility=hidden`).

### Test oracle (before/after case) — `src/explicit_rejection_oracle.c`

Both pinned builds behave correctly, so the before/after case is a
controlled experiment (see `docs/index.html`, Finding B/A). The oracle is
a deliberately wrong model of decapsulation — **explicit rejection**: it
returns an error and no shared secret for any ciphertext other than the
known valid one. It runs the identical invalid-ciphertext battery (same
seeds, same PRNG, same flip patterns) and fails it by design. The oracle
is a test artifact only: it is not a modified liboqs build, not a
vulnerability, and not a real implementation bug. Before = oracle failing
the battery; after = both pinned builds passing the identical battery.

## What the re-encryption check is (source-verified)

Read directly from the pinned source,
`src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.c`,
function `mlk_kem_dec` (comments in the source cite FIPS 203 §7.3):

1. `mlk_kem_check_sk` — verifies the secret key's stored `H(ek)`.
2. `mlk_indcpa_dec` — decrypts the ciphertext to a message `m`.
   (Decryption itself has no failure output; it always yields some `m`.)
3. `mlk_hash_g` — `(Kbar, r) = G(m || H(ek))`.
4. `mlk_indcpa_enc` — re-encrypts `m` with coins `r` to `c'`.
5. `fail = mlk_ct_memcmp(ct, c', ct_bytes)` — constant-time comparison.
6. The rejection key `J(z || ct)` is **always** computed.
7. `mlk_ct_cmov_zero(ss, kr, 32, fail)` — copies `Kbar` into the output
   only when `fail == 0`; otherwise the output stays `J(z || ct)`.

Consequences that the battery tests: an invalid ciphertext can never yield
an error, can never yield the valid `K`, and always yields the same
fallback for the same `(sk, ct)` — because `J(z || c)` is a deterministic
function of the secret-key component `z` and the ciphertext.

## Results summary

- Battery: **PASS on both builds, all three parameter sets.** 246 unique
  invalid ciphertexts per parameter set (200 random, 30 single-bit flips
  at spread positions, 10 additional bit-0 flips of bytes 0–15, 4
  multi-bit flips, all-zero, all-0xFF); 1,476 invalid-ciphertext
  decapsulations total. Every one returned `OQS_SUCCESS` with a 32-byte
  fallback secret that is deterministic for the same (secret key,
  ciphertext) pair, different from the valid `K`, and pairwise distinct
  (`rc_fail=0, det_fail=0, eqK=0, dup_pairs=0` in all six battery logs).
- Determinism: the ML-KEM-768 reference battery run twice produces
  bit-identical logs except the `utc_start` line
  (`outputs/diff-run1-run2.txt` is empty).
- Cross-build: fallback values are bit-identical between the reference
  and optimized builds for all three parameter sets
  (`outputs/diff-ref-opt-512/768/1024.txt` are empty).
- Re-encryption observation (ML-KEM-768, reference sources): self-check
  passes (`c' == ct`, `Kbar == K` for the valid ciphertext). 33 of 46
  single-bit flips decrypt to the same message as the valid ciphertext,
  yet decapsulation returns the fallback — the rejection comes solely
  from the re-encryption comparison.
- Before/after: the explicit-rejection test oracle fails the identical
  battery 0/246; both pinned builds pass it 246/246.
- Timing (20,000 iterations per case, interleaved medians): ML-KEM-512
  reference 85,002 ns valid vs 85,047 ns invalid; optimized 23,187 vs
  23,186 ns. ML-KEM-768 reference 133,192 vs 133,154 ns; optimized
  38,258 vs 38,262 ns. ML-KEM-1024 reference 182,823 vs 182,744 ns;
  optimized 50,582 vs 50,572 ns. Largest median gap: 79 ns (0.04%).
  No valid-vs-invalid difference is detectable above the noise floor.
  Noise disclosure: this timing run executed concurrently with the
  clean-reproduction build (two liboqs builds competing for the same 4
  vCPUs), so the per-call distributions carry large scheduling outliers
  (standard deviations 0.95–3.5 ms, maxima up to ~68 ms); the medians
  are the robust comparison and are stable (an earlier quiet-machine
  run gave medians within 1% of these). Full tables:
  `docs/index.html`; raw per-call data: `outputs/timing-*.csv`.
  See `outputs/run-manifest.md` for the full headline list.

## Limitations

- Empirical indistinguishability checks only: distinctness across 246
  invalid ciphertexts per parameter set and determinism across two runs
  are evidence, not a proof that `J(z || c)` is pseudorandom. No
  statistical test suite (e.g. NIST SP 800-22) was run on fallback
  outputs; the sample is far too small for that, and it is not claimed.
- Timing: single shared virtual machine, uncontrolled background load,
  1.40 GHz vCPU. The shipped timing run executed concurrently with the
  clean-reproduction build, so its distributions carry large scheduling
  outliers (stddev 0.95–3.5 ms, maxima up to ~68 ms); medians are the
  robust comparison. Reported differences are compared against the
  measured noise floor; a difference below the noise floor is reported
  as *not detectable*, not as *proven absent*. No cycle-accurate or
  cache-side-channel measurement was performed.
- The re-encryption observation covers ML-KEM-768 reference sources
  only; 512/1024 and the optimized (AVX2) path are verified through the
  public-API battery and the cross-build fallback equality, not through
  internal instrumentation.
- The internal observation compiles the reference sources with the same
  defines as liboqs but without `-fvisibility=hidden`; the code itself is
  unmodified (verified: built from the pinned tarball extract).
- Malformed/truncated ciphertexts cannot be passed through the public
  `OQS_KEM_decaps` API, which takes a fixed-length ciphertext buffer;
  length validation therefore cannot be tested at this layer and is not
  claimed.
- Constant-time behavior of the comparison (`mlk_ct_memcmp` /
  `mlk_ct_cmov_zero`) is verified by code inspection of the pinned source,
  not by a timing or power measurement capable of detecting a leak.

## Reproduction

```
scripts/build_harness.sh     # compile harness + oracle (needs work/install-*)
scripts/run_all.sh           # full battery + timing + oracle + manifest
scripts/build_internal.sh    # compile re-encryption observation harness
scripts/clean_reproduce.sh   # from a fresh copy: rebuild liboqs twice,
                             # rebuild everything, re-run ML-KEM-768 battery
                             # + observation, compare headline numbers
scripts/verify_digests.sh    # verify SHA256SUMS over all pack files
```

## Primary sources

- FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*,
  NIST, https://csrc.nist.gov/pubs/fips/203/final — §7.3 ML-KEM.Decaps
  (implicit rejection, re-encryption check), Table 3 (sizes), Algorithms
  14/15 (K-PKE.Encrypt/Decrypt), §3.3 (destruction of intermediate
  values). Cited via the pinned implementation, which quotes the section
  numbers in its comments; no local copy of the PDF was available, so
  section-level claims are indexed to the implementation comments and the
  standard's public URL.
- liboqs 0.16.0, `docs/algorithms/kem/ml_kem.yml` — ML-KEM standardized
  by NIST (FIPS 203), upstream mlkem-native commit, parameter-set sizes,
  `no-secret-dependent-branching-claimed: true`.
- liboqs 0.16.0 source, `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.c`
  (`mlk_kem_dec`), `indcpa.c`/`indcpa.h` (Algorithms 14/15),
  `symmetric.h` (`G` = SHA3-512, `J` = SHAKE-256, `H` = SHA3-256).
