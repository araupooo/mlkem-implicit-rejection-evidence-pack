/*
 * mlkem_ir_harness.c — ML-KEM implicit-rejection test harness.
 *
 * Tests FIPS 203 Section 7.3 (ML-KEM.Decaps) implicit rejection on pinned
 * liboqs 0.16.0 builds, through the public OQS_KEM API only:
 *
 *   battery: valid encaps/decaps round-trip, then a battery of invalid
 *            ciphertexts (random, single-bit flips, multi-bit flips,
 *            all-zero, all-0xFF). For each invalid ciphertext the harness
 *            checks that decapsulation (a) returns OQS_SUCCESS,
 *            (b) returns a 32-byte shared secret, (c) that secret differs
 *            from the valid shared secret K, and (d) that it is
 *            deterministic for the same (secret key, ciphertext) pair.
 *            It also checks all fallback secrets are pairwise distinct.
 *   timing:  decapsulation wall time for valid vs invalid ciphertexts,
 *            blocked and interleaved, with mean/median/min/max/stddev.
 *
 * Determinism: keypair and encapsulation use the liboqs *_derand APIs with
 * fixed seeds printed in the log, so the whole battery output (except the
 * timing mode) is bit-identical across runs and across builds. Random
 * invalid ciphertexts come from a fixed-seed xorshift64 PRNG (test-input
 * generation only; not cryptographic randomness).
 *
 * The harness never prints a secret key. It prints public-key prefixes,
 * ciphertexts and shared secrets of ephemeral test keypairs generated at
 * runtime; those values are test data, not real credentials.
 *
 * Build (example):
 *   cc -O2 -DBUILD_LABEL='"reference"' -I<install>/include \
 *      mlkem_ir_harness.c -L<install>/lib -loqs -lcrypto \
 *      -o mlkem_ir_harness_ref
 */
#include <oqs/oqs.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef BUILD_LABEL
#define BUILD_LABEL "unknown"
#endif

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s=", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/* Fixed-seed xorshift64* PRNG: test-input generation only. */
static uint64_t xs_state = 0x9E3779B97F4A7C15ULL;
static uint64_t xs_next(void) {
    uint64_t x = xs_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    xs_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static void xs_bytes(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if ((i % 8) == 0) {
            uint64_t v = xs_next();
            memcpy(out + i, &v, (len - i) < 8 ? (len - i) : 8);
        }
    }
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, uint8_t *out, size_t len) {
    if (strlen(s) != 2 * len) return -1;
    for (size_t i = 0; i < len; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void stats(const char *label, uint64_t *t, size_t n) {
    uint64_t *s = malloc(n * sizeof(uint64_t));
    if (s == NULL) { printf("%s: OOM\n", label); return; }
    memcpy(s, t, n * sizeof(uint64_t));
    qsort(s, n, sizeof(uint64_t), cmp_u64);
    double sum = 0.0;
    for (size_t i = 0; i < n; i++) sum += (double)s[i];
    double mean = sum / (double)n;
    double var = 0.0;
    for (size_t i = 0; i < n; i++) {
        double d = (double)s[i] - mean;
        var += d * d;
    }
    var /= (double)n;
    double sd = 0.0;
    /* sqrt without libm dependency: Newton iteration */
    {
        double g = var > 0 ? var : 1.0;
        for (int i = 0; i < 40; i++) g = 0.5 * (g + var / g);
        sd = g;
        if (var == 0.0) sd = 0.0;
    }
    printf("%s: n=%zu mean=%.1f median=%llu min=%llu max=%llu stddev=%.1f ns/call\n",
           label, n, mean,
           (unsigned long long)s[n / 2],
           (unsigned long long)s[0],
           (unsigned long long)s[n - 1], sd);
    free(s);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <ML-KEM-512|ML-KEM-768|ML-KEM-1024> <battery|timing> "
                        "[keypair_seed_hex128] [encaps_seed_hex64] [n_random] [n_timing] [timing_csv]\n", argv[0]);
        return 2;
    }
    const char *alg = argv[1];
    const char *mode = argv[2];

    uint8_t kp_seed[64], enc_seed[32];
    for (int i = 0; i < 64; i++) kp_seed[i] = (uint8_t)i;            /* 00 01 ... 3f */
    for (int i = 0; i < 32; i++) enc_seed[i] = (uint8_t)(0xA0 + i); /* a0 a1 ... bf */
    if (argc > 3 && argv[3][0] != '\0' && parse_hex(argv[3], kp_seed, 64) != 0) {
        fprintf(stderr, "bad keypair seed hex\n");
        return 2;
    }
    if (argc > 4 && argv[4][0] != '\0' && parse_hex(argv[4], enc_seed, 32) != 0) {
        fprintf(stderr, "bad encaps seed hex\n");
        return 2;
    }
    long n_random = 200;
    if (argc > 5) n_random = atol(argv[5]);
    long n_timing = 20000;
    if (argc > 6) n_timing = atol(argv[6]);
    const char *timing_csv = (argc > 7) ? argv[7] : NULL;

    printf("harness=mlkem_ir_harness build=%s liboqs=%s mode=%s alg=%s\n",
           BUILD_LABEL, OQS_VERSION_TEXT, mode, alg);
    {
        time_t now = time(NULL);
        printf("utc_start=%s", ctime(&now));
    }
    print_hex("keypair_seed", kp_seed, 64);
    print_hex("encaps_seed", enc_seed, 32);

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (kem == NULL) {
        printf("RESULT: FAIL kem_new returned NULL for %s\n", alg);
        return 1;
    }
    printf("lengths: pk=%zu sk=%zu ct=%zu ss=%zu keypair_seed=%zu encaps_seed=%zu\n",
           kem->length_public_key, kem->length_secret_key,
           kem->length_ciphertext, kem->length_shared_secret,
           kem->length_keypair_seed, kem->length_encaps_seed);

    /* Expected sizes per FIPS 203, Table 3. */
    size_t exp_pk = 0, exp_sk = 0, exp_ct = 0;
    if (strcmp(alg, "ML-KEM-512") == 0) { exp_pk = 800; exp_sk = 1632; exp_ct = 768; }
    else if (strcmp(alg, "ML-KEM-768") == 0) { exp_pk = 1184; exp_sk = 2400; exp_ct = 1088; }
    else if (strcmp(alg, "ML-KEM-1024") == 0) { exp_pk = 1568; exp_sk = 3168; exp_ct = 1568; }
    int sizes_ok = (kem->length_public_key == exp_pk &&
                    kem->length_secret_key == exp_sk &&
                    kem->length_ciphertext == exp_ct &&
                    kem->length_shared_secret == 32);
    printf("sizes_check: expected pk=%zu sk=%zu ct=%zu ss=32 -> %s\n",
           exp_pk, exp_sk, exp_ct, sizes_ok ? "OK" : "MISMATCH");

    size_t pk_len = kem->length_public_key;
    size_t sk_len = kem->length_secret_key;
    size_t ct_len = kem->length_ciphertext;
    size_t ss_len = kem->length_shared_secret;
    if (pk_len == 0 || sk_len == 0 || ct_len == 0 || ss_len == 0) {
        printf("RESULT: FAIL zero length\n");
        return 1;
    }

    uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
    uint8_t *ct0 = malloc(ct_len), *K0 = malloc(ss_len);
    uint8_t *ss = malloc(ss_len), *ss2 = malloc(ss_len);
    if (!pk || !sk || !ct0 || !K0 || !ss || !ss2) {
        printf("RESULT: FAIL OOM\n");
        return 1;
    }

    if (OQS_KEM_keypair_derand(kem, pk, sk, kp_seed) != OQS_SUCCESS) {
        printf("RESULT: FAIL keypair_derand\n");
        return 1;
    }
    if (OQS_KEM_encaps_derand(kem, ct0, K0, pk, enc_seed) != OQS_SUCCESS) {
        printf("RESULT: FAIL encaps_derand\n");
        return 1;
    }
    print_hex("pk_prefix32", pk, 32);
    print_hex("ct0", ct0, ct_len);
    print_hex("K0_valid", K0, ss_len);

    if (OQS_KEM_decaps(kem, ss, ct0, sk) != OQS_SUCCESS) {
        printf("valid_decaps: rc=FAIL (decaps returned error on valid ct)\n");
        printf("RESULT: FAIL valid decaps error\n");
        return 1;
    }
    printf("valid_decaps: rc=OQS_SUCCESS match_K=%s\n",
           memcmp(ss, K0, ss_len) == 0 ? "YES" : "NO");
    if (memcmp(ss, K0, ss_len) != 0) {
        printf("RESULT: FAIL valid decaps secret mismatch\n");
        return 1;
    }

    if (strcmp(mode, "battery") == 0) {
        /* Build the invalid-ciphertext list. */
        size_t cap = (size_t)(n_random + 64);
        uint8_t **cts = malloc(cap * sizeof(uint8_t *));
        char **kinds = malloc(cap * sizeof(char *));
        if (!cts || !kinds) { printf("RESULT: FAIL OOM\n"); return 1; }
        size_t n = 0, n_dup_inputs = 0;
        char tmp[128];
        uint8_t *c;
        /* add_ct: append an invalid ciphertext unless it duplicates an
         * earlier one (the flip patterns intentionally overlap); a
         * duplicate input would trivially produce a duplicate fallback
         * and must not count against distinctness. */
        #define ADD_CT(_c, _kind) do { \
            int _dup = 0; \
            for (size_t _i = 0; _i < n; _i++) { \
                if (memcmp(cts[_i], (_c), ct_len) == 0) { _dup = 1; break; } \
            } \
            if (_dup) { free(_c); n_dup_inputs++; } \
            else { cts[n] = (_c); kinds[n] = strdup(_kind); n++; } \
        } while (0)

        for (long i = 0; i < n_random; i++) {
            c = malloc(ct_len);
            xs_bytes(c, ct_len);
            snprintf(tmp, sizeof(tmp), "random #%ld", i);
            ADD_CT(c, tmp);
        }
        /* Single-bit flips at spread positions, bits 0 and 7. */
        size_t positions[] = {0, 1, 2, 3, 7, 15, 31, 63, 127, 255, 511,
                              ct_len / 2, ct_len - 3, ct_len - 2, ct_len - 1};
        for (size_t p = 0; p < sizeof(positions) / sizeof(positions[0]); p++) {
            if (positions[p] >= ct_len) continue;
            for (int bit = 0; bit < 8; bit += 7) {
                c = malloc(ct_len);
                memcpy(c, ct0, ct_len);
                c[positions[p]] ^= (uint8_t)(1u << bit);
                snprintf(tmp, sizeof(tmp), "1bit byte=%zu bit=%d", positions[p], bit);
                ADD_CT(c, tmp);
            }
        }
        /* bit 0 of each of the first 16 bytes. */
        for (size_t b = 0; b < 16 && b < ct_len; b++) {
            c = malloc(ct_len);
            memcpy(c, ct0, ct_len);
            c[b] ^= 0x01;
            snprintf(tmp, sizeof(tmp), "1bit byte=%zu bit=0", b);
            ADD_CT(c, tmp);
        }
        /* Multi-bit flips. */
        {
            c = malloc(ct_len); memcpy(c, ct0, ct_len); c[0] ^= 0xFF;
            ADD_CT(c, "multibit byte0=0xFF");
            c = malloc(ct_len); memcpy(c, ct0, ct_len);
            for (int b = 100; b < 108 && b < (int)ct_len; b++) c[b] ^= 0xFF;
            ADD_CT(c, "multibit bytes100-107=0xFF");
            c = malloc(ct_len); memcpy(c, ct0, ct_len);
            for (int k = 0; k < 8; k++) c[(size_t)(k * 137 % (int)ct_len)] ^= (uint8_t)(1u << (k % 8));
            ADD_CT(c, "multibit 8 scattered bits");
            c = malloc(ct_len); memcpy(c, ct0, ct_len);
            c[0] ^= 0xFF; c[ct_len - 1] ^= 0xFF;
            ADD_CT(c, "multibit first+last byte 0xFF");
            c = malloc(ct_len); memset(c, 0, ct_len);
            ADD_CT(c, "all-zero");
            c = malloc(ct_len); memset(c, 0xFF, ct_len);
            ADD_CT(c, "all-0xFF");
        }
        #undef ADD_CT
        printf("battery: n_invalid_unique=%zu (random=%ld, deduped_inputs=%zu)\n",
               n, n_random, n_dup_inputs);

        uint8_t *all_ss = malloc(n * ss_len);
        if (!all_ss) { printf("RESULT: FAIL OOM\n"); return 1; }
        long rc_fail = 0, det_fail = 0, eqK = 0;
        for (size_t i = 0; i < n; i++) {
            OQS_STATUS rc1 = OQS_KEM_decaps(kem, ss, cts[i], sk);
            OQS_STATUS rc2 = OQS_KEM_decaps(kem, ss2, cts[i], sk);
            int det = (memcmp(ss, ss2, ss_len) == 0);
            int neK = (memcmp(ss, K0, ss_len) != 0);
            if (rc1 != OQS_SUCCESS || rc2 != OQS_SUCCESS) rc_fail++;
            if (!det) det_fail++;
            if (!neK) eqK++;
            memcpy(all_ss + i * ss_len, ss, ss_len);
            printf("INV %04zu kind=%s rc=%s det=%s neK=%s fallback=",
                   i, kinds[i],
                   rc1 == OQS_SUCCESS ? "OK" : "ERROR",
                   det ? "OK" : "FAIL", neK ? "OK" : "FAIL");
            for (size_t b = 0; b < ss_len; b++) printf("%02x", ss[b]);
            printf("\n");
        }
        /* Pairwise distinctness of fallback secrets. */
        long dup_pairs = 0;
        for (size_t i = 0; i < n; i++) {
            for (size_t j = i + 1; j < n; j++) {
                if (memcmp(all_ss + i * ss_len, all_ss + j * ss_len, ss_len) == 0) {
                    dup_pairs++;
                    if (dup_pairs <= 10) {
                        printf("DUP fallback: cases %zu and %zu identical\n", i, j);
                    }
                }
            }
        }
        printf("battery_summary: n=%zu rc_fail=%ld det_fail=%ld eqK=%ld dup_pairs=%ld\n",
               n, rc_fail, det_fail, eqK, dup_pairs);
        int pass = sizes_ok && rc_fail == 0 && det_fail == 0 && eqK == 0 && dup_pairs == 0;
        printf("RESULT: %s battery %s n=%zu\n", pass ? "PASS" : "FAIL", alg, n);
        return pass ? 0 : 1;
    }

    if (strcmp(mode, "timing") == 0) {
        size_t N = (size_t)n_timing;
        uint8_t *ct_bad = malloc(ct_len);
        memcpy(ct_bad, ct0, ct_len);
        ct_bad[0] ^= 0x01; /* single-bit flip, byte 0 */
        uint64_t *t_valid = malloc(N * sizeof(uint64_t));
        uint64_t *t_invalid = malloc(N * sizeof(uint64_t));
        if (!ct_bad || !t_valid || !t_invalid) { printf("RESULT: FAIL OOM\n"); return 1; }

        printf("timing: iters=%zu clock=CLOCK_MONOTONIC invalid_ct=1bit-flip-byte0\n", N);
        /* Warmup. */
        for (size_t i = 0; i < 1000; i++) {
            OQS_KEM_decaps(kem, ss, ct0, sk);
            OQS_KEM_decaps(kem, ss, ct_bad, sk);
        }
        /* Blocked: all valid, then all invalid. */
        for (size_t i = 0; i < N; i++) {
            uint64_t a = now_ns();
            OQS_KEM_decaps(kem, ss, ct0, sk);
            t_valid[i] = now_ns() - a;
        }
        for (size_t i = 0; i < N; i++) {
            uint64_t a = now_ns();
            OQS_KEM_decaps(kem, ss, ct_bad, sk);
            t_invalid[i] = now_ns() - a;
        }
        stats("timing_blocked_valid", t_valid, N);
        stats("timing_blocked_invalid", t_invalid, N);
        /* Interleaved: alternate, swapping order each iteration. */
        for (size_t i = 0; i < N; i++) {
            uint64_t a, b;
            if ((i % 2) == 0) {
                a = now_ns(); OQS_KEM_decaps(kem, ss, ct0, sk); t_valid[i] = now_ns() - a;
                a = now_ns(); OQS_KEM_decaps(kem, ss, ct_bad, sk); t_invalid[i] = now_ns() - a;
            } else {
                a = now_ns(); OQS_KEM_decaps(kem, ss, ct_bad, sk); t_invalid[i] = now_ns() - a;
                a = now_ns(); OQS_KEM_decaps(kem, ss, ct0, sk); t_valid[i] = now_ns() - a;
            }
            (void)b;
        }
        stats("timing_interleaved_valid", t_valid, N);
        stats("timing_interleaved_invalid", t_invalid, N);
        /* Encaps reference timing. */
        for (size_t i = 0; i < N; i++) {
            uint64_t a = now_ns();
            OQS_KEM_encaps(kem, ct_bad, ss, pk);
            t_valid[i] = now_ns() - a;
        }
        stats("timing_encaps_ref", t_valid, N);
        if (timing_csv != NULL) {
            /* Re-run interleaved once more, dumping raw per-call times. */
            FILE *f = fopen(timing_csv, "w");
            if (f != NULL) {
                fprintf(f, "i,valid_ns,invalid_ns\n");
                for (size_t i = 0; i < N; i++) {
                    uint64_t a = now_ns(); OQS_KEM_decaps(kem, ss, ct0, sk);
                    uint64_t tv = now_ns() - a;
                    a = now_ns(); OQS_KEM_decaps(kem, ss, ct_bad, sk);
                    uint64_t ti = now_ns() - a;
                    fprintf(f, "%zu,%llu,%llu\n", i,
                            (unsigned long long)tv, (unsigned long long)ti);
                }
                fclose(f);
                printf("timing_csv: wrote %s (%zu rows)\n", timing_csv, N);
            } else {
                printf("timing_csv: FAILED to open %s\n", timing_csv);
            }
        }
        printf("RESULT: PASS timing %s iters=%zu\n", alg, N);
        return 0;
    }

    printf("RESULT: FAIL unknown mode %s\n", mode);
    return 2;
}
