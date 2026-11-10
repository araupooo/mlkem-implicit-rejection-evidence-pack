/*
 * explicit_rejection_oracle.c — TEST ORACLE (not a real implementation).
 *
 * This program is a deliberately WRONG model of ML-KEM decapsulation:
 * it implements EXPLICIT rejection — it returns an error and no shared
 * secret for any ciphertext other than the one valid ciphertext it knows.
 * FIPS 203 Section 7.3 requires IMPLICIT rejection instead: decapsulation
 * must always return a 32-byte shared secret, K = J(z || c) for an
 * invalid ciphertext, and must never signal failure. Explicit rejection
 * leaks ciphertext validity to the caller and breaks the KEM contract.
 *
 * Purpose: the "before" side of a controlled before/after experiment.
 * The oracle runs the IDENTICAL invalid-ciphertext battery as
 * mlkem_ir_harness.c (same fixed seeds, same xorshift PRNG, same flip
 * patterns) and FAILS it, while the pinned liboqs 0.16.0 builds PASS the
 * identical battery. The oracle is a test artifact only; it is not a
 * modified liboqs build, not a vulnerability, and not a real
 * implementation bug. Do not present it as one.
 *
 * Build (example):
 *   cc -O2 -I<install>/include explicit_rejection_oracle.c \
 *      -L<install>/lib -loqs -lcrypto -o explicit_rejection_oracle
 */
#include <oqs/oqs.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s=", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

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

/*
 * oracle_decaps: explicit-rejection model. Returns 0 and writes K0 only
 * when ct is byte-identical to the valid ciphertext; returns -1 and
 * writes nothing otherwise. This is exactly what FIPS 203 7.3 forbids.
 */
static int oracle_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *ct0,
                         const uint8_t *K0, size_t ct_len, size_t ss_len) {
    if (memcmp(ct, ct0, ct_len) == 0) {
        memcpy(ss, K0, ss_len);
        return 0;
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <ML-KEM-512|ML-KEM-768|ML-KEM-1024> "
                        "[keypair_seed_hex128] [encaps_seed_hex64] [n_random]\n", argv[0]);
        return 2;
    }
    const char *alg = argv[1];
    uint8_t kp_seed[64], enc_seed[32];
    for (int i = 0; i < 64; i++) kp_seed[i] = (uint8_t)i;
    for (int i = 0; i < 32; i++) enc_seed[i] = (uint8_t)(0xA0 + i);
    if (argc > 2 && parse_hex(argv[2], kp_seed, 64) != 0) return 2;
    if (argc > 3 && parse_hex(argv[3], enc_seed, 32) != 0) return 2;
    long n_random = 200;
    if (argc > 4) n_random = atol(argv[4]);

    printf("oracle=explicit_rejection TEST-ORACLE-ONLY not-a-real-implementation\n");
    printf("oracle_semantics: return error and no shared secret for any ct != valid ct (explicit rejection; forbidden by FIPS 203 7.3)\n");
    printf("oracle alg=%s liboqs=%s\n", alg, OQS_VERSION_TEXT);
    {
        time_t now = time(NULL);
        printf("utc_start=%s", ctime(&now));
    }
    print_hex("keypair_seed", kp_seed, 64);
    print_hex("encaps_seed", enc_seed, 32);

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (kem == NULL) { printf("RESULT: FAIL kem_new NULL\n"); return 1; }
    size_t pk_len = kem->length_public_key, sk_len = kem->length_secret_key;
    size_t ct_len = kem->length_ciphertext, ss_len = kem->length_shared_secret;
    if (pk_len == 0 || sk_len == 0 || ct_len == 0 || ss_len == 0) {
        printf("RESULT: FAIL zero length\n");
        return 1;
    }
    uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
    uint8_t *ct0 = malloc(ct_len), *K0 = malloc(ss_len), *ss = malloc(ss_len);
    if (!pk || !sk || !ct0 || !K0 || !ss) { printf("RESULT: FAIL OOM\n"); return 1; }
    if (OQS_KEM_keypair_derand(kem, pk, sk, kp_seed) != OQS_SUCCESS) return 1;
    if (OQS_KEM_encaps_derand(kem, ct0, K0, pk, enc_seed) != OQS_SUCCESS) return 1;
    print_hex("pk_prefix32", pk, 32);
    print_hex("ct0", ct0, ct_len);
    print_hex("K0_valid", K0, ss_len);

    /* Valid ciphertext: oracle returns K0 (trivially, by comparison). */
    printf("valid_decaps: rc=%s match_K=%s\n",
           oracle_decaps(ss, ct0, ct0, K0, ct_len, ss_len) == 0 ? "OK" : "ERROR",
           memcmp(ss, K0, ss_len) == 0 ? "YES" : "NO");

    /* Identical invalid-ciphertext battery as mlkem_ir_harness.c. */
    size_t cap = (size_t)(n_random + 64);
    uint8_t **cts = malloc(cap * sizeof(uint8_t *));
    char **kinds = malloc(cap * sizeof(char *));
    size_t n = 0, n_dup_inputs = 0;
    char tmp[128];
    uint8_t *c;
    /* Same dedupe as mlkem_ir_harness.c: identical battery inputs. */
    #define ADD_CT(_c, _kind) do { \
        int _dup = 0; \
        for (size_t _i = 0; _i < n; _i++) { \
            if (memcmp(cts[_i], (_c), ct_len) == 0) { _dup = 1; break; } \
        } \
        if (_dup) { free(_c); n_dup_inputs++; } \
        else { cts[n] = (_c); kinds[n] = strdup(_kind); n++; } \
    } while (0)
    for (long i = 0; i < n_random; i++) {
        c = malloc(ct_len); xs_bytes(c, ct_len);
        snprintf(tmp, sizeof(tmp), "random #%ld", i); ADD_CT(c, tmp);
    }
    size_t positions[] = {0, 1, 2, 3, 7, 15, 31, 63, 127, 255, 511,
                          ct_len / 2, ct_len - 3, ct_len - 2, ct_len - 1};
    for (size_t p = 0; p < sizeof(positions) / sizeof(positions[0]); p++) {
        if (positions[p] >= ct_len) continue;
        for (int bit = 0; bit < 8; bit += 7) {
            c = malloc(ct_len); memcpy(c, ct0, ct_len);
            c[positions[p]] ^= (uint8_t)(1u << bit);
            snprintf(tmp, sizeof(tmp), "1bit byte=%zu bit=%d", positions[p], bit);
            ADD_CT(c, tmp);
        }
    }
    for (size_t b = 0; b < 16 && b < ct_len; b++) {
        c = malloc(ct_len); memcpy(c, ct0, ct_len); c[b] ^= 0x01;
        snprintf(tmp, sizeof(tmp), "1bit byte=%zu bit=0", b); ADD_CT(c, tmp);
    }
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
    #undef ADD_CT

    printf("battery: n_invalid_unique=%zu (random=%ld, deduped_inputs=%zu)\n",
           n, n_random, n_dup_inputs);
    long pass = 0;
    for (size_t i = 0; i < n; i++) {
        /* Battery criterion (FIPS 203 7.3): decaps must return a 32-byte
         * secret, deterministic, and different from the valid K. */
        memset(ss, 0, ss_len);
        int rc = oracle_decaps(ss, cts[i], ct0, K0, ct_len, ss_len);
        int ok = (rc == 0);
        if (ok) pass++;
        printf("INV %04zu kind=%s rc=%s criterion_32byte_secret=%s\n",
               i, kinds[i], rc == 0 ? "OK" : "ERROR", ok ? "PASS" : "FAIL");
    }
    printf("oracle_battery_summary: n=%zu pass=%ld fail=%zu\n", n, pass, n - (size_t)pass);
    printf("RESULT: FAIL oracle %s pass=%ld/%zu (explicit rejection fails the FIPS 203 7.3 battery by design)\n",
           alg, pass, n);
    return 1;
}
