/*
 * reenc_observation.c — observe the FIPS 203 Section 7.3 re-encryption
 * check directly, using the mlkem-native internal API.
 *
 * This program links the UNMODIFIED mlkem-native reference sources from
 * the pinned liboqs 0.16.0 tree (indcpa.c, poly.c, ...) with a test main
 * that replays the exact steps of mlk_kem_dec (FIPS 203 Algorithm 19,
 * ML-KEM.Decaps) with instrumentation:
 *
 *   m  = K-PKE.Decrypt(ct)            (FIPS 203 Algorithm 15)
 *   (Kbar, r) = G(m || H(ek))         (FIPS 203 Section 7.3, step 2)
 *   c' = K-PKE.Encrypt(m, r)          (FIPS 203 Algorithm 14)
 *   fail = (c' != ct)                 (constant-time compare in decaps)
 *   ss = J(z || ct) if fail else Kbar
 *
 * For each single-bit-flipped ciphertext it reports whether the decrypted
 * message m is UNCHANGED from the valid ciphertext's message. When m is
 * unchanged, re-encryption reproduces the ORIGINAL ciphertext c', so
 * c' != ct_flip and the ONLY reason decapsulation returns the fallback
 * (instead of the true K) is the re-encryption comparison itself. That is
 * the direct observation of the re-encryption check path: decryption
 * succeeded with an unchanged message, yet the ciphertext was rejected.
 *
 * The program also self-checks the replication: for the valid ciphertext
 * it verifies c' == ct and Kbar == K (the public-API shared secret).
 *
 * This is an observation harness over unmodified pinned sources, not a
 * modified implementation. ML-KEM-768 only (parameter set compiled in).
 *
 * Build: see scripts/build_internal.sh.
 */
#include <oqs/oqs.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Internal mlkem-native headers (include paths set by build script). */
#include "indcpa.h"
#include "symmetric.h"
#include "params.h"

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s=", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
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

int main(int argc, char **argv) {
    uint8_t kp_seed[64], enc_seed[32];
    for (int i = 0; i < 64; i++) kp_seed[i] = (uint8_t)i;
    for (int i = 0; i < 32; i++) enc_seed[i] = (uint8_t)(0xA0 + i);
    if (argc > 1 && parse_hex(argv[1], kp_seed, 64) != 0) return 2;
    if (argc > 2 && parse_hex(argv[2], enc_seed, 32) != 0) return 2;

    printf("reenc_observation: ML-KEM-768 reference sources (mlkem-native, liboqs %s)\n",
           OQS_VERSION_TEXT);
    {
        time_t now = time(NULL);
        printf("utc_start=%s", ctime(&now));
    }
    print_hex("keypair_seed", kp_seed, 64);
    print_hex("encaps_seed", enc_seed, 32);

    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    if (kem == NULL) { printf("RESULT: FAIL kem_new NULL\n"); return 1; }
    size_t pk_len = kem->length_public_key; /* 1184 */
    size_t sk_len = kem->length_secret_key; /* 2400 */
    size_t ct_len = kem->length_ciphertext; /* 1088 */
    size_t ss_len = kem->length_shared_secret; /* 32 */

    uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
    uint8_t *ct0 = malloc(ct_len), *K0 = malloc(ss_len);
    if (!pk || !sk || !ct0 || !K0) { printf("RESULT: FAIL OOM\n"); return 1; }
    if (OQS_KEM_keypair_derand(kem, pk, sk, kp_seed) != OQS_SUCCESS) return 1;
    if (OQS_KEM_encaps_derand(kem, ct0, K0, pk, enc_seed) != OQS_SUCCESS) return 1;
    print_hex("pk_prefix32", pk, 32);
    print_hex("ct0", ct0, ct_len);
    print_hex("K0_valid", K0, ss_len);

    /* H(ek): SHA3-256 of the public key (FIPS 203 7.3 uses H(ek)). */
    uint8_t h_ek[32];
    mlk_hash_h(h_ek, pk, pk_len);
    print_hex("H_ek", h_ek, 32);

    /* Valid ciphertext: replay decaps steps, self-check against public API. */
    uint8_t m0[32], buf_g[64], kr0[64], cprime0[1088];
    if (mlk_indcpa_dec(m0, ct0, sk, 0) != 0) {
        printf("selfcheck: indcpa_dec(valid) FAILED\n");
        printf("RESULT: FAIL selfcheck\n");
        return 1;
    }
    memcpy(buf_g, m0, 32);
    memcpy(buf_g + 32, h_ek, 32);
    mlk_hash_g(kr0, buf_g, 64);
    if (mlk_indcpa_enc(cprime0, m0, pk, kr0 + 32, 0) != 0) {
        printf("selfcheck: indcpa_enc(valid) FAILED\n");
        printf("RESULT: FAIL selfcheck\n");
        return 1;
    }
    print_hex("m0_decrypted", m0, 32);
    printf("selfcheck: reenc(ct0)==ct0 %s; Kbar==K0 %s\n",
           memcmp(cprime0, ct0, ct_len) == 0 ? "YES" : "NO",
           memcmp(kr0, K0, 32) == 0 ? "YES" : "NO");
    if (memcmp(cprime0, ct0, ct_len) != 0 || memcmp(kr0, K0, 32) != 0) {
        printf("RESULT: FAIL selfcheck replication does not match public API\n");
        return 1;
    }

    /* Single-bit flips: does m change? does re-encryption reproduce ct0? */
    size_t positions[] = {0, 1, 2, 3, 7, 15, 31, 63, 127, 255, 511,
                          ct_len / 2, ct_len - 3, ct_len - 2, ct_len - 1};
    long n_test = 0, n_same_m = 0, n_same_m_fallback = 0;
    uint8_t *ctf = malloc(ct_len);
    uint8_t m1[32], kr1[64], cprime[1088], ss[32];
    printf("flips: byte bit same_m reenc_eq_orig reenc_eq_flip fallback_neK\n");
    for (size_t p = 0; p < sizeof(positions) / sizeof(positions[0]); p++) {
        if (positions[p] >= ct_len) continue;
        for (int bit = 0; bit < 8; bit += 7) {
            memcpy(ctf, ct0, ct_len);
            ctf[positions[p]] ^= (uint8_t)(1u << bit);
            if (mlk_indcpa_dec(m1, ctf, sk, 0) != 0) {
                printf("FLIP byte=%zu bit=%d indcpa_dec FAILED\n", positions[p], bit);
                continue;
            }
            int same_m = (memcmp(m1, m0, 32) == 0);
            memcpy(buf_g, m1, 32);
            memcpy(buf_g + 32, h_ek, 32);
            mlk_hash_g(kr1, buf_g, 64);
            if (mlk_indcpa_enc(cprime, m1, pk, kr1 + 32, 0) != 0) {
                printf("FLIP byte=%zu bit=%d indcpa_enc FAILED\n", positions[p], bit);
                continue;
            }
            int re_orig = (memcmp(cprime, ct0, ct_len) == 0);
            int re_flip = (memcmp(cprime, ctf, ct_len) == 0);
            OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ctf, sk);
            int fallback = (rc == OQS_SUCCESS && memcmp(ss, K0, ss_len) != 0);
            n_test++;
            if (same_m) n_same_m++;
            if (same_m && fallback) n_same_m_fallback++;
            printf("FLIP byte=%zu bit=%d same_m=%s reenc_eq_orig=%s reenc_eq_flip=%s fallback_neK=%s m1=",
                   positions[p], bit,
                   same_m ? "YES" : "NO",
                   re_orig ? "YES" : "NO",
                   re_flip ? "YES" : "NO",
                   fallback ? "YES" : "NO");
            for (int b = 0; b < 32; b++) printf("%02x", m1[b]);
            printf(" fallback=");
            for (size_t b = 0; b < ss_len; b++) printf("%02x", ss[b]);
            printf("\n");
        }
    }
    /* Also the first 16 bytes, bit 0. */
    for (size_t b = 0; b < 16; b++) {
        memcpy(ctf, ct0, ct_len);
        ctf[b] ^= 0x01;
        if (mlk_indcpa_dec(m1, ctf, sk, 0) != 0) continue;
        int same_m = (memcmp(m1, m0, 32) == 0);
        memcpy(buf_g, m1, 32);
        memcpy(buf_g + 32, h_ek, 32);
        mlk_hash_g(kr1, buf_g, 64);
        if (mlk_indcpa_enc(cprime, m1, pk, kr1 + 32, 0) != 0) continue;
        int re_orig = (memcmp(cprime, ct0, ct_len) == 0);
        int re_flip = (memcmp(cprime, ctf, ct_len) == 0);
        OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ctf, sk);
        int fallback = (rc == OQS_SUCCESS && memcmp(ss, K0, ss_len) != 0);
        n_test++;
        if (same_m) n_same_m++;
        if (same_m && fallback) n_same_m_fallback++;
        printf("FLIP byte=%zu bit=0 same_m=%s reenc_eq_orig=%s reenc_eq_flip=%s fallback_neK=%s\n",
               b, same_m ? "YES" : "NO", re_orig ? "YES" : "NO",
               re_flip ? "YES" : "NO", fallback ? "YES" : "NO");
    }
    printf("reenc_summary: n_flips=%ld same_message=%ld same_message_and_fallback=%ld\n",
           n_test, n_same_m, n_same_m_fallback);
    printf("reenc_conclusion: %ld flipped ciphertext(s) decrypt to the SAME message as the valid ciphertext, yet decapsulation returns the fallback secret; for those inputs the rejection comes solely from the re-encryption comparison (c' != ct), as specified in FIPS 203 Section 7.3.\n",
           n_same_m_fallback);
    int pass = (n_same_m_fallback > 0);
    printf("RESULT: %s reenc_observation n_same_m_fallback=%ld\n",
           pass ? "PASS" : "FAIL", n_same_m_fallback);
    return pass ? 0 : 1;
}
