// Host tests for src/crypto.c. With no arguments: FIPS-197 / RFC 7748 vectors and CCM tamper checks.
// `crypto_test ccm` and `crypto_test x25519` read hex lines on stdin and print results, so
// test_crypto.py can compare them with tools/pulsar_crypto.py and the `cryptography` package.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto.h"

static int failures;
#define CHECK(c)                                                    \
    do {                                                            \
        if (!(c)) {                                                 \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);     \
            failures++;                                             \
        }                                                           \
    } while (0)

static size_t unhex(const char* s, uint8_t* out, size_t max) {
    size_t n = 0;
    while (s[0] && s[1] && n < max) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static void hex(const uint8_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static void vectors(void) {
    // FIPS-197 C.1
    uint8_t key[16], pt[16], ct[16], want[16];
    unhex("000102030405060708090a0b0c0d0e0f", key, 16);
    unhex("00112233445566778899aabbccddeeff", pt, 16);
    unhex("69c4e0d86a7b0430d8cdb78070b4c55a", want, 16);
    aes128_t aes;
    aes128_init(&aes, key);
    aes128_encrypt(&aes, pt, ct);
    CHECK(!memcmp(ct, want, 16));

    // RFC 7748 5.2
    uint8_t k[32], u[32], out[32], exp[32];
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k, 32);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32);
    unhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", exp, 32);
    x25519(out, k, u);
    CHECK(!memcmp(out, exp, 32));
    unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", k, 32);
    unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u, 32);
    unhex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", exp, 32);
    x25519(out, k, u);
    CHECK(!memcmp(out, exp, 32));

    // RFC 7748 6.1 (Diffie-Hellman)
    uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32], shared[32], s1[32], s2[32];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_priv, 32);
    unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", a_pub, 32);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b_priv, 32);
    unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", b_pub, 32);
    unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", shared, 32);
    x25519_base(out, a_priv);
    CHECK(!memcmp(out, a_pub, 32));
    x25519_base(out, b_priv);
    CHECK(!memcmp(out, b_pub, 32));
    x25519(s1, a_priv, b_pub);
    x25519(s2, b_priv, a_pub);
    CHECK(!memcmp(s1, shared, 32) && !memcmp(s2, shared, 32));

    // RFC 7748 5.2 iterated: 1 and 1000 iterations
    uint8_t kk[32] = {9}, uu[32] = {9}, tmp[32];
    for (int i = 1; i <= 1000; i++) {
        x25519(tmp, kk, uu);
        memcpy(uu, kk, 32);
        memcpy(kk, tmp, 32);
        if (i == 1) {
            unhex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", exp, 32);
            CHECK(!memcmp(kk, exp, 32));
        }
    }
    unhex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", exp, 32);
    CHECK(!memcmp(kk, exp, 32));

    // CCM: round trip, in place, tamper, short
    uint8_t nonce[13], iv[8] = {1, 2, 3, 4, 5, 6, 7, 8}, msg[40], buf[44], back[40];
    pulsar_nonce(0x7fffffffffull, 1, iv, nonce);
    CHECK(nonce[4] == 0xff && nonce[0] == 0xff && nonce[5] == 1);
    pulsar_nonce(5, 0, iv, nonce);
    CHECK(nonce[0] == 5 && nonce[4] == 0);
    for (int i = 0; i < 40; i++) msg[i] = (uint8_t)(i * 7);
    for (size_t len = 0; len <= 40; len++) {
        pulsar_ccm_encrypt(key, nonce, 0, msg, len, buf);
        CHECK(pulsar_ccm_decrypt(key, nonce, 0, buf, len + 4, back));
        CHECK(!memcmp(back, msg, len));
        memcpy(buf + 4, msg, len);  // in-place encrypt matches out-of-place
        uint8_t ref[44];
        pulsar_ccm_encrypt(key, nonce, 0, msg, len, ref);
        pulsar_ccm_encrypt(key, nonce, 0, buf + 4, len, buf + 4);
        CHECK(!memcmp(ref, buf + 4, len + 4));
        ref[len / 2] ^= 0x10;
        CHECK(!pulsar_ccm_decrypt(key, nonce, 0, ref, len + 4, back));
    }
    CHECK(!pulsar_ccm_decrypt(key, nonce, 0, buf, 3, back));
}

int main(int argc, char** argv) {
    char line[1024];
    if (argc == 2 && !strcmp(argv[1], "ccm")) {
        // "key nonce aad plaintext" -> "ciphertext||mic"
        while (fgets(line, sizeof line, stdin)) {
            char ks[64], ns[64], as[8], ps[600] = "";
            if (sscanf(line, "%63s %63s %7s %599s", ks, ns, as, ps) < 3) continue;
            uint8_t key[16], nonce[13], aad, pt[300], ct[304];
            unhex(ks, key, 16);
            unhex(ns, nonce, 13);
            unhex(as, &aad, 1);
            size_t n = !strcmp(ps, "-") ? 0 : unhex(ps, pt, sizeof pt);
            pulsar_ccm_encrypt(key, nonce, aad, pt, n, ct);
            hex(ct, n + 4);
            printf("\n");
        }
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "x25519")) {
        // "scalar point" -> "result"
        while (fgets(line, sizeof line, stdin)) {
            char ss[80], ps[80];
            if (sscanf(line, "%79s %79s", ss, ps) != 2) continue;
            uint8_t s[32], p[32], o[32];
            unhex(ss, s, 32);
            unhex(ps, p, 32);
            x25519(o, s, p);
            hex(o, 32);
            printf("\n");
        }
        return 0;
    }
    vectors();
    if (failures) return 1;
    printf("crypto: FIPS-197, RFC 7748 (5.2, 6.1, 1000 iterations), CCM round-trip/tamper ok\n");
    return 0;
}
