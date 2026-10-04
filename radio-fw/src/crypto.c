// AES-128 (FIPS-197, encrypt only), Pulsar AES-CCM (RFC 3610, L=2, M=4) and X25519 (RFC 7748).
// The X25519 field arithmetic follows TweetNaCl (Bernstein et al., public domain), with the
// undefined left shift of a negative carry replaced by a multiply.
#include "crypto.h"

#include <string.h>

//------------------------------------------------------------------ AES-128

static const uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

void aes128_init(aes128_t* ctx, const uint8_t key[16]) {
    uint8_t* w = ctx->rk;
    memcpy(w, key, 16);
    uint8_t rcon = 1;
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4] = {w[i - 4], w[i - 3], w[i - 2], w[i - 1]};
        if (i % 16 == 0) {
            uint8_t u = t[0];
            t[0] = (uint8_t)(kSbox[t[1]] ^ rcon);
            t[1] = kSbox[t[2]];
            t[2] = kSbox[t[3]];
            t[3] = kSbox[u];
            rcon = xtime(rcon);
        }
        for (int k = 0; k < 4; k++) w[i + k] = (uint8_t)(w[i - 16 + k] ^ t[k]);
    }
}

void aes128_encrypt(const aes128_t* ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ ctx->rk[i];
    for (int round = 1; round <= 10; round++) {
        uint8_t t[16];
        for (int i = 0; i < 16; i++) t[i] = kSbox[s[(i + 4 * (i % 4)) % 16]];  // SubBytes + ShiftRows
        if (round < 10) {
            for (int c = 0; c < 4; c++) {  // MixColumns
                uint8_t* col = &t[4 * c];
                uint8_t a = col[0], b = col[1], d = col[2], e = col[3], all = (uint8_t)(a ^ b ^ d ^ e);
                col[0] ^= (uint8_t)(all ^ xtime((uint8_t)(a ^ b)));
                col[1] ^= (uint8_t)(all ^ xtime((uint8_t)(b ^ d)));
                col[2] ^= (uint8_t)(all ^ xtime((uint8_t)(d ^ e)));
                col[3] ^= (uint8_t)(all ^ xtime((uint8_t)(e ^ a)));
            }
        }
        for (int i = 0; i < 16; i++) s[i] = t[i] ^ ctx->rk[16 * round + i];
    }
    memcpy(out, s, 16);
}

//------------------------------------------------------------------ Pulsar CCM

void pulsar_nonce(uint64_t counter, uint8_t direction, const uint8_t iv[8], uint8_t nonce[PULSAR_NONCE_LEN]) {
    uint64_t pc = (counter & ((1ull << 39) - 1)) | ((uint64_t)(direction & 1) << 39);
    for (int i = 0; i < 5; i++) nonce[i] = (uint8_t)(pc >> (8 * i));
    memcpy(nonce + 5, iv, 8);
}

// A_i / B_0 blocks: flags | nonce | 2-byte big-endian counter or length
static void ccm_block(uint8_t blk[16], uint8_t flags, const uint8_t nonce[13], uint16_t v) {
    blk[0] = flags;
    memcpy(blk + 1, nonce, 13);
    blk[14] = (uint8_t)(v >> 8);
    blk[15] = (uint8_t)v;
}

static void ccm_mac(const aes128_t* aes, const uint8_t nonce[13], uint8_t aad, const uint8_t* pt, size_t len,
                    uint8_t mac[16]) {
    uint8_t blk[16];
    ccm_block(blk, (uint8_t)(0x40 | ((PULSAR_MIC_LEN - 2) / 2) << 3 | 1), nonce, (uint16_t)len);  // Adata, M=4, L=2
    aes128_encrypt(aes, blk, mac);
    uint8_t a[16] = {0, 1, aad};  // 2-byte AAD length, the AAD byte, zero pad
    for (int i = 0; i < 16; i++) mac[i] ^= a[i];
    aes128_encrypt(aes, mac, mac);
    for (size_t off = 0; off < len; off += 16) {
        size_t n = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < n; i++) mac[i] ^= pt[off + i];
        aes128_encrypt(aes, mac, mac);
    }
}

static void ccm_ctr(const aes128_t* aes, const uint8_t nonce[13], const uint8_t* in, size_t len, uint8_t* out) {
    uint8_t blk[16], ks[16];
    for (size_t off = 0; off < len; off += 16) {
        ccm_block(blk, 1, nonce, (uint16_t)(off / 16 + 1));
        aes128_encrypt(aes, blk, ks);
        size_t n = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
    }
}

static void ccm_tag(const aes128_t* aes, const uint8_t nonce[13], const uint8_t mac[16], uint8_t tag[4]) {
    uint8_t blk[16], s0[16];
    ccm_block(blk, 1, nonce, 0);
    aes128_encrypt(aes, blk, s0);
    for (int i = 0; i < PULSAR_MIC_LEN; i++) tag[i] = mac[i] ^ s0[i];
}

void pulsar_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[13], uint8_t aad, const uint8_t* in,
                        size_t len, uint8_t* out) {
    aes128_t aes;
    aes128_init(&aes, key);
    uint8_t mac[16];
    ccm_mac(&aes, nonce, aad, in, len, mac);  // before ccm_ctr: in may alias out
    ccm_ctr(&aes, nonce, in, len, out);
    ccm_tag(&aes, nonce, mac, out + len);
}

bool pulsar_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13], uint8_t aad, const uint8_t* in,
                        size_t len, uint8_t* out) {
    if (len < PULSAR_MIC_LEN) return false;
    size_t n = len - PULSAR_MIC_LEN;
    uint8_t got[PULSAR_MIC_LEN], want[PULSAR_MIC_LEN], mac[16];
    memcpy(got, in + n, PULSAR_MIC_LEN);
    aes128_t aes;
    aes128_init(&aes, key);
    ccm_ctr(&aes, nonce, in, n, out);
    ccm_mac(&aes, nonce, aad, out, n, mac);
    ccm_tag(&aes, nonce, mac, want);
    uint8_t diff = 0;
    for (int i = 0; i < PULSAR_MIC_LEN; i++) diff |= (uint8_t)(got[i] ^ want[i]);
    if (diff) memset(out, 0, n);
    return diff == 0;
}

//------------------------------------------------------------------ X25519 (TweetNaCl field code)

typedef int64_t gf[16];
static const gf k121665 = {0xDB41, 1};

static void car25519(gf o) {
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;  // arithmetic shift (gcc/clang on every target we build for)
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * 65536;
    }
}

static void sel25519(gf p, gf q, int64_t b) {
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t o[32], const gf n) {
    gf m, t;
    memcpy(t, n, sizeof(gf));
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)t[i];
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t n[32]) {
    for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void fadd(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void fsub(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void fmul(gf o, const gf a, const gf b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    memcpy(o, t, sizeof(gf));
    car25519(o);
    car25519(o);
}

static void finv(gf o, const gf in) {
    gf c;
    memcpy(c, in, sizeof(gf));
    for (int a = 253; a >= 0; a--) {
        fmul(c, c, c);
        if (a != 2 && a != 4) fmul(c, c, in);
    }
    memcpy(o, c, sizeof(gf));
}

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t z[32];
    gf x, a, b, c, d, e, f;
    memcpy(z, scalar, 32);
    z[31] = (uint8_t)((z[31] & 127) | 64);
    z[0] &= 248;
    unpack25519(x, point);
    memcpy(b, x, sizeof(gf));
    memset(a, 0, sizeof(gf));
    memset(c, 0, sizeof(gf));
    memset(d, 0, sizeof(gf));
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        int64_t r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        fadd(e, a, c);
        fsub(a, a, c);
        fadd(c, b, d);
        fsub(b, b, d);
        fmul(d, e, e);
        fmul(f, a, a);
        fmul(a, c, a);
        fmul(c, b, e);
        fadd(e, a, c);
        fsub(a, a, c);
        fmul(b, a, a);
        fsub(c, d, f);
        fmul(a, c, k121665);
        fadd(a, a, d);
        fmul(c, c, a);
        fmul(a, d, f);
        fmul(d, b, x);
        fmul(b, e, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    finv(c, c);
    fmul(a, a, c);
    pack25519(out, a);
    memset(z, 0, sizeof(z));
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    static const uint8_t nine[32] = {9};
    x25519(out, scalar, nine);
}
