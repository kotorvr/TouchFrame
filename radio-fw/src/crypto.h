// Portable crypto for the Pulsar host: AES-128 (software), the Pulsar AES-CCM profile, X25519.
// No hardware access, so all of it is unit-tested on the PC (radio-fw/test/crypto_test.c) against
// the RFC/FIPS vectors and tools/pulsar_crypto.py. On the dongle, per-packet link crypto runs in
// the CCM peripheral (ccm_hw.c); this software CCM does the one-off pairing wrap and checks the
// peripheral in the self-test.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ---- AES-128, encrypt direction only (all CCM needs)
typedef struct {
    uint8_t rk[176];  // expanded key
} aes128_t;

void aes128_init(aes128_t* ctx, const uint8_t key[16]);
void aes128_encrypt(const aes128_t* ctx, const uint8_t in[16], uint8_t out[16]);

// ---- Pulsar AES-CCM (docs/PROTOCOL.md Q3): RFC 3610 with L = 2, a 4-byte MIC, and one byte of
// associated data. The nRF CCM peripheral uses the packet header byte masked with 0xE3 as that
// byte; Pulsar's header is 0 (pairing) or S0 = 0x04 (connected), so the AAD is always 0x00.
#define PULSAR_MIC_LEN 4
#define PULSAR_NONCE_LEN 13

// 13-byte nonce in the nRF hardware-CCM layout: 39-bit packet counter LE, direction in bit 39,
// then the 8-byte IV (tools/pulsar_crypto.py nonce_from_fields).
void pulsar_nonce(uint64_t counter, uint8_t direction, const uint8_t iv[8], uint8_t nonce[PULSAR_NONCE_LEN]);

// out = ciphertext || MIC (len + 4 bytes). in and out may be the same buffer.
void pulsar_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[PULSAR_NONCE_LEN], uint8_t aad,
                        const uint8_t* in, size_t len, uint8_t* out);
// in = ciphertext || MIC (len >= 4); writes len - 4 plaintext bytes. False if the MIC is wrong
// (out is then zeroed).
bool pulsar_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[PULSAR_NONCE_LEN], uint8_t aad,
                        const uint8_t* in, size_t len, uint8_t* out);

// ---- X25519 (RFC 7748). Slow but small: roughly 70 ms per call on the nRF52840.
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);
