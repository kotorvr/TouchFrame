#include "pulsar_pair.h"

#include <string.h>

#include "crypto.h"
#include "pulsar_ll.h"

static uint64_t get64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

bool pair_advert_parse(const uint8_t* p, uint8_t len, pair_advert_t* a) {
    if (len < 14 || (p[0] != 1 && p[0] != 2)) return false;
    a->type = p[0];
    a->pulsar_version = (uint16_t)(p[1] | p[2] << 8);
    a->hw = (uint16_t)(p[3] | p[4] << 8);
    a->device_id = get64(p + (p[0] == 2 ? 5 : 6));
    return true;
}

uint8_t pair_advert_build(uint64_t device_id, uint16_t hw, uint8_t out[PAIR_ADVERT_LEN]) {
    memset(out, 0, PAIR_ADVERT_LEN);
    out[0] = 2;
    out[1] = (uint8_t)PULSAR_VERSION;
    out[2] = (uint8_t)(PULSAR_VERSION >> 8);
    out[3] = (uint8_t)hw;
    out[4] = (uint8_t)(hw >> 8);
    for (int i = 0; i < 8; i++) out[5 + i] = (uint8_t)(device_id >> (8 * i));
    return PAIR_ADVERT_LEN;
}

void pair_data_build(const uint8_t shared[32], uint32_t netaddr, const uint8_t link_key[16], const uint8_t iv[8],
                     uint8_t out[PAIR_DATA_LEN]) {
    uint8_t pt[20], nonce[PULSAR_NONCE_LEN];
    for (int i = 0; i < 4; i++) pt[i] = (uint8_t)(netaddr >> (8 * i));
    memcpy(pt + 4, link_key, 16);
    pulsar_nonce(0, 0, iv, nonce);
    memcpy(out, iv, 8);
    pulsar_ccm_encrypt(shared, nonce, 0, pt, sizeof pt, out + 8);  // wrap key = shared[0..15]
    memset(pt, 0, sizeof pt);
}

bool pair_data_parse(const uint8_t shared[32], const uint8_t in[PAIR_DATA_LEN], uint32_t* netaddr,
                     uint8_t link_key[16]) {
    uint8_t pt[20], nonce[PULSAR_NONCE_LEN];
    pulsar_nonce(0, 0, in, nonce);
    if (!pulsar_ccm_decrypt(shared, nonce, 0, in + 8, PAIR_DATA_LEN - 8, pt)) return false;
    *netaddr = (uint32_t)pt[0] | (uint32_t)pt[1] << 8 | (uint32_t)pt[2] << 16 | (uint32_t)pt[3] << 24;
    memcpy(link_key, pt + 4, 16);
    memset(pt, 0, sizeof pt);
    return true;
}

uint8_t pair_frame(uint8_t cmd, uint8_t seq, const uint8_t* data, uint8_t len, uint8_t* out) {
    out[0] = cmd;
    out[1] = seq;
    if (len) memcpy(out + 2, data, len);
    return (uint8_t)(2 + len);
}
