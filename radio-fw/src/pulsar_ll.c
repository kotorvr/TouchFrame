#include "pulsar_ll.h"

#include <string.h>

// elk-app table 0x32504 (FUN_00028ad0 +0x15e)
static const uint16_t kSlotOffset[PULSAR_SLOTS] = {0, 225, 525, 825, 1125};

uint32_t pulsar_slot_offset_us(uint8_t slot) {
    return PULSAR_SLOT_BASE_US + kSlotOffset[slot < PULSAR_SLOTS ? slot : 0];
}

uint8_t pulsar_beacon_build(const pulsar_beacon_t* b, uint8_t* p) {
    uint64_t m = b->map & ((1ull << PULSAR_NUM_CHANNELS) - 1);
    p[0] = (uint8_t)((m & 0x1F) << 3 | (uint64_t)(b->dm_in & 3u) << 1);
    p[1] = (uint8_t)(m >> 5);
    p[2] = (uint8_t)(m >> 13);
    p[3] = (uint8_t)(m >> 21);
    p[4] = (uint8_t)(m >> 29);
    p[5] = b->unmapped;
    p[6] = (uint8_t)b->session_nonce;
    p[7] = (uint8_t)(b->session_nonce >> 8);
    for (int i = 0; i < 6; i++) p[8 + i] = (uint8_t)(b->timestamp_us >> (8 * i));
    p[14] = b->cl_slot_mask;
    p[15] = b->ack_mask;
    return PULSAR_BEACON_HDR_LEN;
}

bool pulsar_beacon_parse(const uint8_t* p, uint8_t len, pulsar_beacon_t* b) {
    if (len < PULSAR_BEACON_HDR_LEN) return false;
    if (!pulsar_parse_beacon(p, len, &b->map, &b->unmapped)) return false;
    b->dm_in = (uint8_t)((p[0] >> 1) & 3);
    b->session_nonce = (uint16_t)(p[6] | p[7] << 8);
    b->timestamp_us = 0;
    for (int i = 0; i < 6; i++) b->timestamp_us |= (uint64_t)p[8 + i] << (8 * i);
    b->cl_slot_mask = p[14];
    b->ack_mask = p[15];
    return true;
}

static uint16_t xorshift16(uint16_t x) {
    x ^= (uint16_t)(x << 7);
    x ^= (uint16_t)(x >> 9);
    x ^= (uint16_t)(x << 8);
    return x;
}

void pulsar_dm_init(pulsar_dm_t* dm, uint32_t netaddr) {
    dm->rng = (uint16_t)netaddr ? (uint16_t)netaddr : 1;  // xorshift must not start at 0
    dm->rng = xorshift16(dm->rng);
    dm->countdown = (uint8_t)(dm->rng % 20 + 5);
}

bool pulsar_dm_next(pulsar_dm_t* dm, uint8_t* announce) {
    if (dm->countdown == 0) {
        dm->rng = xorshift16(dm->rng);
        dm->countdown = (uint8_t)(dm->rng % 20 + 5);
        *announce = 0;
        return true;
    }
    dm->countdown--;
    // byte 0 bits 1..2 can only say 1..3 periods ahead; further out reads as "none"
    *announce = dm->countdown + 1 <= 3 ? (uint8_t)(dm->countdown + 1) : 0;
    return false;
}
