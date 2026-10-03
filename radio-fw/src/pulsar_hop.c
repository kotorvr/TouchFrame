#include "pulsar_hop.h"

// syncboss table at 0x4fe70 (FUN_0001ac24): 2404-2478 MHz in 2 MHz steps, skipping 2426.
static const uint8_t kChannelMhz[PULSAR_NUM_CHANNELS] = {
    4,  6,  8,  10, 12, 14, 16, 18, 20, 22, 24, 28, 30, 32, 34, 36, 38, 40, 42,
    44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78};

uint8_t pulsar_channel_mhz(uint8_t logical) {
    return kChannelMhz[logical < PULSAR_NUM_CHANNELS ? logical : 0];
}

uint8_t pulsar_hop_increment(uint32_t netaddr) { return (uint8_t)((netaddr & 0xFF) % 11 + 5); }

uint8_t pulsar_remap(uint64_t map, uint8_t unmapped) {
    if (map & (1ull << unmapped)) return unmapped;
    uint8_t used[PULSAR_NUM_CHANNELS], n = 0;
    for (uint8_t i = 0; i < PULSAR_NUM_CHANNELS; i++)
        if (map & (1ull << i)) used[n++] = i;
    return n ? used[unmapped % n] : unmapped;
}

uint8_t pulsar_hop_next(pulsar_hop_t* h) {
    h->unmapped = (uint8_t)((h->unmapped + h->hop) % PULSAR_NUM_CHANNELS);
    return pulsar_remap(h->map, h->unmapped);
}

bool pulsar_parse_beacon(const uint8_t* p, uint8_t len, uint64_t* map, uint8_t* unmapped) {
    if (len < 6) return false;
    // byte 0 bits 3..7 = map bits 0..4; bytes 1..4 = map bits 5..36
    uint64_t m = (uint64_t)(p[0] >> 3) | (uint64_t)p[1] << 5 | (uint64_t)p[2] << 13 | (uint64_t)p[3] << 21 |
                 (uint64_t)p[4] << 29;
    m &= (1ull << PULSAR_NUM_CHANNELS) - 1;
    if (p[5] >= PULSAR_NUM_CHANNELS) return false;
    int count = 0;
    for (int i = 0; i < PULSAR_NUM_CHANNELS; i++) count += (int)((m >> i) & 1);
    if (count < 8) return false;
    *map = m;
    *unmapped = p[5];
    return true;
}
