// Pulsar connected-link hopping (docs/PROTOCOL.md Q1): BLE channel selection algorithm #1 over
// 37 logical channels. Pure C, no hardware access, so it is unit-tested on the PC
// (radio-fw/test/hop_test.c).
#pragma once
#include <stdbool.h>
#include <stdint.h>

#define PULSAR_NUM_CHANNELS 37

typedef struct {
    uint64_t map;      // bit i = logical channel i enabled (37 bits)
    uint8_t unmapped;  // current unmapped channel, 0..36
    uint8_t hop;       // (netaddr & 0xFF) % 11 + 5
} pulsar_hop_t;

// nRF FREQUENCY (MHz above 2400) of logical channel 0..36.
uint8_t pulsar_channel_mhz(uint8_t logical);

uint8_t pulsar_hop_increment(uint32_t netaddr);

// The logical channel actually used for `unmapped` under `map`.
uint8_t pulsar_remap(uint64_t map, uint8_t unmapped);

// Advance one beacon period; returns the new logical channel.
uint8_t pulsar_hop_next(pulsar_hop_t* h);

// Parse a beacon payload (after S0 and LENGTH). Fills map/unmapped; false if too short or the map
// has fewer than 8 channels (the firmware rejects those too).
bool pulsar_parse_beacon(const uint8_t* payload, uint8_t len, uint64_t* map, uint8_t* unmapped);
