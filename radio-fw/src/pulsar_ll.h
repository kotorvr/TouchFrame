// Pulsar link layer, the parts docs/PROTOCOL.md Q1 pins: beacon layout, DM-beacon schedule, slot
// timing, addresses. Pure C, no hardware access (tested on the PC: radio-fw/test/ll_test.c).
#pragma once
#include <stdbool.h>
#include <stdint.h>

#include "pulsar_hop.h"

#define PULSAR_BEACON_PERIOD_US 2000
#define PULSAR_BEACON_HDR_LEN 16       // bytes 0..15; CL data follows
#define PULSAR_BEACON_CL_MAX 34        // CL_HOST_MAX_PAYLOAD_LEN
#define PULSAR_BEACON_MAX_LEN 50       // "Beacon length too large" (<= 0x32)
#define PULSAR_UPLINK_MAX_LEN 126      // LL_DEV_MAX_PAYLOAD_LEN
#define PULSAR_SLOTS 5

// Beacon byte 14 (whose downlink rides this beacon) and byte 15 (ack bitmap) are indexed by CL
// endpoint, 1 << endpoint, endpoints 1..4 (docs/re/LINK.md §4, CONFIRMED). Radio slots are 0..4
// (TX prefix slot + 1). Which endpoint a slot has is INFERRED: endpoint = slot + this offset (1:
// endpoints start at TRANSPORT_ENDPOINT_START = 1). One capture settles it; rebuild with -D to try 0.
#ifndef PULSAR_ENDPOINT_OFFSET
#define PULSAR_ENDPOINT_OFFSET 1
#endif
#define PULSAR_SLOT_BIT(slot) ((uint8_t)(1u << ((slot) + PULSAR_ENDPOINT_OFFSET)))
#define PULSAR_SLOT_BASE_US 350        // first uplink slot starts this long after the beacon anchor
#define PULSAR_VERSION 0x1701          // Q6: on air 01 17
#define PULSAR_S0 0x04                 // connected-link S0 byte

// Frequencies (MHz above 2400) and addresses
#define PULSAR_DISCOVERY_MHZ 2         // adverts + DM beacons
#define PULSAR_PAIRING_MHZ 26          // DM (pairing) link
#define PULSAR_DISCOVERY_BASE 0xFACEB00Cu
#define PULSAR_DISCOVERY_PREFIX 0xAA   // adverts, and the pairing link (base = device id low word)
#define PULSAR_HOST_PREFIX 0xF0        // host beacons / downlink on the connected link
// device in slot s transmits with prefix s + 1 (0x01..0x05)

// Slot s uplink starts at anchor + pulsar_slot_offset_us(s) (350 + {0, 225, 525, 825, 1125}).
uint32_t pulsar_slot_offset_us(uint8_t slot);

typedef struct {
    uint64_t map;            // 37-bit channel map
    uint8_t unmapped;        // this beacon's unmapped channel (byte 5)
    uint8_t dm_in;           // periods until the DM beacon, 0 = none announced (byte 0 bits 1..2)
    uint16_t session_nonce;  // bytes 6..7
    uint64_t timestamp_us;   // bytes 8..13, 48-bit sync-clock time of this beacon
    uint8_t cl_slot_mask;    // byte 14: 1 << slot addressed by the CL data (INFERRED meaning)
    uint8_t ack_mask;        // byte 15: slots heard since the last beacon
} pulsar_beacon_t;

// Builds the 16-byte header into out[0..15]; returns 16. CL data, if any, goes after it.
uint8_t pulsar_beacon_build(const pulsar_beacon_t* b, uint8_t* out);
// Parses a beacon payload; false if shorter than the header, the map has < 8 channels, or
// unmapped is out of range (what the controller rejects too).
bool pulsar_beacon_parse(const uint8_t* payload, uint8_t len, pulsar_beacon_t* b);

// DM-beacon schedule (INFERRED, PROTOCOL Q1: xorshift16 seeded with netaddr & 0xFFFF, the next DM
// beacon (r % 20) + 5 periods later). Call pulsar_dm_next once per beacon period: it returns true
// when this period is a DM period, and sets *announce to the byte-0 countdown for this beacon.
typedef struct {
    uint16_t rng;
    uint8_t countdown;  // periods until the next DM period
} pulsar_dm_t;

void pulsar_dm_init(pulsar_dm_t* dm, uint32_t netaddr);
bool pulsar_dm_next(pulsar_dm_t* dm, uint8_t* announce);

// Connected-link CCM nonces (docs/re/AUDIT.md A2/A3; PROTOCOL Q3). CCM runs on UPLINK ONLY (A4):
// beacons and downlink CL data are plaintext. Direction bit always 0 (A17).
// Legacy / negotiation nonce: packet counter 0, IV = session_nonce << 48 | beacon_ts48 (u64 LE), the
// timestamp of the beacon that starts the period the uplink is sent in. Used until the accept.
void pulsar_nonce_legacy(uint16_t session_nonce, uint64_t beacon_ts, uint8_t nonce[13]);
// Steady state: per-slot u32 counter (0 after the accept) and the 8-byte IV the controller sent in
// its connection request.
void pulsar_nonce_steady(uint32_t counter, const uint8_t iv[8], uint8_t nonce[13]);
// The CCM direction bit (nonce bit 39). AUDIT A17: never written, so 0; tools/pulsar_host.py's
// steady_state_nonce defaults to 1. The host learns it per controller from the first request.
static inline void pulsar_nonce_dir(uint8_t nonce[13], uint8_t dir) {
    nonce[4] = (uint8_t)((nonce[4] & 0x7F) | (dir ? 0x80 : 0));
}

// Airtime of a Nrf_2Mbit packet: 1 preamble + 5 address + s0 + 1 LENGTH + payload + 3 CRC bytes.
static inline uint32_t pulsar_airtime_us(uint8_t s0len, uint8_t payload_len) {
    return (uint32_t)(1 + 5 + s0len + 1 + payload_len + 3) * 4u;
}
