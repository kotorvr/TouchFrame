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

// One number S per controller (docs/re/REVIEW-RE.md R1/R4, CONFIRMED on both sides): the accept's
// [11], TX prefix S + 1, beacon byte 14 (whose downlink rides this beacon) and byte 15 (ack bitmap)
// bit 1 << S, and uplink CL[0]. S is 1..4: slot 0 (prefix 1) is the negotiation slot a seeking
// controller requests in, and an accept with [11] = 0 trips a fatal assert in the controller.
#define PULSAR_SLOT_BIT(slot) ((uint8_t)(1u << (slot)))
// Slots the host assigns: 1..4.
#define PULSAR_SLOT_USABLE(slot) ((slot) >= 1 && (slot) <= 4)
#define PULSAR_NEG_SLOT 0              // CONN_NEG_SLOT: requests and the accept that answers them
#define PULSAR_SLOT_BASE_US 350        // first uplink slot starts this long after the beacon anchor
#define PULSAR_VERSION 0x1701          // Q6: on air 01 17
#define PULSAR_S0 0x04                 // connected-link S0 byte

// Frequencies (MHz above 2400) and addresses
#define PULSAR_DISCOVERY_MHZ 2         // adverts + DM beacons
#define PULSAR_PAIRING_MHZ 26          // DM (pairing) link
#define PULSAR_DISCOVERY_BASE 0xFACEB00Cu
#define PULSAR_DISCOVERY_PREFIX 0xAA   // adverts, and the pairing link (base = device id low word)
#define PULSAR_HOST_PREFIX 0xF0        // host beacons / downlink on the connected link
// A seeking controller listens 75.25 ms on each of these logical channels in turn (REVIEW-RE R10):
// the host's channel map must contain all three.
#define PULSAR_SEEK_CHANNELS {0, 17, 36}
#define PULSAR_SEEK_MAP ((1ull << 0) | (1ull << 17) | (1ull << 36))
#define PULSAR_SEEK_DWELL_US 75250
#define PULSAR_MISSED_BEACONS_DC 25    // PULSAR_DEVICE_MISSED_BEACONS_BEFORE_DC (R9): > 24 missed -> seek
// device in slot s transmits with prefix s + 1 (0x01..0x05)

// Slot s uplink starts at anchor + pulsar_slot_offset_us(s) (350 + {0, 225, 525, 825, 1125}).
uint32_t pulsar_slot_offset_us(uint8_t slot);

typedef struct {
    uint64_t map;            // 37-bit channel map
    uint8_t unmapped;        // this beacon's unmapped channel (byte 5)
    uint8_t dm_in;           // periods until the DM beacon, 0 = none announced (byte 0 bits 1..2)
    uint16_t session_nonce;  // bytes 6..7
    uint64_t timestamp_us;   // bytes 8..13, 48-bit sync-clock time of this beacon
    uint8_t cl_slot_mask;    // byte 14: 1 << S of the controller the CL data is for (0 = broadcast)
    uint8_t ack_mask;        // byte 15: 1 << S for each slot heard since the last beacon
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
// Steady state: per-slot u32 counter and the 8-byte IV the controller sent in its connection
// request. The counter is 0 at the accept and advances once per beacon period, skipped periods
// included, whether or not the period carried an uplink (REVIEW-RE R7). Which period counts as 0 is
// a live-capture item, so the host searches around its prediction.
void pulsar_nonce_steady(uint32_t counter, const uint8_t iv[8], uint8_t nonce[13]);
// The CCM direction bit (nonce bit 39). Always 0 on the uplink (REVIEW-RE R8, AUDIT A17). The host
// still learns it per controller from the first request, in case a capture says otherwise.
static inline void pulsar_nonce_dir(uint8_t nonce[13], uint8_t dir) {
    nonce[4] = (uint8_t)((nonce[4] & 0x7F) | (dir ? 0x80 : 0));
}

// Airtime of a Nrf_2Mbit packet: 1 preamble + 5 address + s0 + 1 LENGTH + payload + 3 CRC bytes.
static inline uint32_t pulsar_airtime_us(uint8_t s0len, uint8_t payload_len) {
    return (uint32_t)(1 + 5 + s0len + 1 + payload_len + 3) * 4u;
}
