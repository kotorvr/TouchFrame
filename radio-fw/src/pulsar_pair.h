// Pulsar pairing (docs/PROTOCOL.md Q1 discovery advert, Q2 pairing exchange): the byte formats,
// mirroring tools/pulsar_host.py. Pure C, tested on the PC against that tool.
//
// Pairing-link frames are the radio payload [cmd][seq][data...] on 2426 MHz (S0 off; LENGTH and
// the CRC-24 are the radio's). INFERRED: how the host opens this link (we just start polling the
// controller's DM address after its advert, MASTER-PLAN 3.1.9) and the reply's command byte
// (UNKNOWN, AUDIT A5: we accept any reply with our seq and the same command number).
#pragma once
#include <stdbool.h>
#include <stdint.h>

// On-air command byte = (number << 1) | read (docs/re/AUDIT.md A5; SPL dispatcher FUN_0000822c).
#define PAIR_CMD_PAIRING_DATA 0x22   // write #0x11: [8-byte IV][CCM(20)+MIC] = 32 bytes
#define PAIR_CMD_SETUP_X25519 0x25   // read #0x12: carries our 32-byte public key; the reply has the controller's
#define PAIR_CMD_NUM(b) (((b) & 0x7F) >> 1)
#define PAIR_DATA_LEN 32
#define PAIR_ADVERT_LEN 32
#define PAIR_MAX_MISSES 666          // syncboss FUN_00020a70 gives up after 0x29a misses
#define PAIR_POLL_US 2000            // host TX every 2 ms, reply window up to 2000 us after (FUN_0001be1c)

typedef struct {
    uint8_t type;            // [0]: 2 (or 1, older layout)
    uint16_t pulsar_version; // [1..2]
    uint16_t hw;             // [3..4]
    uint64_t device_id;      // [5..12] (type 2) / [6..13] (type 1)
} pair_advert_t;

bool pair_advert_parse(const uint8_t* p, uint8_t len, pair_advert_t* a);
// A type-2 advert like the controller SPL sends (unknown trailing words zero). Returns its length.
uint8_t pair_advert_build(uint64_t device_id, uint16_t hw, uint8_t out[PAIR_ADVERT_LEN]);

// 0x11 payload: plaintext = [netaddr, 4 bytes LE (the BASE register value)][16-byte link key],
// CCM key = shared_secret[0..15], nonce = counter 0, direction 0, the random IV (sent in clear).
void pair_data_build(const uint8_t shared[32], uint32_t netaddr, const uint8_t link_key[16], const uint8_t iv[8],
                     uint8_t out[PAIR_DATA_LEN]);
bool pair_data_parse(const uint8_t shared[32], const uint8_t in[PAIR_DATA_LEN], uint32_t* netaddr,
                     uint8_t link_key[16]);

// Pairing-link frame: [cmd][seq][data]; returns its length.
uint8_t pair_frame(uint8_t cmd, uint8_t seq, const uint8_t* data, uint8_t len, uint8_t* out);
