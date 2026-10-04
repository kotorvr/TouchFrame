// The contract between the portable link logic (host_core.c, ctrl_core.c) and whatever executes
// radio operations: the nRF52840 RADIO (radio_engine.c) or the PC simulator (test/sim.c).
//
// A core hands out one radio_op_t at a time (next_op), gets every received packet (on_rx) and is
// told when the op finished (on_done). On the dongle, next_op / on_rx / on_done run in interrupt
// context and must be quick; heavy work (crypto, events to the PC) happens in the core's poll(),
// called from the main loop. A core that has nothing to do returns false from next_op and calls
// platform_t.kick when that changes.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum radio_profile {
    RADIO_PROFILE_CONNECTED = 0,  // S0 = 1 byte (0x04 on air), LENGTH 8 bits (PROTOCOL Q1)
    RADIO_PROFILE_DM = 1,         // no S0: discovery, pairing link, DM beacons
};

enum radio_op_kind { RADIO_OP_TX = 1, RADIO_OP_RX = 2 };

// Every link uses Nrf_2Mbit, 8-bit preamble, BALEN 4 big-endian, CRC-24 0x108421/0xFFFFFF over
// the address, whitening off. Logical address n uses base0 for n = 0 and base1 for n = 1..7.
typedef struct {
    uint8_t profile;     // radio_profile
    uint8_t freq;        // MHz above 2400
    uint32_t base0, base1;
    uint8_t prefix[8];
    uint8_t rx_mask;     // RX: logical addresses to listen on
    uint8_t tx_addr;     // TX: logical address to send with
} radio_addr_t;

typedef struct {
    uint8_t kind;        // radio_op_kind
    uint64_t start_us;   // TX: when the ADDRESS event happens (the anchor the peer timestamps);
                         // RX: when to start listening
    uint32_t window_us;  // RX: stop listening this long after start_us (a packet in flight completes)
    bool rx_multi;       // RX: keep listening after a packet until the window closes (else done at the first)
    radio_addr_t addr;
    uint8_t len;         // TX: payload length (S0 and LENGTH are added by the radio)
    uint8_t payload[255];
} radio_op_t;

typedef struct {
    uint64_t t_us;       // ADDRESS event time
    uint8_t freq;
    uint8_t profile;
    uint8_t rxmatch;     // logical address that matched
    int8_t rssi;
    bool crc_ok;
    uint8_t len;
    const uint8_t* payload;
} radio_rx_t;

// Per-instance services. The simulator runs a host and a fake controller in one process, so
// everything a core needs from "the platform" comes through this struct.
typedef struct platform {
    uint64_t (*now_us)(struct platform* p);
    void (*random)(struct platform* p, uint8_t* out, size_t n);
    // AES-CCM for link packets (PROTOCOL Q3 profile): the CCM peripheral on the dongle, software in
    // tests. encrypt: out = in || MIC (len + 4); decrypt: in includes the MIC, false if it fails.
    bool (*ccm)(struct platform* p, bool encrypt, const uint8_t key[16], const uint8_t nonce[13],
                const uint8_t* in, uint8_t len, uint8_t* out);
    // An event for the PC (link.h EVT_*). body and tail are concatenated.
    void (*emit)(struct platform* p, uint8_t evt, const void* body, size_t len, const void* tail, size_t tail_len);
    void (*kick)(struct platform* p);  // a core has a new radio op ready
    // Stop the radio engine now: no op running, no core callback until the next kick. The main
    // loop calls it before changing state the ISR reads (identity, pairing <-> beacons).
    void (*radio_halt)(struct platform* p);
    uint64_t device_id;                // FICR DEVICEID
    void* user;
} platform_t;
