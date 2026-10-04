// Pulsar host ("be the Quest"): beacon scheduler, uplink slots, pairing, connections, and the
// link-v3 host commands. Portable: radio work goes through radio_op.h, so the same code runs on
// the dongle (radio_engine.c) and in the PC simulator (test/sim.c).
//
// Threading on the dongle: host_next_op / host_on_rx / host_on_done run in the radio interrupt;
// host_poll and host_command run in the main loop. They share only the fields marked "ISR".
#pragma once
#include <stdbool.h>
#include <stdint.h>

#include "link.h"
#include "pulsar_cl.h"
#include "pulsar_hop.h"
#include "pulsar_ll.h"
#include "pulsar_pair.h"
#include "radio_op.h"
#include "store.h"

#define HOST_RX_RING 32       // power of two
#define HOST_DLQ 8            // downlink messages queued per slot
#define HOST_LOST_US 250000   // a connected slot with no uplink this long is LOST
#define HOST_DL_RETRY_PERIODS 3
#define HOST_DL_MAX_TRIES 60
#define HOST_CTR_NEAR 4       // steady counters tried from the next expected one on
#define HOST_CTR_BACK 4       // ... and back from where elapsed beacon periods put it (lost uplinks)
#define HOST_TX_LEAD_US 150   // a beacon is planned at least this long before it goes out
#define HOST_REAL_DL_REPEATS 4 // real formats: no CL ack is known, so each downlink goes out this often

typedef struct {
    uint64_t t_us;
    uint8_t freq, profile, rxmatch, len;
    int8_t rssi;
    bool crc_ok;
    uint8_t data[PULSAR_UPLINK_MAX_LEN + 4];
} host_rx_t;

typedef struct {
    cl_msg_t msg;
    uint8_t addr_slot;  // slot the beacon addresses (byte 14); differs from the queue's slot only
                        // for a CONN_ACCEPT answering a request made in another slot
} host_dl_t;

typedef struct {
    uint8_t state;           // link_slot_state
    bool allowed;            // named by CMD_CONNECT (or auto-accepted)
    bool accept_queued;
    uint64_t device_id;
    uint16_t version;
    int8_t rssi;
    uint32_t rx_packets, rx_bad_mic;
    uint64_t last_rx_us;
    uint16_t input_seq, imu_seq;
    uint8_t last_ul_seq;
    bool steady;             // steady-state CCM: iv + per-slot counter (after the accept was queued)
    uint64_t ctr_period;     // beacon period of the last steady-nonce uplink (or of the accept)
    uint32_t probe;          // sweeps the counters between "next" and "elapsed periods" after losses
    uint8_t iv[8];
    uint32_t ctr;            // next expected uplink counter
    host_dl_t dlq[HOST_DLQ];
    uint8_t dlq_head, dlq_len;
    uint8_t next_dl_seq;
    bool head_sent;
    uint64_t head_sent_period;
    uint8_t head_tries;
} host_slot_t;

typedef struct {
    // prepared CL data (plaintext) for one beacon: written by the main loop while !ready, consumed by the ISR
    volatile bool ready;
    uint64_t period;
    uint8_t slot;
    uint8_t len;
    uint8_t data[PULSAR_BEACON_CL_MAX];
} host_prepared_t;

typedef struct {
    platform_t* plat;
    store_t* store;  // flash identity + pairings (LINK_HOST_STORED); NULL = none. Set after host_init.
    const cl_format_t* fmt;
    bool running;
    uint8_t flags;  // LINK_HOST_*
    uint32_t netaddr;
    uint8_t key[16];
    uint16_t session_nonce;
    uint8_t ccm_dir;  // CCM direction bit the controllers use (AUDIT A17: 0); learned from requests
    uint64_t chmap;
    int8_t tx_power;

    // ISR: beacon scheduler
    pulsar_hop_t hop;
    pulsar_dm_t dm;
    uint64_t next_beacon_us;   // aligned to PULSAR_BEACON_PERIOD_US: period index = time / 2000
    bool rx_phase;             // the next op is this period's RX window
    bool cur_dm;
    uint8_t cur_freq;
    volatile uint8_t ack_mask; // slots heard since the last beacon
    host_prepared_t prep;

    // ISR -> main loop: received packets
    host_rx_t ring[HOST_RX_RING];
    volatile uint32_t ring_head, ring_tail;

    // pairing (main loop drives it; the ISR just runs the TX/RX ping-pong while pair_tx_ready)
    uint8_t pair_state;        // link_pair_state
    uint8_t pair_flags;
    uint64_t pair_filter;
    uint64_t pair_deadline_us;
    uint64_t pair_device;
    uint8_t pair_seq, pair_step, pair_cmd;
    uint8_t pair_priv[32], pair_pub[32], pair_shared[32];
    uint8_t pair_tx[2 + PAIR_DATA_LEN];
    uint8_t pair_tx_len;
    volatile bool pair_tx_ready;   // ISR may (re)send pair_tx
    volatile bool pair_rx_phase;
    volatile uint32_t pair_misses;
    uint64_t pair_tx_us;

    host_slot_t slot[PULSAR_SLOTS];
    uint8_t dl_rr;
    uint64_t refused_id, refused_us;  // rate-limits the "not allowed" note

    // stats
    uint32_t beacons, dm_beacons, uplinks, crc_errors, late_beacons;
    volatile uint32_t ring_overflow;
} host_t;

void host_init(host_t* h, platform_t* plat);
void host_stop(host_t* h);  // CMD_STOP: everything off, connections reported dropped
bool host_running(const host_t* h);

// Link v3 host commands (CMD_HOST_START .. CMD_HAPTIC, CMD_PAIR_LIST, CMD_PAIR_FORGET). Emits
// EVT_RESULT and friends. Returns false if `cmd` is not a host command. CMD_PAIR_LIST / FORGET work
// in any mode (they only touch the store unless the host is running).
bool host_command(host_t* h, uint8_t cmd, const uint8_t* body, uint32_t len);
void host_fill_status(const host_t* h, link_host_status_t* s);

// Main loop.
void host_poll(host_t* h);

// Radio callbacks (ISR on the dongle).
bool host_next_op(host_t* h, uint64_t now, radio_op_t* op);
void host_on_rx(host_t* h, const radio_rx_t* rx);
void host_on_done(host_t* h, const radio_op_t* op, uint64_t now);
