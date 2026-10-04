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
#define HOST_CTR_NEAR 2       // steady counters tried each side of the predicted one
#define HOST_CTR_SEARCH 32    // first steady uplink after an accept: counters tried around the prediction
#define HOST_TX_LEAD_US 150   // a beacon is planned at least this long before it goes out
#define HOST_TL_TIMEOUT_US 1000000  // real TL: a command not answered in this long fails (TIMEOUT)
#define HOST_ACCEPT_TRIES 100 // real: the accept goes out in this many beacons at most

typedef struct {
    uint64_t t_us;
    uint8_t freq, profile, rxmatch, len;
    int8_t rssi;
    bool crc_ok;
    uint8_t data[PULSAR_UPLINK_MAX_LEN + 4];
} host_rx_t;

// Why a queued real TL command was sent (what its answer is for).
enum { DL_USER = 0, DL_SILENT, DL_DESC, DL_IMU_CFG };

typedef struct {
    cl_msg_t msg;
    uint8_t addr_slot;  // slot the beacon addresses (byte 14); differs from the queue's slot only
                        // for a CONN_ACCEPT answering a request made in another slot
    uint8_t why;        // DL_*: DL_USER reads / writes report EVT_REG
    uint8_t tl_reg;     // real: the register the TL packet named (set when it is first encoded)
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
    uint64_t steady_id;      // the controller that iv belongs to
    bool held;               // CMD_DISCONNECT: ignore it until CMD_CONNECT (a real one stays on the link)
    bool ctr_locked;         // a steady uplink decrypted: ctr_last / ctr_period predict the next
    uint32_t ctr_last;       // counter of the last steady uplink
    uint64_t ctr_period;     // ... and its beacon period (the counter advances once per period, R7)
    uint64_t accept_period;  // beacon period the accept first went out in (0 = not yet)
    uint32_t probe;          // sweeps the counters beyond the search window
    uint8_t iv[8];
    host_dl_t dlq[HOST_DLQ];
    uint8_t dlq_head, dlq_len;
    uint8_t next_dl_seq;
    bool head_sent;
    uint64_t head_sent_period;
    uint8_t head_tries;

    // real TL (docs/re/REVIEW-RE.md R0): one command on air at a time, re-sent every beacon
    uint8_t tl_seq;          // seq of the newest command; bumped per new command, 15 wraps to 0.
                             // Kept across reconnects: the controller drops a repeat of its last seq
    uint64_t tl_deadline_us; // the head command (head_sent) times out then
    cl_ntf_t ntf;            // notification reassembly (R13)
    uint64_t ntf_fwd;        // ntf ids forwarded as EVT_REG(NOTIFY) (CMD_REG_SUBSCRIBE in real mode)
    struct { uint8_t buttons, battery_pct; uint16_t touch; int16_t stick[2]; uint16_t trigger, grip, pressure; } in;
    int16_t imu_last[6];     // accel, gyro: the last IMU sample (EVT_SAMPLE)
    uint64_t imu_last_us;
    int16_t temp_raw;
    uint8_t accel_fs_g;      // from cmd 0x32 (0 = not read yet)
    uint16_t gyro_fs_dps;
    uint8_t hand;            // link_hand, from cmd 1 (R11)
    cl_msg_t led;            // the last CMD_LED, re-sent after every (re)connect (R16)
    bool led_set;
    uint64_t haptic_stop_us; // a SIMPLE buzz shorter than 2 s: send the stop then (0 = none)
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
    uint8_t pair_retries;      // 0x25 rounds after a failed reply (R15)
    uint64_t pair_last_id;     // the controller paired last: EVT_PAIR(DONE) again with its hand
    bool pair_last_hand_sent;
    uint8_t pair_priv[32], pair_pub[32], pair_shared[32];
    uint8_t pair_tx[2 + PAIR_DATA_LEN];
    uint8_t pair_tx_len;
    volatile bool pair_tx_ready;   // ISR may (re)send pair_tx
    volatile bool pair_rx_phase;
    volatile uint32_t pair_misses;
    uint64_t pair_tx_us;

    host_slot_t slot[PULSAR_SLOTS];
    uint8_t dl_rr;
    volatile uint8_t idle_seq;  // real TL: the seq the idle [00][seq] beacon carries (LINK_HOST_TL_IDLE)
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
