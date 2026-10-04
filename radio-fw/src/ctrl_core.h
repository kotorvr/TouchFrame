// Fake Touch Plus for the loopback rig (CMD_FAKE_START on a second dongle, and test/sim.c).
//
// Unpaired it behaves like the controller SPL as docs/re/REVIEW-RE.md pins it: type-2 adverts on
// 2402 MHz, then the 2426 MHz DM link: 0x25 SetupX25519Keys answered with its public key, 0x22
// PairingData unwrapped (a failure wipes the keys, R15), replies [status][seq][data] with the
// retransmit rule (R5), and only a 0x2a Reset sends it to the "app" 500 ms later (R6).
// Paired it seeks the host's beacons on logical channels 0/17/36 (R10), follows the hop (CSA#1),
// requests a slot and then talks in it. With LINK_FAKE_REAL_CONN it uses the real formats all
// the way: request in the negotiation slot, one accept (slot S 1..4, R1-R4), the steady counter per
// beacon period (R7), direction 0 (R8), the TL header for register reads / writes and a
// notification chunk stream for input / IMU (R0, R13). Without it, the PLACEHOLDER connected-link
// formats (pulsar_cl.h). Same threading rules as host_core.h.
#pragma once
#include <stdbool.h>
#include <stdint.h>

#include "link.h"
#include "pulsar_cl.h"
#include "pulsar_hop.h"
#include "pulsar_ll.h"
#include "pulsar_pair.h"
#include "radio_op.h"

#define CTRL_REGS 64
#define CTRL_REG_SIZE 32
#define CTRL_LOST_PERIODS PULSAR_MISSED_BEACONS_DC
#define CTRL_NOTES 16

enum ctrl_state { CTRL_IDLE = 0, CTRL_ADVERTISING, CTRL_SEEKING, CTRL_FOLLOWING };

typedef struct {
    uint8_t kind;   // EVT_PAIR / EVT_CONN / EVT_TEXT note for the main loop
    uint8_t a, b;
    uint32_t v;
} ctrl_note_t;

typedef struct {
    platform_t* plat;
    const cl_format_t* fmt;
    uint8_t state;           // ctrl_state
    uint8_t flags;           // LINK_FAKE_*
    uint64_t device_id;

    // pairing (the SPL)
    bool paired;
    uint32_t netaddr;
    uint8_t key[16];
    uint8_t priv[32], pub[32], host_pub[32], shared[32];
    volatile bool shared_wanted, shared_ready;
    uint8_t pair_data[PAIR_DATA_LEN];
    uint8_t pair_data_seq;
    volatile bool pair_data_pending;  // ISR -> main: unwrap this 0x22; main builds its reply
    volatile bool pair_done;
    uint8_t fail_pair_data;           // test hook: refuse this many PairingData (as a MIC failure)
    uint8_t spl_last_seq;             // a request with this seq is a retransmit (starts at 0)
    uint64_t reset_at_us;             // a Reset arrived: boot the "app" (seek) then
    bool adv_rx_phase;
    uint8_t reply[2 + 32];            // the SPL's last reply, re-sent for a retransmit
    volatile uint8_t reply_len;       // 0 = none yet
    bool reply_pending;
    uint64_t reply_at_us;

    // connected link
    uint16_t session_nonce;   // from the beacons
    uint8_t iv[8];            // steady-state IV we announce in CONN_REQ
    uint8_t dir;              // CCM direction bit we use (0, R8)
    uint64_t accept_period;   // beacon period the accept arrived in: the steady counter counts from it
    pulsar_hop_t hop;
    uint8_t seek_idx;         // which of the R10 seek channels the next seek window uses
    uint64_t anchor_us;       // local time of the last beacon's ADDRESS (or dead-reckoned)
    uint64_t period;          // beacon period index of that beacon (host timestamp / 2000)
    uint64_t beacon_ts;
    uint64_t dm_period;       // next DM period announced (0 = none)
    uint32_t missed;
    bool heard;               // the last RX op caught a beacon: an uplink goes next
    bool cur_dm;
    bool accepted;
    uint8_t want_slot, slot;
    uint8_t last_dl_seq;
    uint8_t ul_seq;
    bool reply_reg_pending;   // a REG_DATA answer waits for the beacon ack bit
    bool reply_reg_sent;
    cl_msg_t reg_reply;
    struct { uint8_t reg; uint16_t period_ms; uint64_t next_us; } sub[4];
    uint16_t stream_seq;

    // real TL (the controller's T state, REVIEW-RE R0)
    uint8_t tl_seq;           // last seq seen in an addressed packet (T+0x40): every uplink carries it
    uint8_t tl_reg, tl_flags; // ... and its reg / flags, for the duplicate filter
    bool tl_seen;
    uint8_t resp[3 + CTRL_REG_SIZE];  // [reg][flags][data] of the last response
    uint8_t resp_len;         // 0 = the last command had no response
    bool resp_pending;
    uint8_t frag[16];         // the rest of a fragmented chunk, for the next notification (R13)
    uint8_t frag_len;
    uint64_t echo_next_us;    // ntf 0xb LED echo, every 2 s
    uint32_t led_cfg[3];      // cmd 0x28 as applied {period, on-time, d}
    uint8_t haptic_amp;
    uint16_t haptic_freq;
    bool data_ready;          // cmd 9 written
    uint32_t a1_writes;       // cmd 0xa1 (never expected, R12)
    uint32_t fatal_accepts;   // accepts with [11] = 0: a real controller asserts (R1)
    uint32_t dup_commands;    // retransmitted commands (seq, reg, read) not executed again

    // simulated registers and peripherals (tests read these)
    uint8_t regs[CTRL_REGS][CTRL_REG_SIZE];
    uint8_t reg_len[CTRL_REGS];
    cl_msg_t last_led, last_haptic;
    uint32_t haptic_bytes;
    uint32_t uplinks_sent, beacons_heard;

    // ISR -> main notes
    ctrl_note_t notes[CTRL_NOTES];
    volatile uint32_t note_head, note_tail;
} ctrl_t;

void ctrl_init(ctrl_t* c, platform_t* plat);
// CMD_FAKE_START body; emits EVT_RESULT. Must be called with the radio halted (main loop).
void ctrl_start(ctrl_t* c, const uint8_t* body, uint32_t len);
void ctrl_stop(ctrl_t* c);
void ctrl_poll(ctrl_t* c);

bool ctrl_next_op(ctrl_t* c, uint64_t now, radio_op_t* op);
void ctrl_on_rx(ctrl_t* c, const radio_rx_t* rx);
void ctrl_on_done(ctrl_t* c, const radio_op_t* op, uint64_t now);
