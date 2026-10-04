// Fake Touch Plus for the loopback rig (CMD_FAKE_START on a second dongle, and test/sim.c).
//
// Unpaired it behaves like the controller SPL as far as PROTOCOL.md pins it: type-2 adverts on
// 2402 MHz, then the 2426 MHz DM link where it answers 0x12 SetupX25519Keys with its public key
// and unwraps 0x11 PairingData (real formats, so the host's pairing code is tested for real).
// Paired it seeks a DM beacon on 2402, follows the beacon hop (CSA#1), asks for a slot and then
// streams in it, all with the PLACEHOLDER connected-link formats (pulsar_cl.h): the real ones are
// not pinned yet. Same threading rules as host_core.h.
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
#define CTRL_REG_SIZE 16
#define CTRL_LOST_PERIODS 250   // PULSAR_DEVICE_MISSED_BEACONS_BEFORE_DC (value INFERRED)
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

    // pairing
    bool paired;
    uint32_t netaddr;
    uint8_t key[16];
    uint8_t priv[32], pub[32], host_pub[32], shared[32];
    volatile bool shared_wanted, shared_ready;
    uint8_t pair_data[PAIR_DATA_LEN];
    uint8_t pair_data_seq;
    volatile bool pair_data_pending;  // ISR -> main: decrypt this 0x11
    volatile bool pair_done;          // main -> ISR: answer 0x11 with seq pair_done_seq
    uint8_t pair_done_seq;
    uint64_t paired_at_us;
    bool adv_rx_phase;
    uint8_t reply[2 + 32];
    uint8_t reply_len;
    bool reply_pending;
    uint64_t reply_at_us;

    // connected link
    cl_session_t session;
    pulsar_hop_t hop;
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
