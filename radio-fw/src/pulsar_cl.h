// Pulsar connected-link "CL" messages: what rides in a beacon's CL data (host -> controller,
// PLAINTEXT) and in an uplink (controller -> host, CCM-encrypted by the LL; nonces in pulsar_ll.h).
//
// Pinned: the controller's connection request (AUDIT A3), the host's accept (docs/re/REVIEW-RE.md
// R1-R3) and the TL header that carries register access and notifications (REVIEW-RE R0). The
// peripheral payloads are in docs/re/PERIPHERALS.md. The link logic talks to a format through
// cl_format_t, and there are two of them:
//
//   cl_real         the real Touch Plus formats. Downlink register reads / writes, LED (cmd 0x28)
//                   and haptics (0x97 / 0xa0) become TL packets; uplinks decode to CL_CONN_REQ or
//                   CL_TL_UP, and the host runs the TL exchange (host_core.c). What is still
//                   unpinned (PCM haptics, a disconnect message) encodes to CL_PENDING_RE.
//   cl_placeholder  TouchFrame's own invented formats, so host mode can be exercised end to end
//                   against our fake controller (ctrl_core.c) and in the simulator. NEVER sent to a
//                   real controller: the host only uses it with LINK_HOST_PLACEHOLDER.
//
// Messages are passed around as format-neutral cl_msg_t.
#pragma once
#include <stdbool.h>
#include <stdint.h>

#include "pulsar_ll.h"

#define CL_DIR_UP 0       // controller -> host (CCM direction bit)
#define CL_DIR_DOWN 1     // host -> controller, a controller that has not been accepted (accept / reject)
#define CL_DIR_DOWN_TL 2  // host -> controller, a connected controller (real: a TL packet)
#define CL_DOWN_MAX PULSAR_BEACON_CL_MAX         // downlink is plaintext (AUDIT A4)
#define CL_UP_MAX (PULSAR_UPLINK_MAX_LEN - 4)
#define CL_REG_DATA_MAX 32
#define CL_PENDING_RE (-2)  // encode: the real format is not known yet
#define CL_TOO_BIG (-1)     // encode: does not fit
#define CL_EP_ACCEPT 2      // accept [2] & 7 (REVIEW-RE R2): accept ...
#define CL_EP_REJECT 3      // ... or refuse; the controller goes back to idle. Never sent by us.

// The TL header (REVIEW-RE R0). Downlink: beacon bytes 16.. = [reg][flags][payload <= 32].
// Uplink, after CL[0] = S: [reg][flags][data].
#define TL_SEQ_MASK 0x0F    // bits 0..3: the request's seq; uplinks carry the last seq the controller saw
#define TL_READ 0x10        // 1 = read, 0 = write
#define TL_ERR 0x20         // response: the handler failed
#define TL_NTF 0x40         // notification (unsolicited uplink)
#define TL_PAYLOAD_MAX 32
#define TL_REG_NTF 0x00     // notifications: reg 0 + the ntf chunk stream
#define TL_REG_RF_STATS 0x2A // RF-performance stats channel, either direction: ignored

enum cl_msg_type {
    CL_NONE = 0,
    // host -> controller
    CL_CONN_ACCEPT,   // conn: device_id, slot (assigned), version, fmt, iv (real: [12] = iv != 0)
    CL_CONN_REJECT,   // conn: device_id, reason
    CL_DISCONNECT,    // conn: device_id
    CL_REG_READ,      // reg: tag, reg, len (bytes wanted), n + data (read parameters, real only)
    CL_REG_WRITE,     // reg: tag, reg, len, data
    CL_REG_SUB,       // sub: reg, flags, period_ms
    CL_LED,           // led
    CL_HAPTIC,        // haptic (PCM in chunks)
    // controller -> host (CL_IDLE is also the real host's idle TL packet [00][seq])
    CL_IDLE,          // nothing to say but the ack
    CL_CONN_REQ,      // conn: device_id, slot (wanted), version, fmt, iv (steady-state CCM IV)
    CL_STREAM,        // stream: one input + IMU sample
    CL_REG_DATA,      // reg: tag, reg, kind, status, len, data, ul_seq
    // real TL packets as such (the fake controller, and the host's uplink path)
    CL_TL_UP,         // tl: slot, reg, flags, data, n
    CL_TL_DOWN,       // tl: reg, flags, data, n
};

typedef struct {
    uint16_t seq;
    uint32_t sample_us;   // controller's sync-clock time of the sample (low 32 bits)
    uint8_t buttons, battery_pct;
    uint16_t touch;
    int16_t stick[2];
    uint16_t trigger, grip, pressure;
    int16_t accel[3], gyro[3], temp;
} cl_stream_t;

typedef struct {
    uint8_t type;      // cl_msg_type
    uint8_t seq;       // down: message sequence (placeholder 1..255; real: the TL seq, 0..15)
                       // up: ul_seq for REG_DATA dedupe
    uint8_t ack;       // up: the last down seq this controller processed (0 = none)
    union {
        struct { uint64_t device_id; uint8_t slot; uint16_t version; uint8_t reason, endpoint, fmt; uint8_t iv[8]; } conn;
        struct { uint8_t tag, reg, len, kind, status, n; uint8_t data[CL_REG_DATA_MAX]; } reg;
        struct { uint8_t reg, flags; uint16_t period_ms; } sub;
        struct { uint8_t mode, intensity; uint32_t period_us, on_us; int32_t phase_us; uint32_t mask; } led;
        struct { uint8_t mode, amplitude; uint16_t freq_hz, duration_ms; uint8_t n; uint8_t pcm[25]; } haptic;
        struct { uint8_t slot, reg, flags, n; const uint8_t* data; } tl;  // data points into the packet
        cl_stream_t stream;
    } u;
} cl_msg_t;

typedef struct {
    const char* name;
    bool real;  // talks to real controllers
    // Plaintext bytes written (<= max), or CL_TOO_BIG / CL_PENDING_RE.
    int (*encode)(const cl_msg_t* m, uint8_t* out, int max);
    bool (*decode)(const uint8_t* in, int len, uint8_t dir, cl_msg_t* m);
    uint8_t haptic_chunk;  // PCM bytes per CL_HAPTIC message
} cl_format_t;

extern const cl_format_t cl_real;
extern const cl_format_t cl_placeholder;

// Notification chunk stream (REVIEW-RE R0 rule 7, R13; libsyncboss ntf_unpacker_next 0x12e74).
// Each chunk = u16 header + payload: type bits 0..4 (+ bit 5 at header bit 11), length bits 5..10,
// fragment seq bits 12..14, bit 15 = last fragment; (h & 0xf000) == 0x8000 is a whole chunk.
// Fragments of one type with seq 0, 1, 2 ... are appended (total <= 0x3f) and delivered with the
// last one. A NON-FINAL fragment ends the notification: reassembly continues in the next one, so
// the state lives per controller. A broken sequence drops the partial chunk and the rest.
#define CL_NTF_MAX 0x3F
typedef struct {
    bool active;
    uint8_t type, seq, len;
    uint8_t buf[CL_NTF_MAX];
} cl_ntf_t;

typedef void (*cl_ntf_cb)(void* user, uint8_t type, const uint8_t* data, uint8_t len);
void cl_ntf_unpack(cl_ntf_t* st, const uint8_t* p, int n, cl_ntf_cb cb, void* user);
// One whole chunk at out (len <= CL_NTF_MAX); bytes written, or 0 if it does not fit in max.
int cl_ntf_pack(uint8_t* out, int max, uint8_t type, const uint8_t* data, uint8_t len);
