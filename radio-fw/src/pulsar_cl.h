// Pulsar connected-link "CL" messages: what rides in a beacon's CL data (host -> controller,
// PLAINTEXT) and in an uplink (controller -> host, CCM-encrypted by the LL; nonces in pulsar_ll.h).
//
// Only the controller's connection request is pinned so far (docs/re/AUDIT.md A3). The CL/TL
// transport and the host's answers are RE-1's; the peripheral payloads are in docs/re/PERIPHERALS.md
// (RE-2) but ride that transport. So the link logic talks to a format through cl_format_t and there
// are two of them:
//
//   cl_real         the real Touch Plus formats. Decodes the connection request; everything the
//                   host would send is a STUB (encode returns CL_PENDING_RE -> LINK_ERR_PENDING_RE).
//                   RE-1/RE-2 fill these in; nothing else in the firmware has to change.
//   cl_placeholder  TouchFrame's own invented formats, so host mode can be exercised end to end
//                   against our fake controller (ctrl_core.c) and in the simulator. NEVER sent to a
//                   real controller: the host only uses it with LINK_HOST_PLACEHOLDER.
//
// Messages are passed around as format-neutral cl_msg_t.
#pragma once
#include <stdbool.h>
#include <stdint.h>

#include "pulsar_ll.h"

#define CL_DIR_UP 0    // controller -> host (CCM direction bit)
#define CL_DIR_DOWN 1  // host -> controller
#define CL_DOWN_MAX PULSAR_BEACON_CL_MAX         // downlink is plaintext (AUDIT A4)
#define CL_UP_MAX (PULSAR_UPLINK_MAX_LEN - 4)
#define CL_REG_DATA_MAX 32
#define CL_PENDING_RE (-2)  // encode: the real format is not known yet
#define CL_TOO_BIG (-1)     // encode: does not fit

enum cl_msg_type {
    CL_NONE = 0,
    // host -> controller
    CL_CONN_ACCEPT,   // conn: device_id, slot (assigned), version
    CL_CONN_REJECT,   // conn: device_id, reason
    CL_DISCONNECT,    // conn: device_id
    CL_REG_READ,      // reg: tag, reg, len
    CL_REG_WRITE,     // reg: tag, reg, len, data
    CL_REG_SUB,       // sub: reg, flags, period_ms
    CL_LED,           // led
    CL_HAPTIC,        // haptic (PCM in chunks)
    // controller -> host
    CL_IDLE,          // nothing to say but the ack
    CL_CONN_REQ,      // conn: device_id, slot (wanted), version, iv (steady-state CCM IV)
    CL_STREAM,        // stream: one input + IMU sample
    CL_REG_DATA,      // reg: tag, reg, kind, status, len, data, ul_seq
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
    uint8_t seq;       // down: message sequence (1..255) for dedupe/ack; up: ul_seq for REG_DATA dedupe
    uint8_t ack;       // up: the last down seq this controller processed (0 = none)
    union {
        struct { uint64_t device_id; uint8_t slot; uint16_t version; uint8_t reason; uint8_t iv[8]; } conn;
        struct { uint8_t tag, reg, len, kind, status; uint8_t data[CL_REG_DATA_MAX]; } reg;
        struct { uint8_t reg, flags; uint16_t period_ms; } sub;
        struct { uint8_t mode, intensity; uint32_t period_us, on_us; int32_t phase_us; uint32_t mask; } led;
        struct { uint8_t mode, amplitude; uint16_t freq_hz, duration_ms; uint8_t n; uint8_t pcm[25]; } haptic;
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
