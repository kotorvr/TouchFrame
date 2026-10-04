#include "pulsar_cl.h"

#include <string.h>

static void put16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
static void put32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void put64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint16_t get16(const uint8_t* p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t get32(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t get64(const uint8_t* p) { return (uint64_t)get32(p) | (uint64_t)get32(p + 4) << 32; }

//------------------------------------------------------------------ real formats

// Connection negotiation, host -> controller (docs/re/LINK.md §4, the device accept handler elk-app
// 0x23aa8): [0] 1, [1] 0 (INFERRED), [2] endpoint (CL_EP_CONN_NEG, then CL_EP_LOCK), [3..10] the
// controller's device id, [11] the radio slot we assign (0..4), [12..13] version 0x1701. As
// tools/pulsar_host.py build_conn_negotiation. INFERRED: that these 14 bytes alone (not the 26-byte
// record body syncboss copies, CL length 36) are enough; the device validates only [0], [2], [3..11].
#define REAL_CONN_TYPE 1
#define REAL_CONN_LEN 14
#define REAL_REQ_LEN 25
// TODO(RE-1, one capture): the TL header for register read / write / subscribe (LINK.md §3: command
// register ids 0x05..0xb4) and notifications (0x14 wrapper stripped, ntf chunk stream).
// TODO(RE-2 formats exist in docs/re/PERIPHERALS.md; they need that transport): LED cmd 0x28
// {u32 period_us >= 700, u32 ontime_us <= 75, i32 centre_us on the host clock}; haptics 0x97 /
// 0xa0 {amp, u16 Hz 40..561} / 0x9d ADPCM (each stops after 2 s; send 0x97 at duration_ms when
// shorter); input/IMU arrive as notification chunks after cmd 9 (IMU ntf 1 = u48 timestamp + 6 x
// i16 at 500 Hz, scales from cmd 0x32).
static int real_encode(const cl_msg_t* m, uint8_t* b, int max) {
    if (m->type == CL_CONN_ACCEPT) {
        if (max < REAL_CONN_LEN) return CL_TOO_BIG;
        memset(b, 0, REAL_CONN_LEN);
        b[0] = REAL_CONN_TYPE;
        b[2] = (uint8_t)(m->u.conn.endpoint & 7);
        put64(b + 3, m->u.conn.device_id);
        b[11] = m->u.conn.slot;
        put16(b + 12, m->u.conn.version);
        return REAL_CONN_LEN;
    }
    if (m->type == CL_CONN_REQ) {  // the request as real_decode reads it (the fake controller sends it)
        if (max < REAL_REQ_LEN) return CL_TOO_BIG;
        memset(b, 0, REAL_REQ_LEN);
        b[1] = 0x11;
        put64(b + 2, m->u.conn.device_id);
        put16(b + 10, m->u.conn.version);
        b[14] = 1;  // slots requested
        memcpy(b + 15, m->u.conn.iv, 8);
        return REAL_REQ_LEN;
    }
    return CL_PENDING_RE;
}

// The controller's connection request (docs/re/AUDIT.md A3, elk-app 0x23bc4, LENGTH 25):
// [0] 0, [1] 0x11 (format: [1] >> 3 = 2), [2..9] device id, [10..13] version word (01 17 ..),
// [14] ?, [15..22] the steady-state IV (u64 LE), [23..24] ?. INFERRED: that the CL payload starts at
// the first decrypted uplink byte (the LL/CL header split is RE-1's).
// TODO(RE-1): input / IMU / hreg uplinks.
static bool real_decode(const uint8_t* b, int n, uint8_t dir, cl_msg_t* m) {
    memset(m, 0, sizeof(*m));
    if (dir == CL_DIR_DOWN) {  // a negotiation packet, checked like the device accept handler does
        uint8_t ep = n >= REAL_CONN_LEN ? b[2] & 7 : 0;
        if (b[0] != REAL_CONN_TYPE || (ep != CL_EP_CONN_NEG && ep != CL_EP_LOCK) || b[11] >= PULSAR_SLOTS)
            return false;
        m->type = CL_CONN_ACCEPT;
        m->u.conn.endpoint = ep;
        m->u.conn.device_id = get64(b + 3);
        m->u.conn.slot = b[11];
        m->u.conn.version = get16(b + 12);
        return true;
    }
    if (n < 23 || b[0] != 0 || (b[1] >> 3) != 2) return false;
    m->type = CL_CONN_REQ;
    m->u.conn.device_id = get64(b + 2);
    m->u.conn.version = get16(b + 10);
    m->u.conn.slot = 0xFF;  // a real controller does not ask for a slot
    memcpy(m->u.conn.iv, b + 15, 8);
    return true;
}

const cl_format_t cl_real = {"real", true, real_encode, real_decode, 0};

//------------------------------------------------------------------ placeholder (loopback only)
// Invented by TouchFrame. Byte 0 = type, byte 1 = seq (down) or ack (up), then the fields below.
// Rides the real LL: plaintext downlink, uplink under the legacy nonce until the accept and the
// steady-state nonce after (the IV travels in CONN_REQ, like the real request).

enum {
    PH_CONN_ACCEPT = 0x01, PH_CONN_REJECT = 0x02, PH_DISCONNECT = 0x03,
    PH_REG_READ = 0x10, PH_REG_WRITE = 0x11, PH_REG_SUB = 0x12,
    PH_LED = 0x20, PH_HAPTIC = 0x21,
    PH_IDLE = 0x80, PH_CONN_REQ = 0x81, PH_STREAM = 0x82, PH_REG_DATA = 0x83,
    PH_STREAM_LEN = 36,
};

static int ph_encode(const cl_msg_t* m, uint8_t* p, int max) {
    uint8_t b[CL_UP_MAX];
    int n = 2;
    b[1] = m->seq;
    switch (m->type) {
    case CL_CONN_ACCEPT:
    case CL_CONN_REJECT:
    case CL_DISCONNECT:
    case CL_CONN_REQ:
        b[0] = m->type == CL_CONN_ACCEPT ? PH_CONN_ACCEPT
             : m->type == CL_CONN_REJECT ? PH_CONN_REJECT
             : m->type == CL_DISCONNECT ? PH_DISCONNECT : PH_CONN_REQ;
        if (m->type == CL_CONN_REQ) b[1] = m->ack;
        put64(b + 2, m->u.conn.device_id);
        b[10] = m->u.conn.slot;
        put16(b + 11, m->u.conn.version);
        b[13] = m->u.conn.reason;
        memcpy(b + 14, m->u.conn.iv, 8);
        n = 22;
        break;
    case CL_REG_READ:
    case CL_REG_WRITE:
        b[0] = m->type == CL_REG_READ ? PH_REG_READ : PH_REG_WRITE;
        b[2] = m->u.reg.tag;
        b[3] = m->u.reg.reg;
        b[4] = m->u.reg.len;
        n = 5;
        if (m->type == CL_REG_WRITE) {
            if (m->u.reg.len > CL_REG_DATA_MAX) return CL_TOO_BIG;
            memcpy(b + 5, m->u.reg.data, m->u.reg.len);
            n += m->u.reg.len;
        }
        break;
    case CL_REG_SUB:
        b[0] = PH_REG_SUB;
        b[2] = m->u.sub.reg;
        b[3] = m->u.sub.flags;
        put16(b + 4, m->u.sub.period_ms);
        n = 6;
        break;
    case CL_LED:
        b[0] = PH_LED;
        b[2] = m->u.led.mode;
        b[3] = m->u.led.intensity;
        put32(b + 4, m->u.led.period_us);
        put32(b + 8, m->u.led.on_us);
        put32(b + 12, (uint32_t)m->u.led.phase_us);
        put32(b + 16, m->u.led.mask);
        n = 20;
        break;
    case CL_HAPTIC:
        b[0] = PH_HAPTIC;
        b[2] = m->u.haptic.mode;
        b[3] = m->u.haptic.amplitude;
        put16(b + 4, m->u.haptic.freq_hz);
        put16(b + 6, m->u.haptic.duration_ms);
        b[8] = m->u.haptic.n;
        if (m->u.haptic.n > sizeof(m->u.haptic.pcm)) return CL_TOO_BIG;
        memcpy(b + 9, m->u.haptic.pcm, m->u.haptic.n);
        n = 9 + m->u.haptic.n;
        break;
    case CL_IDLE:
        b[0] = PH_IDLE;
        b[1] = m->ack;
        break;
    case CL_STREAM: {
        const cl_stream_t* s = &m->u.stream;
        b[0] = PH_STREAM;
        b[1] = m->ack;
        put16(b + 2, s->seq);
        put32(b + 4, s->sample_us);
        b[8] = s->buttons;
        b[9] = s->battery_pct;
        put16(b + 10, s->touch);
        put16(b + 12, (uint16_t)s->stick[0]);
        put16(b + 14, (uint16_t)s->stick[1]);
        put16(b + 16, s->trigger);
        put16(b + 18, s->grip);
        put16(b + 20, s->pressure);
        for (int i = 0; i < 3; i++) put16(b + 22 + 2 * i, (uint16_t)s->accel[i]);
        for (int i = 0; i < 3; i++) put16(b + 28 + 2 * i, (uint16_t)s->gyro[i]);
        put16(b + 34, (uint16_t)s->temp);
        n = PH_STREAM_LEN;
        break;
    }
    case CL_REG_DATA:
        if (m->u.reg.len > CL_REG_DATA_MAX) return CL_TOO_BIG;
        b[0] = PH_REG_DATA;
        b[1] = m->ack;
        b[2] = m->seq;
        b[3] = m->u.reg.tag;
        b[4] = m->u.reg.reg;
        b[5] = m->u.reg.kind;
        b[6] = m->u.reg.status;
        b[7] = m->u.reg.len;
        memcpy(b + 8, m->u.reg.data, m->u.reg.len);
        n = 8 + m->u.reg.len;
        break;
    default:
        return CL_TOO_BIG;
    }
    if (n > max) return CL_TOO_BIG;
    memcpy(p, b, (size_t)n);
    return n;
}

static bool ph_decode(const uint8_t* b, int n, uint8_t dir, cl_msg_t* m) {
    memset(m, 0, sizeof(*m));
    if (n < 2) return false;
    bool up = dir == CL_DIR_UP;
    if (up) m->ack = b[1];
    else m->seq = b[1];
    switch (b[0]) {
    case PH_CONN_ACCEPT:
    case PH_CONN_REJECT:
    case PH_DISCONNECT:
    case PH_CONN_REQ:
        if (n < 22 || up != (b[0] == PH_CONN_REQ)) return false;
        m->type = b[0] == PH_CONN_ACCEPT ? CL_CONN_ACCEPT
                : b[0] == PH_CONN_REJECT ? CL_CONN_REJECT
                : b[0] == PH_DISCONNECT ? CL_DISCONNECT : CL_CONN_REQ;
        m->u.conn.device_id = get64(b + 2);
        m->u.conn.slot = b[10];
        m->u.conn.version = get16(b + 11);
        m->u.conn.reason = b[13];
        memcpy(m->u.conn.iv, b + 14, 8);
        return true;
    case PH_REG_READ:
    case PH_REG_WRITE:
        if (up || n < 5) return false;
        m->type = b[0] == PH_REG_READ ? CL_REG_READ : CL_REG_WRITE;
        m->u.reg.tag = b[2];
        m->u.reg.reg = b[3];
        m->u.reg.len = b[4];
        if (m->type == CL_REG_WRITE) {
            if (m->u.reg.len > CL_REG_DATA_MAX || n < 5 + m->u.reg.len) return false;
            memcpy(m->u.reg.data, b + 5, m->u.reg.len);
        }
        return true;
    case PH_REG_SUB:
        if (up || n < 6) return false;
        m->type = CL_REG_SUB;
        m->u.sub.reg = b[2];
        m->u.sub.flags = b[3];
        m->u.sub.period_ms = get16(b + 4);
        return true;
    case PH_LED:
        if (up || n < 20) return false;
        m->type = CL_LED;
        m->u.led.mode = b[2];
        m->u.led.intensity = b[3];
        m->u.led.period_us = get32(b + 4);
        m->u.led.on_us = get32(b + 8);
        m->u.led.phase_us = (int32_t)get32(b + 12);
        m->u.led.mask = get32(b + 16);
        return true;
    case PH_HAPTIC:
        if (up || n < 9 || b[8] > sizeof(m->u.haptic.pcm) || n < 9 + b[8]) return false;
        m->type = CL_HAPTIC;
        m->u.haptic.mode = b[2];
        m->u.haptic.amplitude = b[3];
        m->u.haptic.freq_hz = get16(b + 4);
        m->u.haptic.duration_ms = get16(b + 6);
        m->u.haptic.n = b[8];
        memcpy(m->u.haptic.pcm, b + 9, b[8]);
        return true;
    case PH_IDLE:
        if (!up) return false;
        m->type = CL_IDLE;
        return true;
    case PH_STREAM: {
        if (!up || n < PH_STREAM_LEN) return false;
        cl_stream_t* s = &m->u.stream;
        m->type = CL_STREAM;
        s->seq = get16(b + 2);
        s->sample_us = get32(b + 4);
        s->buttons = b[8];
        s->battery_pct = b[9];
        s->touch = get16(b + 10);
        s->stick[0] = (int16_t)get16(b + 12);
        s->stick[1] = (int16_t)get16(b + 14);
        s->trigger = get16(b + 16);
        s->grip = get16(b + 18);
        s->pressure = get16(b + 20);
        for (int i = 0; i < 3; i++) s->accel[i] = (int16_t)get16(b + 22 + 2 * i);
        for (int i = 0; i < 3; i++) s->gyro[i] = (int16_t)get16(b + 28 + 2 * i);
        s->temp = (int16_t)get16(b + 34);
        return true;
    }
    case PH_REG_DATA:
        if (!up || n < 8 || b[7] > CL_REG_DATA_MAX || n < 8 + b[7]) return false;
        m->type = CL_REG_DATA;
        m->seq = b[2];
        m->u.reg.tag = b[3];
        m->u.reg.reg = b[4];
        m->u.reg.kind = b[5];
        m->u.reg.status = b[6];
        m->u.reg.len = b[7];
        memcpy(m->u.reg.data, b + 8, b[7]);
        return true;
    }
    return false;
}

const cl_format_t cl_placeholder = {"placeholder", false, ph_encode, ph_decode, 25};
