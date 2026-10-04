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

//------------------------------------------------------------------ real formats: RE pending

// TODO(RE-1, MASTER-PLAN 3.1.3): the steady-state nonce the host must produce. PROTOCOL Q3 has two
// INFERRED hypotheses: (a) the negotiation's random 8-byte IV reused for the session with an
// advancing 39-bit counter, (b) the 16-bit session nonce in the top counter bits. Whichever RE-1
// pins goes here; tools/pulsar_crypto.py `scan` checks it against a capture in one packet.
static bool real_nonce(const cl_session_t* s, uint64_t period, uint8_t dir, uint8_t slot, uint8_t nonce[13]) {
    (void)s, (void)period, (void)dir, (void)slot, (void)nonce;
    return false;
}

// TODO(RE-1, MASTER-PLAN 3.1.1-2): connection negotiation, CL/TL framing, hreg access.
// Known so far (PROTOCOL Q6, elk-app accept handler FUN_00023aa8): the controller accepts a
// negotiation packet with [0] = 1 (type), [2] & 7 = endpoint (2 = CONN_NEG, 3 = lock), [3..10] =
// its 64-bit peer id, [11] = slot; its response starts 0x19, 0x11 and echoes its connection
// record incl. the 0x1701 version. Not enough to transmit: byte 1, the trailing fields, the
// 36-byte beacon variant and the nonce are open.
// TODO(RE-2, MASTER-PLAN 3.1.5-8): LED config (p / ot / d and its limits), haptics, IMU layout.
static int real_encode(const cl_msg_t* m, uint8_t* out, int max) {
    (void)m, (void)out, (void)max;
    return CL_PENDING_RE;
}

// TODO(RE-1/RE-2): parse real uplinks (negotiation request, hreg data, input, IMU). Until then the
// host can only report them raw (LINK_HOST_RAW_UPLINKS).
static bool real_decode(const uint8_t* in, int len, uint8_t dir, cl_msg_t* m) {
    (void)in, (void)len, (void)dir, (void)m;
    return false;
}

const cl_format_t cl_real = {"real", true, real_nonce, real_encode, real_decode, 0};

//------------------------------------------------------------------ placeholder (loopback only)
// Invented by TouchFrame. Byte 0 = type, byte 1 = seq (down) or ack (up), then the fields below.
// Nonce: counter = beacon period index, direction bit, IV = session nonce, netaddr, slot, 'T'.

enum {
    PH_CONN_ACCEPT = 0x01, PH_CONN_REJECT = 0x02, PH_DISCONNECT = 0x03,
    PH_REG_READ = 0x10, PH_REG_WRITE = 0x11, PH_REG_SUB = 0x12,
    PH_LED = 0x20, PH_HAPTIC = 0x21,
    PH_IDLE = 0x80, PH_CONN_REQ = 0x81, PH_STREAM = 0x82, PH_REG_DATA = 0x83,
};

static bool ph_nonce(const cl_session_t* s, uint64_t period, uint8_t dir, uint8_t slot, uint8_t nonce[13]) {
    uint64_t pc = (period & ((1ull << 39) - 1)) | (uint64_t)(dir & 1) << 39;
    for (int i = 0; i < 5; i++) nonce[i] = (uint8_t)(pc >> (8 * i));
    put16(nonce + 5, s->session_nonce);
    put32(nonce + 7, s->netaddr);
    nonce[11] = slot;
    nonce[12] = 'T';
    return true;
}

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
        n = 14;
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
        put16(b + 8, s->buttons);
        for (int i = 0; i < 4; i++) put16(b + 10 + 2 * i, s->analog[i]);
        b[18] = s->touch;
        put16(b + 19, s->battery);
        for (int i = 0; i < 3; i++) put16(b + 21 + 2 * i, (uint16_t)s->accel[i]);
        for (int i = 0; i < 3; i++) put16(b + 27 + 2 * i, (uint16_t)s->gyro[i]);
        put16(b + 33, (uint16_t)s->temp);
        n = 35;
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
        if (n < 14 || up != (b[0] == PH_CONN_REQ)) return false;
        m->type = b[0] == PH_CONN_ACCEPT ? CL_CONN_ACCEPT
                : b[0] == PH_CONN_REJECT ? CL_CONN_REJECT
                : b[0] == PH_DISCONNECT ? CL_DISCONNECT : CL_CONN_REQ;
        m->u.conn.device_id = get64(b + 2);
        m->u.conn.slot = b[10];
        m->u.conn.version = get16(b + 11);
        m->u.conn.reason = b[13];
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
        if (!up || n < 35) return false;
        cl_stream_t* s = &m->u.stream;
        m->type = CL_STREAM;
        s->seq = get16(b + 2);
        s->sample_us = get32(b + 4);
        s->buttons = get16(b + 8);
        for (int i = 0; i < 4; i++) s->analog[i] = get16(b + 10 + 2 * i);
        s->touch = b[18];
        s->battery = get16(b + 19);
        for (int i = 0; i < 3; i++) s->accel[i] = (int16_t)get16(b + 21 + 2 * i);
        for (int i = 0; i < 3; i++) s->gyro[i] = (int16_t)get16(b + 27 + 2 * i);
        s->temp = (int16_t)get16(b + 33);
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

const cl_format_t cl_placeholder = {"placeholder", false, ph_nonce, ph_encode, ph_decode, 21};
