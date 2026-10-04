#include "pulsar_cl.h"

#include <string.h>

#include "link.h"
#include "le.h"

//------------------------------------------------------------------ real formats

// The accept, host -> controller (REVIEW-RE R1-R3, CONFIRMED on both sides; the device accept
// handler elk-app 0x23af8): [0] 1, [1] 0 (not read), [2] (fmt << 3) | 2, [3..10] the controller's
// device id, [11] S (1..4), [12] 1 if the request carried a steady IV (0 makes the controller zero
// its IV and keep the legacy nonce), [13] slot count (1). One accept, re-sent until the controller
// shows up in slot S; never a second "lock" packet ([2] & 7 == 3 is a reject). INFERRED: that these
// 14 bytes alone (not the 26-byte record body syncboss copies) are enough; the device reads no more.
#define REAL_CONN_TYPE 1
#define REAL_CONN_LEN 14
#define REAL_REQ_LEN 25
// cmd 0x28 LED config {u32 period_us, u32 ontime_us, i32 d}: d = the pulse centre on the shared
// clock, modulo the period (PERIPHERALS §2; REVIEW-RE "d = pulse centre"). OFF = on-time 0 with a
// long period (with a period < 1000 us, on-time 0 busy-loops the LED thread, R16).
#define REG_LED_CONFIG 0x28
#define REG_HAPTIC_SIMPLE 0x97   // {u8 amplitude}, 0 = stop
#define REG_HAPTIC_FREQ 0xA0     // {u8 amplitude, u16 freq 40..561}; stops by itself after 2 s
#define LED_OFF_PERIOD_US 500000

static int tl_put(uint8_t* b, int max, uint8_t reg, uint8_t flags, const uint8_t* data, int n) {
    if (n > TL_PAYLOAD_MAX || 2 + n > max) return CL_TOO_BIG;
    b[0] = reg;
    b[1] = flags;
    if (n) memcpy(b + 2, data, (size_t)n);
    return 2 + n;
}

static int real_encode(const cl_msg_t* m, uint8_t* b, int max) {
    uint8_t seq = m->seq & TL_SEQ_MASK, p[12];
    switch (m->type) {
    case CL_CONN_ACCEPT:
        if (max < REAL_CONN_LEN || !PULSAR_SLOT_USABLE(m->u.conn.slot)) return CL_TOO_BIG;  // [11] = 0 is fatal
        memset(b, 0, REAL_CONN_LEN);
        b[0] = REAL_CONN_TYPE;
        b[2] = (uint8_t)((m->u.conn.fmt ? m->u.conn.fmt : 2) << 3 | CL_EP_ACCEPT);
        put64(b + 3, m->u.conn.device_id);
        b[11] = m->u.conn.slot;
        b[12] = get64(m->u.conn.iv) != 0;
        b[13] = 1;
        return REAL_CONN_LEN;
    case CL_CONN_REQ:  // the request as real_decode reads it (the fake controller sends it)
        if (max < REAL_REQ_LEN) return CL_TOO_BIG;
        memset(b, 0, REAL_REQ_LEN);
        b[1] = 0x11;  // format 2 (Touch Plus)
        put64(b + 2, m->u.conn.device_id);
        put16(b + 10, m->u.conn.version);
        b[14] = 1;  // slots requested
        memcpy(b + 15, m->u.conn.iv, 8);
        return REAL_REQ_LEN;
    case CL_REG_READ:
        return tl_put(b, max, m->u.reg.reg, seq | TL_READ, m->u.reg.data, m->u.reg.n);
    case CL_REG_WRITE:
        return tl_put(b, max, m->u.reg.reg, seq, m->u.reg.data, m->u.reg.len);
    case CL_LED: {
        uint32_t period = m->u.led.period_us, on = m->u.led.on_us;
        int32_t d = 0;
        if (m->u.led.mode == LINK_LED_OFF) {
            period = LED_OFF_PERIOD_US;
            on = 0;
        } else if (m->u.led.mode != LINK_LED_STROBE || !period || period > INT32_MAX) {
            return CL_TOO_BIG;  // a real controller cannot hold its LEDs on
        } else {
            d = m->u.led.phase_us % (int32_t)period;
            if (d < 0) d += (int32_t)period;
        }
        put32(p, period);
        put32(p + 4, on);
        put32(p + 8, (uint32_t)d);
        return tl_put(b, max, REG_LED_CONFIG, seq, p, 12);
    }
    case CL_HAPTIC:
        if (m->u.haptic.mode == LINK_HAPTIC_STOP) {
            p[0] = 0;
            return tl_put(b, max, REG_HAPTIC_SIMPLE, seq, p, 1);
        }
        if (m->u.haptic.mode == LINK_HAPTIC_SIMPLE) {
            p[0] = m->u.haptic.amplitude;
            put16(p + 1, m->u.haptic.freq_hz);
            return tl_put(b, max, REG_HAPTIC_FREQ, seq, p, 3);
        }
        return CL_PENDING_RE;  // TODO(RE): PCM = 0x9d, 3-bit ADPCM (R16); the encoder is not pinned
    case CL_IDLE:  // the idle host packet, sent with byte 14 = 0 (R0 rule 2)
        return tl_put(b, max, TL_REG_NTF, seq, NULL, 0);
    case CL_TL_UP:  // the fake controller: [S][reg][flags][data]
        if (3 + m->u.tl.n > max) return CL_TOO_BIG;
        b[0] = m->u.tl.slot;
        b[1] = m->u.tl.reg;
        b[2] = m->u.tl.flags;
        if (m->u.tl.n) memcpy(b + 3, m->u.tl.data, m->u.tl.n);
        return 3 + m->u.tl.n;
    default:
        return CL_PENDING_RE;  // CL_REG_SUB (the controller pushes on its own), CL_DISCONNECT
    }
}

// Uplinks: CL[0] = 0 is the controller's connection request (AUDIT A3, elk-app 0x23bc4, LENGTH 25):
// [1] format ([1] >> 3: 0 = no bytes 14.., 1 = 14..22, >= 2 = all; R16), [2..9] device id, [10..13]
// version word (01 17, handedness, board), [14] slots requested, [15..22] the steady IV (u64 LE),
// [23..24] radio details. CL[0] = S is a TL packet from the controller in slot S (R0).
// Downlinks (the fake controller): the accept / reject (CL_DIR_DOWN), or a TL packet (CL_DIR_DOWN_TL).
static bool real_decode(const uint8_t* b, int n, uint8_t dir, cl_msg_t* m) {
    memset(m, 0, sizeof(*m));
    if (dir == CL_DIR_DOWN) {  // checked like the device accept handler does
        uint8_t ep = n >= REAL_CONN_LEN ? b[2] & 7 : 0;
        if (n < REAL_CONN_LEN || b[0] != REAL_CONN_TYPE || (ep != CL_EP_ACCEPT && ep != CL_EP_REJECT)) return false;
        m->type = ep == CL_EP_ACCEPT ? CL_CONN_ACCEPT : CL_CONN_REJECT;
        m->u.conn.endpoint = ep;
        m->u.conn.fmt = b[2] >> 3;
        m->u.conn.device_id = get64(b + 3);
        m->u.conn.slot = b[11];
        m->u.conn.iv[0] = b[12];   // the IV flag
        m->u.conn.reason = b[13];  // the slot count
        return true;
    }
    if (dir == CL_DIR_DOWN_TL) {
        if (n < 2 || n > 2 + TL_PAYLOAD_MAX) return false;
        m->type = CL_TL_DOWN;
        m->seq = b[1] & TL_SEQ_MASK;
        m->u.tl.reg = b[0];
        m->u.tl.flags = b[1];
        m->u.tl.n = (uint8_t)(n - 2);
        m->u.tl.data = b + 2;
        return true;
    }
    if (n >= 1 && b[0] != 0) {
        if (n < 3 || b[0] >= PULSAR_SLOTS) return false;
        m->type = CL_TL_UP;
        m->u.tl.slot = b[0];
        m->u.tl.reg = b[1];
        m->u.tl.flags = b[2];
        m->u.tl.n = (uint8_t)(n - 3);
        m->u.tl.data = b + 3;
        return true;
    }
    if (n < 23 || (b[1] >> 3) == 0) return false;  // no steady IV: not a Touch Plus request
    m->type = CL_CONN_REQ;
    m->u.conn.fmt = b[1] >> 3;
    m->u.conn.device_id = get64(b + 2);
    m->u.conn.version = get16(b + 10);
    m->u.conn.slot = 0xFF;  // a real controller does not ask for a slot
    memcpy(m->u.conn.iv, b + 15, 8);
    return true;
}

const cl_format_t cl_real = {"real", true, real_encode, real_decode, 0};

//------------------------------------------------------------------ notification chunks

void cl_ntf_unpack(cl_ntf_t* st, const uint8_t* p, int n, cl_ntf_cb cb, void* user) {
    int pos = 0;
    while (pos + 2 <= n) {
        uint16_t h = get16(p + pos);
        uint8_t len = (uint8_t)((h >> 5) & 0x3F);
        if (pos + 2 + len > n) return;  // overrun
        const uint8_t* body = p + pos + 2;
        pos += 2 + len;
        uint8_t type = (uint8_t)((h & 0x1F) | ((h >> 6) & 0x20)), seq = (uint8_t)((h >> 12) & 7);
        bool last = h & 0x8000;
        if ((h & 0xF000) == 0x8000) {  // a whole chunk (leaves a reassembly in progress alone: INFERRED)
            cb(user, type, body, len);
            continue;
        }
        if (seq == 0) {
            st->active = true;
            st->type = type;
            st->seq = 0;
            st->len = 0;
        } else if (!st->active || type != st->type || seq != st->seq + 1) {
            st->active = false;  // broken sequence: the rest of this notification is dropped
            return;
        } else {
            st->seq = seq;
        }
        if (st->len + len > CL_NTF_MAX) {
            st->active = false;
            return;
        }
        memcpy(st->buf + st->len, body, len);
        st->len = (uint8_t)(st->len + len);
        if (!last) return;  // continues in the next notification
        st->active = false;
        cb(user, st->type, st->buf, st->len);
    }
}

int cl_ntf_pack(uint8_t* out, int max, uint8_t type, const uint8_t* data, uint8_t len) {
    if (len > CL_NTF_MAX || type >= 0x40 || 2 + len > max) return 0;
    put16(out, (uint16_t)((type & 0x1F) | len << 5 | (type >> 5 & 1) << 11 | 0x8000));
    if (len) memcpy(out + 2, data, len);
    return 2 + len;
}

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
