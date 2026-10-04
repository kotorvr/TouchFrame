#include "ctrl_core.h"

#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "le.h"

#define TX_LEAD_US 200
#define ADV_RX_WINDOW_US 8000    // after each advert, listen on the DM link this long
#define SPL_RESET_DELAY_US 500000  // the SPL jumps to the app this long after a Reset (R6)
#define REPLY_TURNAROUND_US 150
#define BEACON_WINDOW_US 60      // +- around the expected beacon, plus drift growth
#define SPL_STATUS 0x02          // reply status bits 1..6 are stale: 1 after advertising (R5)
#define NTF_BUDGET 49            // chunk bytes per notification: the 52-byte one-slot uplink less [S][reg][flags]
#define ECHO_PERIOD_US 2000000   // ntf 0xb LED-config echo (R16: every 2 s)
#define LED_MAX_PERIOD_US 500000

// as host_core.c (docs/re/PERIPHERALS.md)
enum { REG_DEVICE_DESC = 0x01, REG_DATA_READY = 0x09, REG_LED_CONFIG = 0x28, REG_IMU_CONFIG = 0x32,
       REG_HAPTIC_SIMPLE = 0x97, REG_HAPTIC_FREQ = 0xA0, REG_BATTERY_TEST = 0xA1 };
enum { NTF_BATTERY = 0x00, NTF_IMU = 0x01, NTF_STICK = 0x02, NTF_TRIGGERS = 0x03, NTF_BUTTONS = 0x04,
       NTF_TOUCH = 0x09, NTF_LED_ECHO = 0x0B, NTF_PRESSURE = 0x15 };

static const uint8_t kSeekChannels[3] = PULSAR_SEEK_CHANNELS;

static void barrier(void) { __sync_synchronize(); }

static void note(ctrl_t* c, uint8_t kind, uint8_t a, uint8_t b, uint32_t v) {
    uint32_t head = c->note_head, next = (head + 1) % CTRL_NOTES;
    if (next == c->note_tail) return;
    c->notes[head] = (ctrl_note_t){kind, a, b, v};
    barrier();
    c->note_head = next;
}

static void reg_set(ctrl_t* c, uint8_t reg, const void* data, uint8_t len) {
    if (reg >= CTRL_REGS) return;
    if (len > CTRL_REG_SIZE) len = CTRL_REG_SIZE;
    memcpy(c->regs[reg], data, len);
    c->reg_len[reg] = len;
}

// The controller's boot LED config {33333, 19, -9} (PERIPHERALS §2.2).
static void led_default(ctrl_t* c) {
    c->led_cfg[0] = 33333;
    c->led_cfg[1] = 19;
    c->led_cfg[2] = (uint32_t)-9;
}

void ctrl_init(ctrl_t* c, platform_t* plat) {
    memset(c, 0, sizeof(*c));
    c->plat = plat;
    c->fmt = &cl_placeholder;
}

void ctrl_start(ctrl_t* c, const uint8_t* body, uint32_t len) {
    uint8_t tag = len ? body[0] : 0;
    link_result_t r = {tag, CMD_FAKE_START, LINK_OK, 0};
    link_fake_start_t f;
    memset(&f, 0, sizeof f);
    if (len == sizeof f) memcpy(&f, body, sizeof f);
    if (len != sizeof f || f.slot >= PULSAR_SLOTS) {
        r.status = LINK_ERR_ARGS;
        c->plat->emit(c->plat, EVT_RESULT, &r, sizeof r, NULL, 0);
        return;
    }
    platform_t* plat = c->plat;
    ctrl_init(c, plat);
    c->flags = f.flags;
    c->device_id = f.device_id ? f.device_id : plat->device_id;
    c->want_slot = c->slot = f.slot;
    // registers the host may read (PROTOCOL Q4 ids): battery 3900 mV, the rest zero
    static const uint8_t battery[2] = {0x3c, 0x0f};
    reg_set(c, 0x15, battery, 2);
    static const uint8_t zero[12] = {0};
    reg_set(c, 0x09, zero, 2);
    reg_set(c, 0x03, zero, 3);
    reg_set(c, 0x04, zero, 1);
    reg_set(c, 0x0b, zero, 12);
    reg_set(c, 0x16, zero, 2);
    reg_set(c, 0x17, zero, 8);
    reg_set(c, 0x2b, zero, 1);
    // imu_config as tools/fake_dongle.py has it: accel +-32 g, gyro +-4000 dps, 500 Hz, 1/1024 g and
    // 1/8.192 dps per count
    static const uint8_t imu_cfg[16] = {0x00, 0x7d, 0xa0, 0x0f, 0xf4, 0x01, 0xf4, 0x01,
                                        0x00, 0x00, 0x80, 0x3a, 0x00, 0x00, 0xfa, 0x3d};
    reg_set(c, REG_IMU_CONFIG, imu_cfg, 16);
    // device_desc (R11): four NUL-padded 8-byte fields; the hand from the id's lowest bit
    uint8_t desc[32] = "oculus";
    memcpy(desc + 8, "rubyprq", 7);
    memcpy(desc + 16, (c->device_id & 1) ? "right" : "left", (c->device_id & 1) ? 5 : 4);
    memcpy(desc + 24, "0x0c", 4);
    reg_set(c, REG_DEVICE_DESC, desc, 32);
    led_default(c);
    if (f.flags & LINK_FAKE_PAIRED) {
        c->paired = true;
        c->netaddr = f.netaddr;
        memcpy(c->key, f.link_key, 16);
        c->state = CTRL_SEEKING;
    } else {
        plat->random(plat, c->priv, sizeof c->priv);
        x25519_base(c->pub, c->priv);  // ~70 ms, before the radio starts
        c->state = CTRL_ADVERTISING;
    }
    do plat->random(plat, c->iv, sizeof c->iv);  // a real controller's IV is never 0 (R16)
    while (!memcmp(c->iv, zero, 8));
    if (f.flags & LINK_FAKE_REAL_CONN) c->fmt = &cl_real;
    plat->emit(plat, EVT_RESULT, &r, sizeof r, NULL, 0);
    plat->kick(plat);
}

void ctrl_stop(ctrl_t* c) {
    c->plat->radio_halt(c->plat);
    c->state = CTRL_IDLE;
}

//------------------------------------------------------------------ radio (ISR)

static void dm_addr(radio_addr_t* a, uint8_t freq, uint32_t base) {
    memset(a, 0, sizeof(*a));
    a->profile = RADIO_PROFILE_DM;
    a->freq = freq;
    a->base0 = a->base1 = base;
    a->prefix[0] = a->prefix[7] = PULSAR_DISCOVERY_PREFIX;
    a->rx_mask = 1;
    a->tx_addr = 7;
}

static void link_addr(ctrl_t* c, radio_addr_t* a, uint8_t tx_slot) {
    memset(a, 0, sizeof(*a));
    a->profile = c->cur_dm ? RADIO_PROFILE_DM : RADIO_PROFILE_CONNECTED;
    a->freq = c->cur_dm ? PULSAR_DISCOVERY_MHZ : 0;  // caller sets the hop channel
    a->base0 = a->base1 = c->netaddr;
    a->prefix[1] = PULSAR_HOST_PREFIX;
    a->prefix[7] = (uint8_t)(tx_slot + 1);
    a->rx_mask = 1u << 1;
    a->tx_addr = 7;
}

// A seeking real controller requests in the negotiation slot; ours asks for want_slot in placeholder.
static uint8_t tx_slot(const ctrl_t* c) {
    if (c->accepted) return c->slot;
    return c->fmt->real ? PULSAR_NEG_SLOT : c->want_slot;
}

static void lost(ctrl_t* c, uint8_t reason) {
    c->state = CTRL_SEEKING;
    c->accepted = false;
    c->frag_len = 0;
    c->resp_pending = false;
    note(c, EVT_CONN, reason == LINK_REASON_TIMEOUT ? LINK_SLOT_LOST : LINK_SLOT_WAITING, c->slot, reason);
}

// Real: the notification chunk stream [chunks] (R0 rule 7) for one uplink, highest priority first. A
// fragmented chunk's first part goes last: a non-final fragment ends the host's chunk loop (R13).
static uint8_t real_chunks(ctrl_t* c, uint64_t now, uint64_t host_now, uint8_t* p) {
    uint8_t n = 0, b[18];
    if (c->frag_len) {  // the last fragment of the chunk started in the previous uplink
        uint16_t h = (uint16_t)((NTF_LED_ECHO & 0x1F) | c->frag_len << 5 | 1u << 12 | 0x8000);
        put16(p, h);
        memcpy(p + 2, c->frag, c->frag_len);
        n = (uint8_t)(2 + c->frag_len);
        c->frag_len = 0;
    }
    uint32_t ph = (uint32_t)(host_now / 1000 % 1000);
    uint16_t tri = (uint16_t)(ph < 500 ? ph * 8 : (1000 - ph) * 8);
    if (c->flags & LINK_FAKE_STREAM_IMU) {
        uint64_t ts = host_now - 100;  // u48 sample time on the sync clock
        for (int i = 0; i < 6; i++) b[i] = (uint8_t)(ts >> (8 * i));
        int16_t v[6] = {0, 0, 1024, (int16_t)(tri - 2000), 0, 0};  // 1 g at +-32 g / 16 bit
        for (int i = 0; i < 6; i++) put16(b + 6 + 2 * i, (uint16_t)v[i]);
        n = (uint8_t)(n + cl_ntf_pack(p + n, NTF_BUDGET - n, NTF_IMU, b, 18));
    }
    bool in = c->flags & LINK_FAKE_STREAM_INPUT;
    if (in) {
        b[0] = (uint8_t)((host_now / 1000000) & 1);
        n = (uint8_t)(n + cl_ntf_pack(p + n, NTF_BUDGET - n, NTF_BUTTONS, b, 1));
        put16(b, (uint16_t)(tri - 2000));
        put16(b + 2, 0);
        n = (uint8_t)(n + cl_ntf_pack(p + n, NTF_BUDGET - n, NTF_STICK, b, 4));
        uint32_t tg = tri | (uint32_t)(4000 - tri) << 12;
        b[0] = (uint8_t)tg, b[1] = (uint8_t)(tg >> 8), b[2] = (uint8_t)(tg >> 16);
        n = (uint8_t)(n + cl_ntf_pack(p + n, NTF_BUDGET - n, NTF_TRIGGERS, b, 3));
    }
    if (now >= c->echo_next_us && n + 2 + 8 <= NTF_BUDGET) {  // the 12-byte LED echo, split 8 + 4
        uint8_t e[12];
        for (int i = 0; i < 3; i++) put32(e + 4 * i, c->led_cfg[i]);
        put16(p + n, (uint16_t)((NTF_LED_ECHO & 0x1F) | 8u << 5));  // seq 0, not last
        memcpy(p + n + 2, e, 8);
        n = (uint8_t)(n + 10);
        memcpy(c->frag, e + 8, 4);
        c->frag_len = 4;
        c->echo_next_us = now + ECHO_PERIOD_US;
        return n;
    }
    if (in) {
        put16(b, 0x001);
        put16(b + 2, 0);
        n = (uint8_t)(n + cl_ntf_pack(p + n, NTF_BUDGET - n, NTF_TOUCH, b, 4));
        put16(b, 0x0ABC | 0xF000);  // pressure: 12 bits; the top nibble must be masked off
        n = (uint8_t)(n + cl_ntf_pack(p + n, NTF_BUDGET - n, NTF_PRESSURE, b, 2));
        b[0] = 87;
        n = (uint8_t)(n + cl_ntf_pack(p + n, NTF_BUDGET - n, NTF_BATTERY, b, 1));
    }
    return n;
}

static void build_uplink(ctrl_t* c, uint64_t now, radio_op_t* op) {
    cl_msg_t m;
    memset(&m, 0, sizeof m);
    m.ack = c->last_dl_seq;
    uint64_t host_now = c->beacon_ts + (now - c->anchor_us);  // sync clock, close enough
    uint8_t tl[NTF_BUDGET];
    if (!c->accepted) {
        m.type = CL_CONN_REQ;
        m.u.conn.device_id = c->device_id;
        m.u.conn.slot = c->want_slot;
        m.u.conn.version = PULSAR_VERSION;
        memcpy(m.u.conn.iv, c->iv, 8);
    } else if (c->fmt->real) {
        m.type = CL_TL_UP;
        m.u.tl.slot = c->slot;
        if (c->resp_pending) {  // a response: [reg][ack-seq | read | err][data]
            m.u.tl.reg = c->resp[0];
            m.u.tl.flags = c->resp[1];
            m.u.tl.n = (uint8_t)(c->resp_len - 2);
            m.u.tl.data = c->resp + 2;
            c->resp_pending = false;
        } else {  // a notification: [0x00][ack-seq | 0x40][chunks]
            m.u.tl.reg = TL_REG_NTF;
            m.u.tl.flags = (uint8_t)(TL_NTF | c->tl_seq);
            m.u.tl.n = real_chunks(c, now, host_now, tl);
            m.u.tl.data = tl;
        }
    } else if (c->reply_reg_pending) {
        m = c->reg_reply;
        m.ack = c->last_dl_seq;
        c->reply_reg_sent = true;
    } else {
        int due = -1;
        for (int i = 0; i < 4; i++)
            if (c->sub[i].period_ms && now >= c->sub[i].next_us) due = i;
        if (due >= 0) {
            uint8_t reg = c->sub[due].reg;
            c->sub[due].next_us = now + (uint64_t)c->sub[due].period_ms * 1000u;
            m.type = CL_REG_DATA;
            m.seq = ++c->ul_seq;
            m.u.reg.reg = reg;
            m.u.reg.kind = LINK_REG_NOTIFY;
            m.u.reg.len = reg < CTRL_REGS ? c->reg_len[reg] : 0;
            if (m.u.reg.len > CL_REG_DATA_MAX) m.u.reg.len = CL_REG_DATA_MAX;
            if (m.u.reg.len) memcpy(m.u.reg.data, c->regs[reg], m.u.reg.len);
        } else if (c->flags & (LINK_FAKE_STREAM_INPUT | LINK_FAKE_STREAM_IMU)) {
            // synthetic sample: a 1 Hz triangle on trigger / grip / stick, button 0 toggling each second
            cl_stream_t* s = &m.u.stream;
            m.type = CL_STREAM;
            s->seq = ++c->stream_seq;
            s->sample_us = (uint32_t)(host_now - 100);
            uint32_t ph = (uint32_t)(host_now / 1000 % 1000);
            uint16_t tri = (uint16_t)(ph < 500 ? ph * 8 : (1000 - ph) * 8);
            if (c->flags & LINK_FAKE_STREAM_INPUT) {
                s->buttons = (uint8_t)((host_now / 1000000) & 1);
                s->battery_pct = 87;
                s->touch = 0x001;
                s->stick[0] = (int16_t)(tri - 2000);
                s->stick[1] = 0;
                s->trigger = tri;
                s->grip = (uint16_t)(4000 - tri);
                s->pressure = 0;
            }
            if (c->flags & LINK_FAKE_STREAM_IMU) {
                s->accel[2] = 1024;  // 1 g at +-32 g / 16 bit
                s->gyro[0] = (int16_t)(tri - 2000);
                s->temp = 25 * 132;
            }
        } else {
            m.type = CL_IDLE;
        }
    }
    uint8_t pt[CL_UP_MAX], nonce[PULSAR_NONCE_LEN];
    int n = c->fmt->encode(&m, pt, sizeof pt);
    uint8_t s = tx_slot(c);
    if (n < 0) {  // nothing this format can say: one filler byte
        pt[0] = 0xFF;
        n = 1;
    }
    // uplink CCM (the only CCM on the connected link): legacy nonce until the accept, then the
    // steady one, its counter = beacon periods since the accept (R7)
    if (c->accepted) pulsar_nonce_steady((uint32_t)(c->period - c->accept_period), c->iv, nonce);
    else pulsar_nonce_legacy(c->session_nonce, c->beacon_ts, nonce);
    pulsar_nonce_dir(nonce, c->dir);
    c->plat->ccm(c->plat, true, c->key, nonce, pt, (uint8_t)n, op->payload);
    op->len = (uint8_t)(n + PULSAR_MIC_LEN);
    op->kind = RADIO_OP_TX;
    op->start_us = c->anchor_us + pulsar_slot_offset_us(s);
    link_addr(c, &op->addr, s);
    if (!c->cur_dm) op->addr.freq = pulsar_channel_mhz(pulsar_remap(c->hop.map, c->hop.unmapped));
    c->uplinks_sent++;
}

bool ctrl_next_op(ctrl_t* c, uint64_t now, radio_op_t* op) {
    switch (c->state) {
    case CTRL_ADVERTISING:
        if (c->reply_pending) {
            op->kind = RADIO_OP_TX;
            op->start_us = c->reply_at_us > now + TX_LEAD_US ? c->reply_at_us : now + TX_LEAD_US;
            dm_addr(&op->addr, PULSAR_PAIRING_MHZ, (uint32_t)c->device_id);
            op->len = c->reply_len;
            memcpy(op->payload, c->reply, c->reply_len);
            c->reply_pending = false;
            return true;
        }
        if (c->reset_at_us && now >= c->reset_at_us) {  // Reset: the SPL starts the app
            c->reset_at_us = 0;
            if (c->paired) {
                c->state = CTRL_SEEKING;
                note(c, EVT_CONN, LINK_SLOT_WAITING, 0, 0);
                return ctrl_next_op(c, now, op);
            }
        }
        if (!c->adv_rx_phase && !c->paired) {
            op->kind = RADIO_OP_TX;
            op->start_us = now + TX_LEAD_US;
            dm_addr(&op->addr, PULSAR_DISCOVERY_MHZ, PULSAR_DISCOVERY_BASE);
            op->len = pair_advert_build(c->device_id, 0x0301, op->payload);
            c->adv_rx_phase = true;
            return true;
        }
        op->kind = RADIO_OP_RX;
        op->start_us = now + 20;
        op->window_us = ADV_RX_WINDOW_US;
        op->rx_multi = false;
        dm_addr(&op->addr, PULSAR_PAIRING_MHZ, (uint32_t)c->device_id);
        c->adv_rx_phase = false;
        return true;
    case CTRL_SEEKING:  // one 75.25 ms dwell on each of logical channels 0, 17, 36 in turn (R10)
        op->kind = RADIO_OP_RX;
        op->start_us = now + 20;
        op->window_us = PULSAR_SEEK_DWELL_US;
        op->rx_multi = false;
        c->cur_dm = false;
        link_addr(c, &op->addr, 0);
        op->addr.freq = pulsar_channel_mhz(kSeekChannels[c->seek_idx % 3]);
        return true;
    case CTRL_FOLLOWING: {
        if (c->heard) {
            c->heard = false;
            build_uplink(c, now, op);
            if (op->start_us >= now + 40) return true;
            // too late for our slot this period (should not happen): skip the uplink
        }
        uint64_t next = c->period + 1;
        c->cur_dm = c->dm_period == next;
        uint8_t logical = pulsar_hop_next(&c->hop);
        uint32_t half = BEACON_WINDOW_US + (c->missed + 1) * 80u;  // 2 x 20 ppm x elapsed, both sides
        if (half > 460) half = 460;
        op->kind = RADIO_OP_RX;
        op->start_us = c->anchor_us + PULSAR_BEACON_PERIOD_US - half;
        op->window_us = 2 * half;
        op->rx_multi = false;
        link_addr(c, &op->addr, 0);
        if (!c->cur_dm) op->addr.freq = pulsar_channel_mhz(logical);
        return true;
    }
    default:
        return false;
    }
}

// A real TL write: what the controller's command handlers do with it. False = the handler failed.
static bool real_write(ctrl_t* c, uint8_t reg, const uint8_t* d, uint8_t n) {
    switch (reg) {
    case REG_LED_CONFIG: {
        if (n < 12) return false;
        uint32_t p = get32(d), ot = get32(d + 4);
        if (ot > LINK_LED_MAX_ON_US) ot = LINK_LED_MAX_ON_US;      // the clamp, then the validator
        if (ot > p || p > LED_MAX_PERIOD_US) return false;
        c->led_cfg[0] = p;
        c->led_cfg[1] = ot;
        c->led_cfg[2] = get32(d + 8);
        memset(&c->last_led, 0, sizeof c->last_led);
        c->last_led.type = CL_LED;
        c->last_led.u.led.mode = ot ? LINK_LED_STROBE : LINK_LED_OFF;
        c->last_led.u.led.period_us = p;
        c->last_led.u.led.on_us = ot;
        c->last_led.u.led.phase_us = (int32_t)c->led_cfg[2];
        note(c, EVT_TEXT, CL_LED, c->last_led.u.led.mode, p);
        return true;
    }
    case REG_HAPTIC_SIMPLE:
    case REG_HAPTIC_FREQ:
        if (n < (reg == REG_HAPTIC_FREQ ? 3 : 1)) return false;
        if (reg == REG_HAPTIC_FREQ) {
            uint16_t f = (uint16_t)(d[1] | d[2] << 8);
            if (f < 40 || f > 561) return false;
            c->haptic_freq = f;
        }
        c->haptic_amp = d[0];
        memset(&c->last_haptic, 0, sizeof c->last_haptic);
        c->last_haptic.type = CL_HAPTIC;
        c->last_haptic.u.haptic.mode = d[0] ? LINK_HAPTIC_SIMPLE : LINK_HAPTIC_STOP;
        c->last_haptic.u.haptic.amplitude = d[0];
        c->last_haptic.u.haptic.freq_hz = c->haptic_freq;
        note(c, EVT_TEXT, CL_HAPTIC, c->last_haptic.u.haptic.mode, d[0]);
        return true;
    case REG_DATA_READY:
        c->data_ready = true;
        return true;
    case REG_BATTERY_TEST:
        c->a1_writes++;
        return true;
    default:
        if (reg >= CTRL_REGS) return false;
        reg_set(c, reg, d, n);
        return true;
    }
}

// A real TL packet addressed to us (R0): duplicate filter, then the read or write handler.
static void real_downlink(ctrl_t* c, const cl_msg_t* m) {
    uint8_t reg = m->u.tl.reg, fl = m->u.tl.flags, seq = fl & TL_SEQ_MASK;
    bool read = fl & TL_READ;
    if (c->tl_seen && seq == c->tl_seq && reg == c->tl_reg && (c->tl_flags & TL_READ) == (fl & TL_READ)) {
        c->dup_commands++;  // a retransmit: the last response again, the command is not run again
        if (c->resp_len) c->resp_pending = true;
        return;
    }
    c->tl_seen = true;
    c->tl_seq = seq;
    c->tl_reg = reg;
    c->tl_flags = fl;
    c->resp_len = 0;
    if (read) {
        uint8_t n = reg < CTRL_REGS ? c->reg_len[reg] : 0;
        c->resp[0] = reg;
        c->resp[1] = (uint8_t)(seq | TL_READ | (n ? 0 : TL_ERR));
        if (n) memcpy(c->resp + 2, c->regs[reg], n);
        c->resp_len = (uint8_t)(2 + n);
    } else if (!real_write(c, reg, m->u.tl.data, m->u.tl.n)) {
        c->resp[0] = reg;  // a failed write is answered; a good one is acked by the next uplink's seq
        c->resp[1] = (uint8_t)(seq | TL_ERR);
        c->resp_len = 2;
    }
    c->resp_pending = c->resp_len != 0;
}

static void on_downlink(ctrl_t* c, const cl_msg_t* m) {
    if (m->type == CL_CONN_ACCEPT) {
        if (m->u.conn.device_id != c->device_id) return;
        if (c->fmt->real && m->u.conn.slot == PULSAR_NEG_SLOT) {  // "accept_pkt->endpoint != CONN_NEG_SLOT"
            c->fatal_accepts++;
            return;
        }
        if (m->u.conn.slot >= PULSAR_SLOTS) return;
        if (!c->accepted) {
            note(c, EVT_CONN, LINK_SLOT_CONNECTED, m->u.conn.slot, 0);
            c->accept_period = c->period;  // the steady counter is 0 in this period (R7)
            c->resp_pending = false;
            c->frag_len = 0;
            led_default(c);
        }
        c->accepted = true;
        c->slot = m->u.conn.slot;
        c->last_dl_seq = m->seq;
        return;
    }
    if (m->type == CL_CONN_REJECT && !c->accepted) {  // back to idle: a new IV, seek again
        c->plat->random(c->plat, c->iv, sizeof c->iv);
        return;
    }
    if (m->type == CL_TL_DOWN) {
        if (c->accepted) real_downlink(c, m);
        return;
    }
    if (!c->accepted || m->seq == c->last_dl_seq) return;  // duplicate (our ack was lost)
    c->last_dl_seq = m->seq;
    switch (m->type) {
    case CL_DISCONNECT:
        lost(c, LINK_REASON_REQUESTED);
        break;
    case CL_REG_READ:
    case CL_REG_WRITE: {
        cl_msg_t* r = &c->reg_reply;
        uint8_t reg = m->u.reg.reg;
        memset(r, 0, sizeof *r);
        r->type = CL_REG_DATA;
        r->seq = ++c->ul_seq;
        r->u.reg.tag = m->u.reg.tag;
        r->u.reg.reg = reg;
        if (reg >= CTRL_REGS) {
            r->u.reg.status = LINK_ERR_REJECTED;
        } else if (m->type == CL_REG_READ) {
            r->u.reg.kind = LINK_REG_READ;
            uint8_t n = c->reg_len[reg];
            if (m->u.reg.len && m->u.reg.len < n) n = m->u.reg.len;
            if (n > CL_REG_DATA_MAX) n = CL_REG_DATA_MAX;
            r->u.reg.len = n;
            memcpy(r->u.reg.data, c->regs[reg], n);
        } else {
            r->u.reg.kind = LINK_REG_WRITE_ACK;
            reg_set(c, reg, m->u.reg.data, m->u.reg.len);
        }
        c->reply_reg_pending = true;
        c->reply_reg_sent = false;
        break;
    }
    case CL_REG_SUB: {
        int free_i = -1, hit = -1;
        for (int i = 0; i < 4; i++) {
            if (c->sub[i].period_ms && c->sub[i].reg == m->u.sub.reg) hit = i;
            if (!c->sub[i].period_ms && free_i < 0) free_i = i;
        }
        int i = hit >= 0 ? hit : free_i;
        if (i < 0) break;
        if (m->u.sub.flags & LINK_SUB_UNSUBSCRIBE) {
            c->sub[i].period_ms = 0;
        } else {
            c->sub[i].reg = m->u.sub.reg;
            c->sub[i].period_ms = m->u.sub.period_ms ? m->u.sub.period_ms : 10;  // "on change": poll at 100 Hz
            c->sub[i].next_us = 0;
        }
        break;
    }
    case CL_LED:
        c->last_led = *m;
        note(c, EVT_TEXT, CL_LED, m->u.led.mode, m->u.led.period_us);
        break;
    case CL_HAPTIC:
        c->last_haptic = *m;
        c->haptic_bytes += m->u.haptic.n;
        note(c, EVT_TEXT, CL_HAPTIC, m->u.haptic.mode, m->u.haptic.n);
        break;
    default:
        break;
    }
}

static void on_beacon(ctrl_t* c, const radio_rx_t* rx, const pulsar_beacon_t* b) {
    c->anchor_us = rx->t_us;
    c->beacon_ts = b->timestamp_us;
    c->period = b->timestamp_us / PULSAR_BEACON_PERIOD_US;
    c->hop.map = b->map;
    c->hop.unmapped = b->unmapped;
    c->session_nonce = b->session_nonce;
    if (b->dm_in) c->dm_period = c->period + b->dm_in;
    c->missed = 0;
    c->heard = true;
    c->beacons_heard++;
    if (c->reply_reg_sent) {  // the ack bitmap covers what we sent last period
        if (b->ack_mask & PULSAR_SLOT_BIT(tx_slot(c))) c->reply_reg_pending = false;
        c->reply_reg_sent = false;
    }
    if (rx->len <= PULSAR_BEACON_HDR_LEN) return;
    const uint8_t* cl = rx->payload + PULSAR_BEACON_HDR_LEN;
    int n = rx->len - PULSAR_BEACON_HDR_LEN;
    bool mine = b->cl_slot_mask & PULSAR_SLOT_BIT(tx_slot(c));
    cl_msg_t m;  // downlink CL data is plaintext (AUDIT A4)
    if (c->fmt->real) {
        // addressed to us, or to nobody (byte 14 = 0: the broadcast handler, R4); TL only when addressed
        if (!c->accepted && (mine || !b->cl_slot_mask) && c->fmt->decode(cl, n, CL_DIR_DOWN, &m)) on_downlink(c, &m);
        else if (c->accepted && mine && c->fmt->decode(cl, n, CL_DIR_DOWN_TL, &m)) on_downlink(c, &m);
    } else if (mine && c->fmt->decode(cl, n, CL_DIR_DOWN, &m)) {
        on_downlink(c, &m);
    }
}

static void spl_reply(ctrl_t* c, const radio_rx_t* rx, uint8_t status, uint8_t seq, const uint8_t* data, uint8_t n) {
    c->reply[0] = status;
    c->reply[1] = seq;
    if (n) memcpy(c->reply + 2, data, n);
    c->reply_len = (uint8_t)(2 + n);
    c->reply_at_us = rx->t_us + pulsar_airtime_us(0, rx->len) + REPLY_TURNAROUND_US;
    c->reply_pending = true;
}

// The SPL's DM-link dispatcher (R5): a repeated seq is a retransmit, anything else runs.
static void spl_on_rx(ctrl_t* c, const radio_rx_t* rx) {
    uint8_t cmd = rx->payload[0], seq = rx->payload[1];
    if (seq == c->spl_last_seq) {
        if (c->reply_len) {
            c->reply_at_us = rx->t_us + pulsar_airtime_us(0, rx->len) + REPLY_TURNAROUND_US;
            c->reply_pending = true;
        }
        return;
    }
    if (c->pair_data_pending) return;  // still unwrapping a PairingData: busy
    c->spl_last_seq = seq;
    c->reply_len = 0;
    if (cmd == PAIR_CMD_SETUP_X25519 && rx->len >= 2 + 32) {
        // TODO: a real SPL draws a new key pair on every 0x25 (R15); ours keeps one (~70 ms each)
        memcpy(c->host_pub, rx->payload + 2, 32);
        c->shared_ready = false;
        c->shared_wanted = true;
        note(c, EVT_PAIR, LINK_PAIR_KEY_EXCHANGE, 0, 0);
        spl_reply(c, rx, SPL_STATUS, seq, c->pub, 32);
    } else if (cmd == PAIR_CMD_PAIRING_DATA && rx->len >= 2 + PAIR_DATA_LEN) {
        if (!c->shared_ready) {  // no key exchange since the last failure: the keys are zero (R15)
            spl_reply(c, rx, SPL_STATUS | PAIR_STATUS_FAILED, seq, NULL, 0);
            return;
        }
        memcpy(c->pair_data, rx->payload + 2, PAIR_DATA_LEN);
        c->pair_data_seq = seq;
        barrier();
        c->pair_data_pending = true;  // the main loop unwraps it and builds the reply; we answer the retry
    } else if (cmd == PAIR_CMD_RESET) {
        spl_reply(c, rx, SPL_STATUS, seq, NULL, 0);
        c->reset_at_us = rx->t_us + SPL_RESET_DELAY_US;
    } else {
        spl_reply(c, rx, SPL_STATUS | PAIR_STATUS_FAILED, seq, NULL, 0);
    }
}

void ctrl_on_rx(ctrl_t* c, const radio_rx_t* rx) {
    if (!rx->crc_ok) return;
    if (c->state == CTRL_ADVERTISING && rx->freq == PULSAR_PAIRING_MHZ && rx->len >= 2) {
        spl_on_rx(c, rx);
        return;
    }
    if (rx->rxmatch != 1) return;
    pulsar_beacon_t b;
    if (!pulsar_beacon_parse(rx->payload, rx->len, &b)) return;
    if (c->state == CTRL_SEEKING) {
        c->state = CTRL_FOLLOWING;
        c->accepted = false;
        c->dm_period = 0;
        c->hop.hop = pulsar_hop_increment(c->netaddr);
        note(c, EVT_CONN, LINK_SLOT_NEGOTIATING, c->want_slot, 0);
    }
    if (c->state == CTRL_FOLLOWING) on_beacon(c, rx, &b);
}

void ctrl_on_done(ctrl_t* c, const radio_op_t* op, uint64_t now) {
    (void)now;
    if (c->state == CTRL_SEEKING && op->kind == RADIO_OP_RX) c->seek_idx++;  // nothing here: next channel
    if (c->state != CTRL_FOLLOWING || op->kind != RADIO_OP_RX || c->heard) return;
    // missed this period's beacon: dead-reckon to the next one (no uplink without a beacon)
    c->anchor_us += PULSAR_BEACON_PERIOD_US;
    c->period++;
    c->beacon_ts += PULSAR_BEACON_PERIOD_US;
    if (++c->missed >= CTRL_LOST_PERIODS) lost(c, LINK_REASON_TIMEOUT);  // > 24 missed (R9)
}

//------------------------------------------------------------------ main loop

void ctrl_poll(ctrl_t* c) {
    if (c->shared_wanted) {
        uint8_t hp[32];
        memcpy(hp, c->host_pub, 32);  // the ISR may replace it meanwhile; then we go again
        c->shared_wanted = false;
        x25519(c->shared, c->priv, hp);
        barrier();
        c->shared_ready = !c->shared_wanted;
    }
    if (c->pair_data_pending) {
        uint32_t netaddr;
        uint8_t key[16];
        bool ok = !c->fail_pair_data && pair_data_parse(c->shared, c->pair_data, &netaddr, key);
        if (c->fail_pair_data) c->fail_pair_data--;
        if (ok) {
            c->netaddr = netaddr;
            memcpy(c->key, key, 16);
            c->paired = true;
            c->pair_done = true;
            note(c, EVT_PAIR, LINK_PAIR_DONE, 0, netaddr);
        } else {  // R15: state 5, keys wiped; only a new 0x25 helps
            memset(c->shared, 0, sizeof c->shared);
            c->shared_ready = false;
            note(c, EVT_PAIR, LINK_PAIR_FAILED, LINK_ERR_CRYPTO, 0);
        }
        c->reply[0] = (uint8_t)(SPL_STATUS | (ok ? 0 : PAIR_STATUS_FAILED));
        c->reply[1] = c->pair_data_seq;
        barrier();
        c->reply_len = 2;  // sent when the host polls again with the same seq
        c->pair_data_pending = false;
    }
    while (c->note_tail != c->note_head) {
        barrier();
        ctrl_note_t n = c->notes[c->note_tail];
        c->note_tail = (c->note_tail + 1) % CTRL_NOTES;
        uint64_t now = c->plat->now_us(c->plat);
        if (n.kind == EVT_PAIR) {
            link_pair_event_t e = {now, n.a, n.a == LINK_PAIR_FAILED ? n.b : 0, 0, 0, c->device_id,
                                   n.a == LINK_PAIR_DONE ? n.v : 0};
            c->plat->emit(c->plat, EVT_PAIR, &e, sizeof e, NULL, 0);
        } else if (n.kind == EVT_CONN) {
            link_conn_event_t e = {now, n.b, n.a, (uint8_t)n.v, 0, c->device_id, PULSAR_VERSION, 0};
            c->plat->emit(c->plat, EVT_CONN, &e, sizeof e, NULL, 0);
        } else {
            char buf[64];
            snprintf(buf, sizeof buf, "fake: %s mode %u, %lu", n.a == CL_LED ? "LED" : "haptic", n.b,
                     (unsigned long)n.v);
            c->plat->emit(c->plat, EVT_TEXT, buf, strlen(buf), NULL, 0);
        }
    }
}
