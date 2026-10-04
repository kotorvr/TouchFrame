#include "ctrl_core.h"

#include <stdio.h>
#include <string.h>

#include "crypto.h"

#define TX_LEAD_US 200
#define ADV_RX_WINDOW_US 8000    // after each advert, listen on the DM link this long
#define SEEK_WINDOW_US 10000
#define PAIR_GRACE_US 200000     // keep answering 0x11 retries this long after pairing
#define REPLY_TURNAROUND_US 150
#define BEACON_WINDOW_US 60      // +- around the expected beacon, plus drift growth

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
    c->session.netaddr = c->netaddr;
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

static uint8_t tx_slot(const ctrl_t* c) { return c->accepted ? c->slot : c->want_slot; }

static void build_uplink(ctrl_t* c, uint64_t now, radio_op_t* op) {
    cl_msg_t m;
    memset(&m, 0, sizeof m);
    m.ack = c->last_dl_seq;
    uint64_t host_now = c->beacon_ts + (now - c->anchor_us);  // sync clock, close enough
    if (!c->accepted) {
        m.type = CL_CONN_REQ;
        m.u.conn.device_id = c->device_id;
        m.u.conn.slot = c->want_slot;
        m.u.conn.version = PULSAR_VERSION;
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
            if (m.u.reg.len) memcpy(m.u.reg.data, c->regs[reg], m.u.reg.len);
        } else if (c->flags & (LINK_FAKE_STREAM_INPUT | LINK_FAKE_STREAM_IMU)) {
            // synthetic sample: a 1 Hz triangle on the analogs, button 0 toggling each second
            cl_stream_t* s = &m.u.stream;
            m.type = CL_STREAM;
            s->seq = ++c->stream_seq;
            s->sample_us = (uint32_t)(host_now - 100);
            uint32_t ph = (uint32_t)(host_now / 1000 % 1000);
            uint16_t tri = (uint16_t)(ph < 500 ? ph * 8 : (1000 - ph) * 8);
            if (c->flags & LINK_FAKE_STREAM_INPUT) {
                s->buttons = (uint16_t)((host_now / 1000000) & 1);
                s->analog[0] = tri;
                s->analog[1] = (uint16_t)(4000 - tri);
                s->analog[2] = s->analog[3] = 2048;
                s->touch = 0x01;
                s->battery = 3900;
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
    if (n < 0 || !c->fmt->nonce(&c->session, c->period, CL_DIR_UP, s, nonce)) n = 0;
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
        if (c->paired && now > c->paired_at_us + PAIR_GRACE_US) {
            c->state = CTRL_SEEKING;
            note(c, EVT_CONN, LINK_SLOT_WAITING, 0, 0);
            return ctrl_next_op(c, now, op);
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
    case CTRL_SEEKING:
        op->kind = RADIO_OP_RX;
        op->start_us = now + 20;
        op->window_us = SEEK_WINDOW_US;
        op->rx_multi = false;
        c->cur_dm = true;
        link_addr(c, &op->addr, 0);
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

static void on_downlink(ctrl_t* c, const cl_msg_t* m) {
    if (m->type == CL_CONN_ACCEPT) {
        if (m->u.conn.device_id != c->device_id || m->u.conn.slot >= PULSAR_SLOTS) return;
        if (!c->accepted) note(c, EVT_CONN, LINK_SLOT_CONNECTED, m->u.conn.slot, 0);
        c->accepted = true;
        c->slot = m->u.conn.slot;
        c->last_dl_seq = m->seq;
        return;
    }
    if (!c->accepted || m->seq == c->last_dl_seq) return;  // duplicate (our ack was lost)
    c->last_dl_seq = m->seq;
    switch (m->type) {
    case CL_DISCONNECT:
        c->accepted = false;
        c->state = CTRL_SEEKING;
        note(c, EVT_CONN, LINK_SLOT_WAITING, c->slot, LINK_REASON_REQUESTED);
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
    c->session.session_nonce = b->session_nonce;
    if (b->dm_in) c->dm_period = c->period + b->dm_in;
    c->missed = 0;
    c->heard = true;
    c->beacons_heard++;
    if (c->reply_reg_sent) {  // the ack bitmap covers what we sent last period
        if (b->ack_mask & (1u << tx_slot(c))) c->reply_reg_pending = false;
        c->reply_reg_sent = false;
    }
    uint8_t addressed = tx_slot(c);
    if (rx->len > PULSAR_BEACON_HDR_LEN + PULSAR_MIC_LEN && (b->cl_slot_mask & (1u << addressed))) {
        uint8_t nonce[PULSAR_NONCE_LEN], pt[PULSAR_BEACON_CL_MAX];
        uint8_t n = (uint8_t)(rx->len - PULSAR_BEACON_HDR_LEN);
        cl_msg_t m;
        if (c->fmt->nonce(&c->session, c->period, CL_DIR_DOWN, addressed, nonce) &&
            c->plat->ccm(c->plat, false, c->key, nonce, rx->payload + PULSAR_BEACON_HDR_LEN, n, pt) &&
            c->fmt->decode(pt, n - PULSAR_MIC_LEN, CL_DIR_DOWN, &m))
            on_downlink(c, &m);
    }
}

void ctrl_on_rx(ctrl_t* c, const radio_rx_t* rx) {
    if (!rx->crc_ok) return;
    if (c->state == CTRL_ADVERTISING && rx->freq == PULSAR_PAIRING_MHZ && rx->len >= 2) {
        uint8_t cmd = rx->payload[0], seq = rx->payload[1];
        if (cmd == PAIR_CMD_SETUP_X25519 && rx->len >= 2 + 32) {
            if (memcmp(c->host_pub, rx->payload + 2, 32)) {
                memcpy(c->host_pub, rx->payload + 2, 32);
                c->shared_ready = false;
                c->shared_wanted = true;
                note(c, EVT_PAIR, LINK_PAIR_KEY_EXCHANGE, 0, 0);
            }
            c->reply_len = pair_frame(PAIR_CMD_SETUP_X25519, seq, c->pub, 32, c->reply);
            c->reply_at_us = rx->t_us + pulsar_airtime_us(0, rx->len) + REPLY_TURNAROUND_US;
            c->reply_pending = true;
        } else if (cmd == PAIR_CMD_PAIRING_DATA && rx->len >= 2 + PAIR_DATA_LEN) {
            if (c->pair_done && seq == c->pair_done_seq) {
                static const uint8_t ok = 0;
                c->reply_len = pair_frame(PAIR_CMD_PAIRING_DATA, seq, &ok, 1, c->reply);
                c->reply_at_us = rx->t_us + pulsar_airtime_us(0, rx->len) + REPLY_TURNAROUND_US;
                c->reply_pending = true;
            } else if (c->shared_ready && !c->pair_data_pending && !c->pair_done) {
                memcpy(c->pair_data, rx->payload + 2, PAIR_DATA_LEN);
                c->pair_data_seq = seq;
                barrier();
                c->pair_data_pending = true;  // the main loop unwraps it; we answer the retry
            }
        }
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
    if (c->state != CTRL_FOLLOWING || op->kind != RADIO_OP_RX || c->heard) return;
    // missed this period's beacon: dead-reckon to the next one (no uplink without a beacon)
    c->anchor_us += PULSAR_BEACON_PERIOD_US;
    c->period++;
    c->beacon_ts += PULSAR_BEACON_PERIOD_US;
    if (++c->missed > CTRL_LOST_PERIODS) {
        c->state = CTRL_SEEKING;
        c->accepted = false;
        note(c, EVT_CONN, LINK_SLOT_LOST, c->slot, LINK_REASON_TIMEOUT);
    }
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
        if (pair_data_parse(c->shared, c->pair_data, &netaddr, key)) {
            c->netaddr = netaddr;
            memcpy(c->key, key, 16);
            c->session.netaddr = netaddr;
            c->paired_at_us = c->plat->now_us(c->plat);
            c->pair_done_seq = c->pair_data_seq;
            barrier();
            c->paired = true;
            c->pair_done = true;
            note(c, EVT_PAIR, LINK_PAIR_DONE, 0, netaddr);
        } else {
            note(c, EVT_PAIR, LINK_PAIR_FAILED, LINK_ERR_CRYPTO, 0);
        }
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
