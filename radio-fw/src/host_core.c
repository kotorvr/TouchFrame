#include "host_core.h"

#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "pulsar_pair.h"

#define BEACON_RX_START_US 250     // listen for uplinks from here ...
#define BEACON_RX_END_US 1800      // ... to here (slot 4 starts at 1475), then retune for the next beacon
#define PAIR_SCAN_WINDOW_US 5000   // discovery RX chunk while scanning
#define PAIR_TX_LEAD_US 200
#define NEGOTIATE_TIMEOUT_US 1000000
#define FULL_MAP ((1ull << PULSAR_NUM_CHANNELS) - 1)

static void barrier(void) { __sync_synchronize(); }

//------------------------------------------------------------------ events

static void emit(host_t* h, uint8_t evt, const void* body, size_t len, const void* tail, size_t tail_len) {
    h->plat->emit(h->plat, evt, body, len, tail, tail_len);
}

static void result(host_t* h, uint8_t tag, uint8_t cmd, uint8_t status, uint8_t detail) {
    link_result_t r = {tag, cmd, status, detail};
    emit(h, EVT_RESULT, &r, sizeof r, NULL, 0);
}

static void text(host_t* h, const char* s) { emit(h, EVT_TEXT, s, strlen(s), NULL, 0); }

static void conn_event(host_t* h, uint8_t s, uint8_t state, uint8_t reason) {
    host_slot_t* sl = &h->slot[s];
    sl->state = state;
    link_conn_event_t e = {h->plat->now_us(h->plat), s, state, reason, sl->rssi, sl->device_id,
                           state == LINK_SLOT_CONNECTED || state == LINK_SLOT_NEGOTIATING ? sl->version : 0, 0};
    emit(h, EVT_CONN, &e, sizeof e, NULL, 0);
}

static void pair_event(host_t* h, uint8_t state, uint8_t status) {
    h->pair_state = state;
    link_pair_event_t e = {h->plat->now_us(h->plat), state, status, h->pair_step, 0,
                           state == LINK_PAIR_SCANNING ? 0 : h->pair_device,
                           state == LINK_PAIR_DONE ? h->netaddr : 0};
    emit(h, EVT_PAIR, &e, sizeof e, NULL, 0);
}

static void reg_event(host_t* h, uint64_t t, uint8_t tag, uint8_t s, uint8_t reg, uint8_t kind, uint8_t status,
                      const uint8_t* data, uint8_t len) {
    link_reg_event_t e = {t, tag, s, reg, kind, status, len};
    emit(h, EVT_REG, &e, sizeof e, data, len);
}

//------------------------------------------------------------------ lifecycle

void host_init(host_t* h, platform_t* plat) {
    memset(h, 0, sizeof(*h));
    h->plat = plat;
    h->fmt = &cl_real;
    for (int s = 0; s < PULSAR_SLOTS; s++) h->slot[s].next_dl_seq = 1;
}

bool host_running(const host_t* h) { return h->running; }

static bool pairing_active(const host_t* h) {
    return h->pair_state >= LINK_PAIR_SCANNING && h->pair_state <= LINK_PAIR_PROVISION;
}

static void dlq_clear(host_slot_t* sl) {
    sl->dlq_len = 0;
    sl->head_sent = false;
    sl->accept_queued = false;
}

// Every connected / negotiating slot goes back to WAITING (or FREE if it was never allowed).
static void drop_all(host_t* h, uint8_t reason) {
    for (uint8_t s = 0; s < PULSAR_SLOTS; s++) {
        host_slot_t* sl = &h->slot[s];
        dlq_clear(sl);
        sl->steady = false;  // the controller re-seeks and sends a new request
        if (sl->state == LINK_SLOT_NEGOTIATING || sl->state == LINK_SLOT_CONNECTED || sl->state == LINK_SLOT_LOST)
            conn_event(h, s, sl->allowed ? LINK_SLOT_WAITING : LINK_SLOT_FREE, reason);
    }
}

static void restart_beacons(host_t* h) {
    uint64_t now = h->plat->now_us(h->plat);
    h->next_beacon_us = (now / PULSAR_BEACON_PERIOD_US + 2) * PULSAR_BEACON_PERIOD_US;
    h->rx_phase = false;
    h->ack_mask = 0;
    h->prep.ready = false;
}

void host_stop(host_t* h) {
    if (!h->running) return;
    h->plat->radio_halt(h->plat);
    drop_all(h, LINK_REASON_REQUESTED);
    if (pairing_active(h)) pair_event(h, LINK_PAIR_STOPPED, LINK_OK);
    h->pair_state = LINK_PAIR_IDLE;
    h->running = false;
}

static bool stored(const host_t* h) { return (h->flags & LINK_HOST_STORED) && h->store && h->store->ok; }

static int find_allowed(const host_t* h, uint64_t device_id) {
    for (int s = 0; s < PULSAR_SLOTS; s++)
        if (h->slot[s].allowed && h->slot[s].device_id == device_id) return s;
    return -1;
}

static bool slot_free(const host_t* h, int s) {
    return PULSAR_SLOT_USABLE(s) && !h->slot[s].allowed && h->slot[s].state == LINK_SLOT_FREE;
}

// The slot for a controller: where it is already allowed, else `want` if free, else the first free
// one. -1 if none.
static int pick_slot(const host_t* h, uint64_t device_id, uint8_t want) {
    int s = find_allowed(h, device_id);
    if (s >= 0) return s;
    if (want < PULSAR_SLOTS && slot_free(h, want)) return want;
    for (int i = 0; i < PULSAR_SLOTS; i++)
        if (slot_free(h, i)) return i;
    return -1;
}

// CMD_CONNECT's effect: the controller may connect into slot s (which pick_slot chose).
static void allow(host_t* h, int s, uint64_t device_id) {
    host_slot_t* sl = &h->slot[s];
    if (sl->allowed && sl->device_id == device_id) return;
    sl->allowed = true;
    sl->device_id = device_id;
    sl->version = 0;
    dlq_clear(sl);
    conn_event(h, (uint8_t)s, LINK_SLOT_WAITING, LINK_REASON_NONE);
}

static void dl_push_disconnect(host_t* h, uint8_t s);

// CMD_DISCONNECT's effect; `forget` also frees the slot.
static void disconnect(host_t* h, uint8_t s, bool forget) {
    host_slot_t* sl = &h->slot[s];
    bool was = sl->state != LINK_SLOT_FREE || sl->allowed;
    dlq_clear(sl);
    if (sl->state == LINK_SLOT_CONNECTED && !h->fmt->real) dl_push_disconnect(h, s);  // best effort
    if (forget) sl->allowed = false;
    if (was) conn_event(h, s, sl->allowed ? LINK_SLOT_WAITING : LINK_SLOT_FREE, LINK_REASON_REQUESTED);
    if (!sl->allowed) sl->device_id = 0;
}

//------------------------------------------------------------------ radio callbacks (ISR)

static void addr_connected(host_t* h, radio_addr_t* a, uint8_t profile, uint8_t freq) {
    memset(a, 0, sizeof(*a));
    a->profile = profile;
    a->freq = freq;
    a->base0 = PULSAR_DISCOVERY_BASE;
    a->base1 = h->netaddr;
    a->prefix[0] = PULSAR_DISCOVERY_PREFIX;
    for (uint8_t s = 0; s < PULSAR_SLOTS; s++) a->prefix[1 + s] = (uint8_t)(s + 1);
    a->prefix[7] = PULSAR_HOST_PREFIX;
    a->tx_addr = 7;
    a->rx_mask = 0x3E;  // logical 1..5 = slots 0..4
}

static bool beacon_op(host_t* h, uint64_t now, radio_op_t* op) {
    if (!h->rx_phase) {
        // Late (e.g. after pairing or a long ISR stall): skip whole periods, keeping the hop count
        // in step with time the way a following controller dead-reckons.
        while (h->next_beacon_us < now + HOST_TX_LEAD_US) {
            h->next_beacon_us += PULSAR_BEACON_PERIOD_US;
            uint8_t ann;
            pulsar_dm_next(&h->dm, &ann);
            pulsar_hop_next(&h->hop);
            h->late_beacons++;
        }
        uint64_t period = h->next_beacon_us / PULSAR_BEACON_PERIOD_US;
        uint8_t announce;
        h->cur_dm = pulsar_dm_next(&h->dm, &announce) && (h->flags & LINK_HOST_DM_BEACONS);
        uint8_t logical = pulsar_hop_next(&h->hop);
        h->cur_freq = h->cur_dm ? PULSAR_DISCOVERY_MHZ : pulsar_channel_mhz(logical);
        if (!(h->flags & LINK_HOST_DM_BEACONS)) announce = 0;

        pulsar_beacon_t b = {h->hop.map, h->hop.unmapped, announce, h->session_nonce,
                             h->next_beacon_us & 0xFFFFFFFFFFFFull, 0, h->ack_mask};
        h->ack_mask = 0;
        op->kind = RADIO_OP_TX;
        op->start_us = h->next_beacon_us;
        addr_connected(h, &op->addr, h->cur_dm ? RADIO_PROFILE_DM : RADIO_PROFILE_CONNECTED, h->cur_freq);
        uint8_t n = pulsar_beacon_build(&b, op->payload);
        if (h->prep.ready) {
            barrier();
            if (h->prep.period == period) {
                op->payload[14] = PULSAR_SLOT_BIT(h->prep.slot);
                memcpy(op->payload + n, h->prep.data, h->prep.len);
                n = (uint8_t)(n + h->prep.len);
                h->prep.ready = false;
            } else if (h->prep.period < period) {
                h->prep.ready = false;  // missed its beacon; the main loop prepares it again
            }
        }
        op->len = n;
        h->beacons++;
        if (h->cur_dm) h->dm_beacons++;
        h->rx_phase = true;
        return true;
    }
    op->kind = RADIO_OP_RX;
    op->start_us = h->next_beacon_us + BEACON_RX_START_US;
    op->window_us = BEACON_RX_END_US - BEACON_RX_START_US;
    op->rx_multi = true;
    addr_connected(h, &op->addr, h->cur_dm ? RADIO_PROFILE_DM : RADIO_PROFILE_CONNECTED, h->cur_freq);
    if (h->cur_dm) op->addr.rx_mask |= 1;  // advertising controllers on AP0 during DM periods
    h->next_beacon_us += PULSAR_BEACON_PERIOD_US;
    h->rx_phase = false;
    return true;
}

static bool pair_op(host_t* h, uint64_t now, radio_op_t* op) {
    radio_addr_t* a = &op->addr;
    memset(a, 0, sizeof(*a));
    a->profile = RADIO_PROFILE_DM;
    if (h->pair_state == LINK_PAIR_SCANNING) {
        op->kind = RADIO_OP_RX;
        op->start_us = now + 50;
        op->window_us = PAIR_SCAN_WINDOW_US;
        op->rx_multi = true;
        a->freq = PULSAR_DISCOVERY_MHZ;
        a->base0 = PULSAR_DISCOVERY_BASE;
        a->prefix[0] = PULSAR_DISCOVERY_PREFIX;
        a->rx_mask = 1;
        return true;
    }
    if (!h->pair_tx_ready) return false;
    a->freq = PULSAR_PAIRING_MHZ;
    a->base0 = a->base1 = (uint32_t)h->pair_device;  // DM link base = device id low word
    a->prefix[0] = a->prefix[7] = PULSAR_DISCOVERY_PREFIX;
    a->rx_mask = 1;
    a->tx_addr = 7;
    if (!h->pair_rx_phase) {
        op->kind = RADIO_OP_TX;
        op->start_us = h->pair_tx_us = now + PAIR_TX_LEAD_US;
        op->len = h->pair_tx_len;
        memcpy(op->payload, h->pair_tx, h->pair_tx_len);
        h->pair_rx_phase = true;
    } else {
        uint32_t air = pulsar_airtime_us(0, h->pair_tx_len);
        op->kind = RADIO_OP_RX;
        op->start_us = h->pair_tx_us + air;
        op->window_us = PAIR_POLL_US - air;
        op->rx_multi = false;
        h->pair_rx_phase = false;
    }
    return true;
}

bool host_next_op(host_t* h, uint64_t now, radio_op_t* op) {
    if (!h->running) return false;
    if (pairing_active(h)) return pair_op(h, now, op);
    return beacon_op(h, now, op);
}

void host_on_rx(host_t* h, const radio_rx_t* rx) {
    if (rx->crc_ok && rx->rxmatch >= 1 && rx->rxmatch <= PULSAR_SLOTS && !pairing_active(h))
        h->ack_mask |= PULSAR_SLOT_BIT(rx->rxmatch - 1);
    if (pairing_active(h) && h->pair_state != LINK_PAIR_SCANNING && rx->crc_ok) h->pair_tx_ready = false;
    uint32_t head = h->ring_head, next = (head + 1) & (HOST_RX_RING - 1);
    if (next == h->ring_tail) {
        h->ring_overflow++;
        return;
    }
    host_rx_t* e = &h->ring[head];
    e->t_us = rx->t_us;
    e->freq = rx->freq;
    e->profile = rx->profile;
    e->rxmatch = rx->rxmatch;
    e->rssi = rx->rssi;
    e->crc_ok = rx->crc_ok;
    e->len = rx->len < sizeof(e->data) ? rx->len : (uint8_t)sizeof(e->data);
    memcpy(e->data, rx->payload, e->len);
    barrier();
    h->ring_head = next;
}

void host_on_done(host_t* h, const radio_op_t* op, uint64_t now) {
    (void)now;
    // A pairing poll that got no answer: count it; the next op re-sends the same frame.
    if (pairing_active(h) && op->kind == RADIO_OP_RX && op->addr.freq == PULSAR_PAIRING_MHZ && h->pair_tx_ready)
        h->pair_misses++;
}

//------------------------------------------------------------------ pairing (main loop)

static void pair_send(host_t* h, uint8_t cmd, const uint8_t* data, uint8_t len) {
    h->pair_cmd = cmd;
    h->pair_tx_len = pair_frame(cmd, h->pair_seq, data, len, h->pair_tx);
    h->pair_misses = 0;
    h->pair_rx_phase = false;
    barrier();
    h->pair_tx_ready = true;
    h->plat->kick(h->plat);
}

static void pair_finish(host_t* h, uint8_t state, uint8_t status) {
    h->plat->radio_halt(h->plat);
    h->pair_tx_ready = false;
    pair_event(h, state, status);
    memset(h->pair_priv, 0, sizeof h->pair_priv);
    memset(h->pair_shared, 0, sizeof h->pair_shared);
    h->pair_state = LINK_PAIR_IDLE;
    restart_beacons(h);
    h->plat->kick(h->plat);
}

static void pair_link(host_t* h, uint64_t device_id) {
    h->plat->radio_halt(h->plat);
    h->pair_device = device_id;
    h->pair_step = 0;
    pair_event(h, LINK_PAIR_LINKING, LINK_OK);
    // Our ephemeral X25519 key pair (~70 ms on the dongle; the radio is idle meanwhile).
    h->plat->random(h->plat, h->pair_priv, sizeof h->pair_priv);
    x25519_base(h->pair_pub, h->pair_priv);
    h->pair_seq = 1;
    pair_send(h, PAIR_CMD_SETUP_X25519, h->pair_pub, 32);
}

static void pair_on_advert(host_t* h, const host_rx_t* r) {
    pair_advert_t a;
    if (!r->crc_ok || !pair_advert_parse(r->data, r->len, &a)) return;
    link_advert_t e;
    memset(&e, 0, sizeof e);
    e.t_us = r->t_us;
    e.device_id = a.device_id;
    e.rssi = r->rssi;
    e.type = a.type;
    e.pulsar_version = a.pulsar_version;
    e.hw = a.hw;
    e.len = r->len < sizeof e.raw ? r->len : (uint8_t)sizeof e.raw;
    memcpy(e.raw, r->data, e.len);
    emit(h, EVT_ADVERT, &e, sizeof e, NULL, 0);
    if (h->pair_state == LINK_PAIR_SCANNING && (h->pair_flags & LINK_PAIR_AUTO) &&
        (!h->pair_filter || h->pair_filter == a.device_id))
        pair_link(h, a.device_id);
}

static void pair_on_reply(host_t* h, const host_rx_t* r) {
    if (!r->crc_ok || r->len < 2 || PAIR_CMD_NUM(r->data[0]) != PAIR_CMD_NUM(h->pair_cmd) ||
        r->data[1] != h->pair_seq) {
        h->pair_tx_ready = true;  // not ours: keep polling
        h->plat->kick(h->plat);
        return;
    }
    h->pair_step++;
    if (h->pair_cmd == PAIR_CMD_SETUP_X25519) {
        if (r->len < 2 + 32) {
            h->pair_tx_ready = true;
            h->plat->kick(h->plat);
            return;
        }
        pair_event(h, LINK_PAIR_KEY_EXCHANGE, LINK_OK);
        x25519(h->pair_shared, h->pair_priv, r->data + 2);
        uint8_t iv[8], payload[PAIR_DATA_LEN];
        h->plat->random(h->plat, iv, sizeof iv);
        pair_data_build(h->pair_shared, h->netaddr, h->key, iv, payload);
        h->pair_seq++;
        pair_event(h, LINK_PAIR_PROVISION, LINK_OK);
        pair_send(h, PAIR_CMD_PAIRING_DATA, payload, sizeof payload);
    } else if (h->pair_cmd == PAIR_CMD_PAIRING_DATA) {
        uint64_t id = h->pair_device;
        pair_finish(h, LINK_PAIR_DONE, LINK_OK);
        if (stored(h) && h->store->netaddr == h->netaddr) {  // saved, and allowed in a slot
            const store_pair_t* p = store_find(h->store, id);
            int s = pick_slot(h, id, p ? p->slot : 0xFF);
            if (!store_add_pair(h->store, id, (uint8_t)(s >= 0 ? s : 0), LINK_HAND_UNKNOWN))
                text(h, "pairing done but not stored: flash write failed");
            if (s >= 0) allow(h, s, id);
        }
    }
}

static void pair_poll(host_t* h) {
    if (!pairing_active(h)) return;
    uint64_t now = h->plat->now_us(h->plat);
    if (now > h->pair_deadline_us) {
        pair_finish(h, h->pair_state == LINK_PAIR_SCANNING ? LINK_PAIR_STOPPED : LINK_PAIR_FAILED, LINK_ERR_TIMEOUT);
    } else if (h->pair_state != LINK_PAIR_SCANNING && h->pair_misses > PAIR_MAX_MISSES) {
        pair_finish(h, LINK_PAIR_FAILED, LINK_ERR_TIMEOUT);
    }
}

//------------------------------------------------------------------ connected link (main loop)

static bool dl_push(host_t* h, uint8_t s, const cl_msg_t* m, uint8_t addr_slot) {
    host_slot_t* sl = &h->slot[s];
    if (sl->dlq_len >= HOST_DLQ) return false;
    host_dl_t* d = &sl->dlq[(sl->dlq_head + sl->dlq_len) % HOST_DLQ];
    d->msg = *m;
    d->msg.seq = sl->next_dl_seq;
    sl->next_dl_seq = (uint8_t)(sl->next_dl_seq % 255 + 1);
    d->addr_slot = addr_slot;
    sl->dlq_len++;
    return true;
}

static void dl_pop(host_slot_t* sl) {
    if (!sl->dlq_len) return;
    sl->dlq_head = (uint8_t)((sl->dlq_head + 1) % HOST_DLQ);
    sl->dlq_len--;
    sl->head_sent = false;
    sl->head_tries = 0;
}

// Fill h->prep with the next downlink, for the beacon two periods from now.
static void dl_prepare(host_t* h) {
    if (h->prep.ready || pairing_active(h)) return;
    uint64_t now = h->plat->now_us(h->plat);
    uint64_t period = now / PULSAR_BEACON_PERIOD_US + 2;
    for (uint8_t i = 0; i < PULSAR_SLOTS; i++) {
        uint8_t s = (uint8_t)((h->dl_rr + i) % PULSAR_SLOTS);
        host_slot_t* sl = &h->slot[s];
        if (!sl->dlq_len) continue;
        if (sl->head_sent && period < sl->head_sent_period + HOST_DL_RETRY_PERIODS) continue;
        host_dl_t* d = &sl->dlq[sl->dlq_head];
        if (h->fmt->real && sl->head_tries >= HOST_REAL_DL_REPEATS) {  // sent often enough
            dl_pop(sl);
            continue;
        }
        if (sl->head_tries >= HOST_DL_MAX_TRIES) {  // never acknowledged: give up on it
            if (d->msg.type == CL_REG_READ || d->msg.type == CL_REG_WRITE)
                reg_event(h, now, d->msg.u.reg.tag, s, d->msg.u.reg.reg,
                          d->msg.type == CL_REG_READ ? LINK_REG_READ : LINK_REG_WRITE_ACK, LINK_ERR_TIMEOUT, NULL, 0);
            if (d->msg.type == CL_CONN_ACCEPT) sl->accept_queued = false;
            dl_pop(sl);
            continue;
        }
        // downlink CL data is plaintext (docs/re/AUDIT.md A4)
        int n = h->fmt->encode(&d->msg, h->prep.data, PULSAR_BEACON_CL_MAX);
        if (n < 0) {
            dl_pop(sl);  // cannot be sent in this format (checked at enqueue; defensive)
            continue;
        }
        h->prep.len = (uint8_t)n;
        h->prep.slot = d->addr_slot;
        h->prep.period = period;
        sl->head_sent = true;
        sl->head_sent_period = period;
        sl->head_tries++;
        h->dl_rr = (uint8_t)(s + 1);
        barrier();
        h->prep.ready = true;
        return;
    }
}

static void dl_push_disconnect(host_t* h, uint8_t s) {
    cl_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = CL_DISCONNECT;
    m.u.conn.device_id = h->slot[s].device_id;
    dl_push(h, s, &m, s);
}

static void on_conn_req(host_t* h, uint8_t rx_slot, const cl_msg_t* m) {
    int s = find_allowed(h, m->u.conn.device_id);
    // auto-accept anyone (LINK_HOST_AUTO_ACCEPT), or a stored pairing that found no slot at start
    if (s < 0 && ((h->flags & LINK_HOST_AUTO_ACCEPT) || (stored(h) && store_find(h->store, m->u.conn.device_id)))) {
        s = pick_slot(h, m->u.conn.device_id, m->u.conn.slot < PULSAR_SLOTS ? m->u.conn.slot : rx_slot);
        if (s >= 0) {
            h->slot[s].allowed = true;
            h->slot[s].device_id = m->u.conn.device_id;
        }
    }
    if (s < 0) {
        uint64_t now = h->plat->now_us(h->plat);
        if (h->refused_id == m->u.conn.device_id && now - h->refused_us < 1000000) return;
        h->refused_id = m->u.conn.device_id;
        h->refused_us = now;
        char buf[96];
        snprintf(buf, sizeof buf, "controller %08lx%08lx seeking: not allowed (CMD_CONNECT it)",
                 (unsigned long)(m->u.conn.device_id >> 32), (unsigned long)m->u.conn.device_id);
        text(h, buf);
        return;
    }
    host_slot_t* sl = &h->slot[s];
    sl->version = m->u.conn.version;
    if (sl->accept_queued) return;
    if (sl->state != LINK_SLOT_NEGOTIATING) {
        dlq_clear(sl);
        sl->last_rx_us = h->plat->now_us(h->plat);  // negotiation timeout runs from here
        conn_event(h, (uint8_t)s, LINK_SLOT_NEGOTIATING, LINK_REASON_NONE);
    }
    cl_msg_t acc;
    memset(&acc, 0, sizeof acc);
    acc.type = CL_CONN_ACCEPT;
    acc.u.conn.device_id = sl->device_id;
    acc.u.conn.slot = (uint8_t)s;
    acc.u.conn.version = PULSAR_VERSION;  // never anything else (PROTOCOL Q6)
    if (h->fmt->real) {  // LINK.md §4: CONN_NEG, then LOCK
        acc.u.conn.endpoint = CL_EP_CONN_NEG;
        sl->accept_queued = dl_push(h, (uint8_t)s, &acc, rx_slot);
        acc.u.conn.endpoint = CL_EP_LOCK;
        sl->accept_queued = sl->accept_queued && dl_push(h, (uint8_t)s, &acc, rx_slot);
    } else {
        sl->accept_queued = dl_push(h, (uint8_t)s, &acc, rx_slot);
    }
    if (sl->accept_queued) {  // the controller restarts its counter when the accept arrives
        memcpy(sl->iv, m->u.conn.iv, 8);
        sl->ctr_period = h->plat->now_us(h->plat) / PULSAR_BEACON_PERIOD_US;
        sl->ctr = 0;
        sl->steady = true;
    }
}

static uint64_t unwrap32(uint64_t ref, uint32_t low) {
    // the 64-bit time with these low 32 bits closest to (and normally just before) ref
    uint64_t t = (ref & ~0xFFFFFFFFull) | low;
    if (t > ref + (1ull << 31)) t -= 1ull << 32;
    else if (ref > t + (1ull << 31)) t += 1ull << 32;
    return t;
}

static void on_stream(host_t* h, uint8_t s, const host_rx_t* r, const cl_msg_t* m) {
    host_slot_t* sl = &h->slot[s];
    if (sl->state != LINK_SLOT_CONNECTED) return;
    const cl_stream_t* st = &m->u.stream;
    uint8_t fl = h->fmt->real ? 0 : 1;
    uint64_t t = unwrap32(r->t_us, st->sample_us);
    link_input_t in = {t, s, fl, ++sl->input_seq, st->buttons, st->battery_pct, st->touch,
                       {st->stick[0], st->stick[1]}, st->trigger, st->grip, st->pressure};
    if (h->flags & LINK_HOST_COMPACT) {
        link_sample_t smp = {in, {st->accel[0], st->accel[1], st->accel[2]}, {st->gyro[0], st->gyro[1], st->gyro[2]}};
        smp.in.flags |= 4;
        emit(h, EVT_SAMPLE, &smp, sizeof smp, NULL, 0);
        return;
    }
    emit(h, EVT_INPUT, &in, sizeof in, NULL, 0);
    // TODO(RE-2): full scale from reg 0x32 imu_config; these are the ICM-42686 maxima as guesses.
    link_imu_t imu = {t, s, (uint8_t)(fl | 4), ++sl->imu_seq,
                      {st->accel[0], st->accel[1], st->accel[2]}, {st->gyro[0], st->gyro[1], st->gyro[2]},
                      st->temp, 16, 32, 4000, 0};
    emit(h, EVT_IMU, &imu, sizeof imu, NULL, 0);
}

static bool try_steady(host_t* h, host_slot_t* sl, const host_rx_t* r, uint32_t ctr, uint64_t period, uint8_t* pt) {
    uint8_t nonce[PULSAR_NONCE_LEN];
    pulsar_nonce_steady(ctr, sl->iv, nonce);
    pulsar_nonce_dir(nonce, h->ccm_dir);
    if (!h->plat->ccm(h->plat, false, h->key, nonce, r->data, r->len, pt)) return false;
    sl->ctr = ctr + 1;
    sl->ctr_period = period;
    return true;
}

// The steady nonce (after the accept) or the legacy nonce of this period's beacon (a request, or a
// controller that has not taken the accept yet); whichever the slot's state makes likelier goes
// first. Each try is a busy-waiting HW CCM pass, so the candidates are few: the next counters, and
// the counters the elapsed beacon periods predict (one uplink per period) for when uplinks were lost
// while the controller kept hearing us. 0 = no MIC matched, 1 = steady, 2 = legacy.
static int decrypt_uplink(host_t* h, host_slot_t* sl, const host_rx_t* r, uint8_t* pt) {
    uint64_t period = r->t_us / PULSAR_BEACON_PERIOD_US;
    bool legacy_first = sl->state != LINK_SLOT_CONNECTED && sl->state != LINK_SLOT_LOST;
    for (int pass = 0; pass < 2; pass++) {
        if ((pass == 0) == legacy_first) {
            uint8_t nonce[PULSAR_NONCE_LEN];
            for (uint8_t k = 0; k < 2; k++) {  // both CCM directions (AUDIT A17 vs pulsar_host)
                uint8_t dir = (uint8_t)(h->ccm_dir ^ k);
                pulsar_nonce_legacy(h->session_nonce, period * PULSAR_BEACON_PERIOD_US, nonce);
                pulsar_nonce_dir(nonce, dir);
                if (h->plat->ccm(h->plat, false, h->key, nonce, r->data, r->len, pt)) {
                    h->ccm_dir = dir;
                    return 2;
                }
            }
        } else if (sl->steady) {
            for (uint32_t i = 0; i < HOST_CTR_NEAR; i++)
                if (try_steady(h, sl, r, sl->ctr + i, period, pt)) return 1;
            uint32_t ahead = (uint32_t)(period > sl->ctr_period ? period - sl->ctr_period : 1);
            for (uint32_t i = 0; i <= HOST_CTR_BACK && ahead > i + HOST_CTR_NEAR; i++)
                if (try_steady(h, sl, r, sl->ctr + ahead - 1 - i, period, pt)) return 1;
            // the controller skips uplinks in periods it missed our beacon, so the counter can also be
            // anywhere in between: one probe per packet sweeps that gap
            if (ahead > HOST_CTR_NEAR + HOST_CTR_BACK + 1) {
                uint32_t span = ahead - HOST_CTR_NEAR - HOST_CTR_BACK - 1;
                sl->probe = sl->probe % span;
                if (try_steady(h, sl, r, sl->ctr + HOST_CTR_NEAR + sl->probe++, period, pt)) return 1;
            }
        }
    }
    return 0;
}

static void on_uplink(host_t* h, const host_rx_t* r) {
    uint8_t s = (uint8_t)(r->rxmatch - 1);
    host_slot_t* sl = &h->slot[s];
    uint8_t flags = r->crc_ok ? LINK_UP_CRC_OK : 0;
    uint8_t pt[PULSAR_UPLINK_MAX_LEN + 4];
    uint8_t n = 0;
    int how = 0;
    if (r->crc_ok) {
        h->uplinks++;
        sl->rx_packets++;
        sl->rssi = r->rssi;
        if (r->len > PULSAR_MIC_LEN) {
            flags |= LINK_UP_DECRYPTED;
            n = (uint8_t)(r->len - PULSAR_MIC_LEN);
            how = decrypt_uplink(h, sl, r, pt);
            if (how) flags |= LINK_UP_MIC_OK;
            else sl->rx_bad_mic++;
        }
    } else {
        h->crc_errors++;
    }
    bool ok = how != 0;
    if (h->flags & LINK_HOST_RAW_UPLINKS) {
        link_uplink_t u = {r->t_us, s, r->freq, r->rssi, flags, ok ? n : r->len};
        emit(h, EVT_UPLINK, &u, sizeof u, ok ? pt : r->data, ok ? n : r->len);
    }
    // The controller uses the steady nonce only after it took our accept: it is on the link.
    if (how == 1) {
        sl->last_rx_us = r->t_us;
        if (sl->allowed && (sl->state == LINK_SLOT_NEGOTIATING || sl->state == LINK_SLOT_LOST)) {
            sl->accept_queued = false;
            conn_event(h, s, LINK_SLOT_CONNECTED, LINK_REASON_NONE);
        }
    }
    cl_msg_t m;
    if (!ok || !h->fmt->decode(pt, n, CL_DIR_UP, &m)) return;
    sl->last_rx_us = r->t_us;
    if (sl->head_sent && sl->dlq_len && m.ack == sl->dlq[sl->dlq_head].msg.seq) dl_pop(sl);
    switch (m.type) {
    case CL_CONN_REQ:
        on_conn_req(h, s, &m);
        break;
    case CL_STREAM:
        on_stream(h, s, r, &m);
        break;
    case CL_REG_DATA:
        if (sl->state == LINK_SLOT_CONNECTED && m.seq != sl->last_ul_seq) {
            sl->last_ul_seq = m.seq;
            reg_event(h, r->t_us, m.u.reg.tag, s, m.u.reg.reg, m.u.reg.kind, m.u.reg.status, m.u.reg.data,
                      m.u.reg.len);
        }
        break;
    default:
        break;
    }
}

static void slot_timeouts(host_t* h) {
    uint64_t now = h->plat->now_us(h->plat);
    for (uint8_t s = 0; s < PULSAR_SLOTS; s++) {
        host_slot_t* sl = &h->slot[s];
        if (sl->state == LINK_SLOT_CONNECTED && now - sl->last_rx_us > HOST_LOST_US) {
            dlq_clear(sl);
            conn_event(h, s, LINK_SLOT_LOST, LINK_REASON_TIMEOUT);
        } else if (sl->state == LINK_SLOT_NEGOTIATING && now - sl->last_rx_us > NEGOTIATE_TIMEOUT_US) {
            dlq_clear(sl);
            conn_event(h, s, LINK_SLOT_WAITING, LINK_REASON_TIMEOUT);
        }
    }
}

void host_poll(host_t* h) {
    if (!h->running) return;
    while (h->ring_tail != h->ring_head) {
        barrier();
        const host_rx_t* r = &h->ring[h->ring_tail];
        if (pairing_active(h)) {
            if (r->freq == PULSAR_DISCOVERY_MHZ && r->rxmatch == 0) pair_on_advert(h, r);
            else if (r->freq == PULSAR_PAIRING_MHZ && h->pair_state != LINK_PAIR_SCANNING) pair_on_reply(h, r);
        } else if (r->rxmatch == 0) {
            if (r->crc_ok) pair_on_advert(h, r);  // an advertising controller heard in a DM period
        } else if (r->rxmatch <= PULSAR_SLOTS) {
            on_uplink(h, r);
        }
        h->ring_tail = (h->ring_tail + 1) & (HOST_RX_RING - 1);
    }
    pair_poll(h);
    if (!h->running) return;
    slot_timeouts(h);
    dl_prepare(h);
}

//------------------------------------------------------------------ commands (main loop)

static uint8_t host_start(host_t* h, const link_host_start_t* c, uint8_t* detail) {
    uint64_t map = 0;
    for (int i = 0; i < 5; i++) map |= (uint64_t)c->chmap[i] << (8 * i);
    map &= FULL_MAP;
    int count = 0;
    for (int i = 0; i < PULSAR_NUM_CHANNELS; i++) count += (int)((map >> i) & 1);
    if (count < 8 || c->tx_power_dbm < -40 || c->tx_power_dbm > 8) return LINK_ERR_ARGS;
    uint32_t netaddr = c->netaddr;
    const uint8_t* key = c->link_key;
    if (c->flags & LINK_HOST_STORED) {
        if (!h->store || !h->store->ok) return LINK_ERR_STATE;
        if (!h->store->netaddr) {  // first use: a random identity, kept from now on
            uint8_t k[16];
            do h->plat->random(h->plat, (uint8_t*)&netaddr, sizeof netaddr);
            while (netaddr == 0 || netaddr == 0xFFFFFFFFu);
            h->plat->random(h->plat, k, sizeof k);
            if (!store_set_identity(h->store, netaddr, k)) return LINK_ERR_CRYPTO;
        }
        netaddr = h->store->netaddr;
        key = h->store->key;
    }

    h->plat->radio_halt(h->plat);
    if (h->running) drop_all(h, LINK_REASON_HOST_RESTART);
    if (pairing_active(h)) pair_event(h, LINK_PAIR_STOPPED, LINK_OK);
    h->pair_state = LINK_PAIR_IDLE;
    h->flags = c->flags;
    h->fmt = (c->flags & LINK_HOST_PLACEHOLDER) ? &cl_placeholder : &cl_real;
    h->netaddr = netaddr;
    memcpy(h->key, key, 16);
    h->session_nonce = c->session_nonce;
    h->chmap = map;
    h->tx_power = c->tx_power_dbm;
    h->hop.map = map;
    h->hop.unmapped = 0;  // PROTOCOL Q1: host LL start, FUN_0001a85c
    h->hop.hop = pulsar_hop_increment(netaddr);
    pulsar_dm_init(&h->dm, netaddr);
    h->ring_tail = h->ring_head;
    for (int s = 0; s < PULSAR_SLOTS; s++) {
        dlq_clear(&h->slot[s]);
        h->slot[s].input_seq = h->slot[s].imu_seq = 0;
    }
    h->beacons = h->dm_beacons = h->uplinks = h->crc_errors = h->late_beacons = 0;
    h->running = true;
    restart_beacons(h);
    h->plat->kick(h->plat);
    *detail = 0;
    if (stored(h)) {  // newest pairings first, while slots last
        for (int i = h->store->npairs - 1; i >= 0; i--) {
            const store_pair_t* p = &h->store->pair[i];
            int s = pick_slot(h, p->device_id, p->slot);
            if (s < 0) break;
            allow(h, s, p->device_id);
            (*detail)++;
        }
    }
    return LINK_OK;
}

static void pair_list(host_t* h, uint8_t tag) {
    link_pairings_t hdr;
    link_pairing_t rec[LINK_MAX_PAIRINGS];
    memset(&hdr, 0, sizeof hdr);
    memset(rec, 0, sizeof rec);
    const store_t* st = h->store;
    if (st && st->ok) {
        hdr.netaddr = st->netaddr;
        hdr.count = st->npairs;
        hdr.flags = 1;
        hdr.writes_left = store_writes_left(st);
        for (uint8_t i = 0; i < st->npairs; i++)
            rec[i] = (link_pairing_t){st->pair[i].device_id, st->pair[i].slot, st->pair[i].hand, 0};
    }
    emit(h, EVT_PAIRINGS, &hdr, sizeof hdr, rec, hdr.count * sizeof rec[0]);
    result(h, tag, CMD_PAIR_LIST, LINK_OK, hdr.count);
}

static uint8_t pair_forget(host_t* h, const link_pair_forget_t* c, uint8_t* removed) {
    store_t* st = h->store;
    bool all = c->flags & (LINK_FORGET_ALL | LINK_FORGET_IDENTITY);
    if (!st || !st->ok) return LINK_ERR_STATE;
    if (!all && !c->device_id) return LINK_ERR_ARGS;
    // disconnect what is being forgotten (stored pairings only; CMD_CONNECTed ones are the driver's)
    if (h->running && (h->flags & LINK_HOST_STORED)) {
        for (uint8_t s = 0; s < PULSAR_SLOTS; s++) {
            uint64_t id = h->slot[s].device_id;
            if (h->slot[s].allowed && store_find(st, id) && (all || id == c->device_id)) disconnect(h, s, true);
        }
    }
    int n;
    if (c->flags & LINK_FORGET_IDENTITY) {
        n = st->npairs;
        if (!store_set_identity(st, 0, NULL)) n = -1;
    } else {
        n = all ? store_forget_all(st) : store_forget(st, c->device_id);
    }
    if (n < 0) return LINK_ERR_CRYPTO;
    *removed = (uint8_t)n;
    return LINK_OK;
}

void host_fill_status(const host_t* h, link_host_status_t* s) {
    memset(s, 0, sizeof(*s));
    s->version = LINK_VERSION;
    s->mode = h->running ? LINK_MODE_HOST : LINK_MODE_IDLE;
    s->host_flags = h->flags;
    s->pair_state = h->pair_state;
    s->now_us = h->plat->now_us(h->plat);
    s->netaddr = h->netaddr;
    s->beacons = h->beacons;
    s->dm_beacons = h->dm_beacons;
    s->uplinks = h->uplinks;
    s->crc_errors = h->crc_errors;
    s->late_beacons = h->late_beacons + h->plat->radio_late_ops;
    s->events_dropped = h->plat->events_dropped;
    s->channel_mhz = h->cur_freq;
    for (int i = 0; i < PULSAR_SLOTS; i++) {
        const host_slot_t* sl = &h->slot[i];
        link_slot_status_t* o = &s->slot[i];
        o->state = sl->state;
        o->rssi = sl->rssi;
        o->pulsar_version = sl->state == LINK_SLOT_CONNECTED ? sl->version : 0;
        o->device_id = sl->allowed || sl->state ? sl->device_id : 0;
        o->rx_packets = sl->rx_packets;
        o->rx_bad_mic = sl->rx_bad_mic;
        o->last_rx_us = sl->last_rx_us;
    }
}

// Common checks for the per-slot peripheral commands; LINK_OK if the message can be queued.
static uint8_t slot_check(host_t* h, uint8_t s) {
    if (!h->running) return LINK_ERR_STATE;
    if (s >= PULSAR_SLOTS) return LINK_ERR_ARGS;
    if (h->fmt->real) return LINK_ERR_PENDING_RE;  // TODO(RE-1/RE-2): real CL formats
    if (h->slot[s].state != LINK_SLOT_CONNECTED) return LINK_ERR_NOT_CONNECTED;
    return LINK_OK;
}

static uint8_t queue(host_t* h, uint8_t s, const cl_msg_t* m) {
    uint8_t probe[CL_DOWN_MAX];
    int n = h->fmt->encode(m, probe, sizeof probe);
    if (n == CL_PENDING_RE) return LINK_ERR_PENDING_RE;
    if (n < 0) return LINK_ERR_ARGS;
    return dl_push(h, s, m, s) ? LINK_OK : LINK_ERR_QUEUE_FULL;
}

// A newer message of the same type replaces one still waiting in the queue (not yet on air), so a
// fast LED phase loop never fills the queue with stale settings. False if there was none.
static bool replace_unsent(host_t* h, uint8_t s, const cl_msg_t* m) {
    host_slot_t* sl = &h->slot[s];
    for (uint8_t i = sl->head_sent ? 1 : 0; i < sl->dlq_len; i++) {
        host_dl_t* d = &sl->dlq[(sl->dlq_head + i) % HOST_DLQ];
        if (d->msg.type == m->type) {
            uint8_t seq = d->msg.seq;
            d->msg = *m;
            d->msg.seq = seq;
            return true;
        }
    }
    return false;
}

#define BODY(type) \
    if (len < sizeof(type)) { result(h, tag, cmd, LINK_ERR_ARGS, 0); return true; } \
    type c; memcpy(&c, body, sizeof c)

bool host_command(host_t* h, uint8_t cmd, const uint8_t* body, uint32_t len) {
    uint8_t tag = len ? body[0] : 0;
    switch (cmd) {
    case CMD_HOST_START: {
        if (len != sizeof(link_host_start_t)) { result(h, tag, cmd, LINK_ERR_ARGS, 0); return true; }
        link_host_start_t c;
        memcpy(&c, body, sizeof c);
        uint8_t detail = 0, st = host_start(h, &c, &detail);
        result(h, tag, cmd, st, detail);
        return true;
    }
    case CMD_PAIR_LIST:
        pair_list(h, tag);
        return true;
    case CMD_PAIR_FORGET: {
        BODY(link_pair_forget_t);
        uint8_t removed = 0, st = pair_forget(h, &c, &removed);
        result(h, tag, cmd, st, removed);
        return true;
    }
    case CMD_HOST_STATUS: {
        if (!h->running) { result(h, tag, cmd, LINK_ERR_STATE, 0); return true; }
        link_host_status_t s;
        host_fill_status(h, &s);
        emit(h, EVT_HOST_STATUS, &s, sizeof s, NULL, 0);
        result(h, tag, cmd, LINK_OK, 0);
        return true;
    }
    case CMD_PAIR_START: {
        BODY(link_pair_start_t);
        if (!h->running) { result(h, tag, cmd, LINK_ERR_STATE, 0); return true; }
        if (pairing_active(h)) { result(h, tag, cmd, LINK_ERR_BUSY, 0); return true; }
        // after LINK_FORGET_IDENTITY the running identity is no longer the stored one: restart first
        if (stored(h) && h->store->netaddr != h->netaddr) { result(h, tag, cmd, LINK_ERR_STATE, 0); return true; }
        h->plat->radio_halt(h->plat);
        drop_all(h, LINK_REASON_HOST_RESTART);  // beacons pause while pairing owns the radio
        h->pair_flags = c.flags;
        h->pair_filter = c.device_id;
        h->pair_step = 0;
        h->pair_device = 0;
        h->pair_tx_ready = false;
        h->pair_deadline_us = h->plat->now_us(h->plat) + (uint64_t)(c.timeout_s ? c.timeout_s : 60) * 1000000u;
        h->ring_tail = h->ring_head;
        result(h, tag, cmd, LINK_OK, 0);
        pair_event(h, LINK_PAIR_SCANNING, LINK_OK);
        // Without AUTO a known id can be paired directly (after a scan-only run reported it).
        if (!(c.flags & LINK_PAIR_AUTO) && c.device_id) pair_link(h, c.device_id);
        h->plat->kick(h->plat);
        return true;
    }
    case CMD_PAIR_STOP:
        if (pairing_active(h)) pair_finish(h, LINK_PAIR_STOPPED, LINK_OK);
        result(h, tag, cmd, LINK_OK, 0);
        return true;
    case CMD_CONNECT: {
        BODY(link_connect_t);
        if (!h->running) { result(h, tag, cmd, LINK_ERR_STATE, 0); return true; }
        int s = find_allowed(h, c.device_id);
        if (s < 0) {
            if (c.slot == 0xFF) {
                s = pick_slot(h, c.device_id, 0xFF);
                if (s < 0) { result(h, tag, cmd, LINK_ERR_NO_SLOT, 0); return true; }
            } else if (c.slot >= PULSAR_SLOTS) {
                result(h, tag, cmd, LINK_ERR_ARGS, 0);
                return true;
            } else if (!slot_free(h, c.slot)) {
                result(h, tag, cmd, LINK_ERR_NO_SLOT, c.slot);
                return true;
            } else {
                s = c.slot;
            }
            result(h, tag, cmd, LINK_OK, (uint8_t)s);
            allow(h, s, c.device_id);
        } else {
            result(h, tag, cmd, LINK_OK, (uint8_t)s);  // already allowed there
        }
        return true;
    }
    case CMD_DISCONNECT: {
        BODY(link_disconnect_t);
        if (!h->running) { result(h, tag, cmd, LINK_ERR_STATE, 0); return true; }
        if (c.slot >= PULSAR_SLOTS) { result(h, tag, cmd, LINK_ERR_ARGS, 0); return true; }
        result(h, tag, cmd, LINK_OK, c.slot);
        disconnect(h, c.slot, c.flags & 1);
        return true;
    }
    case CMD_REG_READ:
    case CMD_REG_WRITE: {
        BODY(link_reg_cmd_t);
        uint8_t st = slot_check(h, c.slot);
        if (cmd == CMD_REG_WRITE && (c.len > LINK_REG_MAX || len != sizeof c + c.len)) st = LINK_ERR_ARGS;
        if (st == LINK_OK) {
            cl_msg_t m;
            memset(&m, 0, sizeof m);
            m.type = cmd == CMD_REG_READ ? CL_REG_READ : CL_REG_WRITE;
            m.u.reg.tag = tag;
            m.u.reg.reg = c.reg;
            m.u.reg.len = c.len;
            if (cmd == CMD_REG_WRITE) memcpy(m.u.reg.data, body + sizeof c, c.len);
            st = queue(h, c.slot, &m);
        }
        result(h, tag, cmd, st, c.slot);
        return true;
    }
    case CMD_REG_SUBSCRIBE: {
        BODY(link_reg_sub_t);
        uint8_t st = slot_check(h, c.slot);
        if (st == LINK_OK) {
            cl_msg_t m;
            memset(&m, 0, sizeof m);
            m.type = CL_REG_SUB;
            m.u.sub.reg = c.reg;
            m.u.sub.flags = c.flags;
            m.u.sub.period_ms = c.period_ms;
            st = queue(h, c.slot, &m);
        }
        result(h, tag, cmd, st, c.slot);
        return true;
    }
    case CMD_LED: {
        BODY(link_led_t);
        uint8_t st = slot_check(h, c.slot);
        // docs/re/PERIPHERALS.md (RE-2): period >= 700 us, on-time clamped to 75 us by the controller
        if (c.mode > LINK_LED_STROBE || (c.mode == LINK_LED_STROBE && (c.period_us < LINK_LED_MIN_PERIOD_US || !c.on_us)))
            st = LINK_ERR_ARGS;
        if (c.on_us > LINK_LED_MAX_ON_US) c.on_us = LINK_LED_MAX_ON_US;
        if (st == LINK_OK) {
            cl_msg_t m;
            memset(&m, 0, sizeof m);
            m.type = CL_LED;
            m.u.led.mode = c.mode;
            m.u.led.intensity = c.intensity;
            m.u.led.period_us = c.period_us;
            m.u.led.on_us = c.on_us;
            m.u.led.phase_us = c.phase_us;
            m.u.led.mask = c.led_mask;
            if (!replace_unsent(h, c.slot, &m)) st = queue(h, c.slot, &m);
        }
        result(h, tag, cmd, st, c.slot);
        return true;
    }
    case CMD_HAPTIC: {
        BODY(link_haptic_t);
        uint8_t st = slot_check(h, c.slot);
        if (c.mode > LINK_HAPTIC_PCM || c.pcm_len > LINK_PCM_MAX || len != sizeof c + c.pcm_len ||
            (c.mode == LINK_HAPTIC_PCM && !c.pcm_len))
            st = LINK_ERR_ARGS;
        if (st == LINK_OK) {
            const uint8_t* pcm = body + sizeof c;
            uint8_t chunk = h->fmt->haptic_chunk;
            uint8_t parts = c.mode == LINK_HAPTIC_PCM ? (uint8_t)((c.pcm_len + chunk - 1) / chunk) : 1;
            if (HOST_DLQ - h->slot[c.slot].dlq_len < parts) st = LINK_ERR_QUEUE_FULL;
            for (uint8_t i = 0; st == LINK_OK && i < parts; i++) {
                cl_msg_t m;
                memset(&m, 0, sizeof m);
                m.type = CL_HAPTIC;
                m.u.haptic.mode = c.mode;
                m.u.haptic.amplitude = c.amplitude;
                m.u.haptic.freq_hz = c.freq_hz;
                m.u.haptic.duration_ms = c.duration_ms;
                if (c.mode == LINK_HAPTIC_PCM) {
                    uint8_t n = (uint8_t)(c.pcm_len - i * chunk < chunk ? c.pcm_len - i * chunk : chunk);
                    m.u.haptic.n = n;
                    memcpy(m.u.haptic.pcm, pcm + i * chunk, n);
                }
                st = queue(h, c.slot, &m);
            }
        }
        result(h, tag, cmd, st, c.slot);
        return true;
    }
    }
    return false;
}
