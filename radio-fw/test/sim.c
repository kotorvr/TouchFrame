// Loopback simulator: host_core (the dongle as Pulsar host) and ctrl_core (the fake Touch Plus)
// talking over a simulated 2 Mbit air, 1 us steps, each node on its own drifting clock, with
// optional packet loss and outages. Commands go in through the same host_command / ctrl_start
// the firmware's USB link calls; the link-v3 events that come out are checked.
//
// This exercises everything above the RADIO peripheral: beacon scheduling, CSA#1 hop following,
// slot timing, DM beacons, the real 0x12/0x11 pairing exchange, CCM on every packet, placeholder
// CL negotiation / registers / LED / haptics / streams, retransmission and link loss.
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto.h"
#include "../src/ctrl_core.h"
#include "../src/host_core.h"

static int failures;
#define CHECK(c, ...)                                                   \
    do {                                                                \
        if (!(c)) {                                                     \
            printf("FAIL %s:%d: %s: ", __FILE__, __LINE__, #c);         \
            printf(__VA_ARGS__);                                        \
            printf("\n");                                               \
            failures++;                                                 \
        }                                                               \
    } while (0)

//------------------------------------------------------------------ nodes

typedef struct {
    uint8_t type;
    uint16_t len;
    double t;
    uint8_t body[320];
} ev_t;

typedef struct node {
    platform_t plat;
    const char* name;
    bool is_host;
    host_t* host;
    ctrl_t* ctrl;
    double offset_us, ppm;
    uint64_t rng;
    // radio
    bool need_op, has_op, tx_started;
    radio_op_t op;
    double op_start, op_end;  // sim time
    uint32_t late_ops;
    // events
    ev_t* ev;
    size_t nev, cap;
} node_t;

static double T;  // sim time, us
static double loss;
static bool outage;
static uint64_t loss_rng = 0x9E3779B97F4A7C15ull;

static uint64_t xorshift(uint64_t* s) {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

static double local_of(const node_t* n, double t) { return n->offset_us + t * (1 + n->ppm * 1e-6); }
static double sim_of(const node_t* n, double local) { return (local - n->offset_us) / (1 + n->ppm * 1e-6); }

static uint64_t p_now(platform_t* p) { return (uint64_t)local_of((node_t*)p->user, T); }
static void p_random(platform_t* p, uint8_t* out, size_t n) {
    node_t* nd = p->user;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)xorshift(&nd->rng);
}
static bool p_ccm(platform_t* p, bool enc, const uint8_t key[16], const uint8_t nonce[13], const uint8_t* in,
                  uint8_t len, uint8_t* out) {
    (void)p;
    if (enc) {
        pulsar_ccm_encrypt(key, nonce, 0, in, len, out);
        return true;
    }
    return pulsar_ccm_decrypt(key, nonce, 0, in, len, out);
}
static void p_emit(platform_t* p, uint8_t evt, const void* body, size_t len, const void* tail, size_t tail_len) {
    node_t* n = p->user;
    if (n->nev == n->cap) {
        n->cap = n->cap ? n->cap * 2 : 1024;
        n->ev = realloc(n->ev, n->cap * sizeof(ev_t));
    }
    ev_t* e = &n->ev[n->nev++];
    assert(len + tail_len <= sizeof e->body);
    e->type = evt;
    e->len = (uint16_t)(len + tail_len);
    e->t = T;
    memcpy(e->body, body, len);
    if (tail_len) memcpy(e->body + len, tail, tail_len);
}
static void p_kick(platform_t* p) { ((node_t*)p->user)->need_op = true; }
static void p_halt(platform_t* p) {
    node_t* n = p->user;
    n->has_op = false;
    n->need_op = false;
}

static void node_init(node_t* n, const char* name, bool is_host, double offset, double ppm, uint64_t id) {
    memset(n, 0, sizeof(*n));
    n->name = name;
    n->is_host = is_host;
    n->offset_us = offset;
    n->ppm = ppm;
    n->rng = id * 2654435761u + 1;
    n->plat = (platform_t){p_now, p_random, p_ccm, p_emit, p_kick, p_halt, id, 0, 0, n};
    if (is_host) {
        n->host = calloc(1, sizeof(host_t));
        host_init(n->host, &n->plat);
    } else {
        n->ctrl = calloc(1, sizeof(ctrl_t));
        ctrl_init(n->ctrl, &n->plat);
    }
}

static bool next_op(node_t* n, uint64_t now, radio_op_t* op) {
    return n->is_host ? host_next_op(n->host, now, op) : ctrl_next_op(n->ctrl, now, op);
}
static void on_rx(node_t* n, const radio_rx_t* rx) {
    if (n->is_host) host_on_rx(n->host, rx);
    else ctrl_on_rx(n->ctrl, rx);
}
static void on_done(node_t* n) {
    uint64_t now = (uint64_t)local_of(n, T);
    if (n->is_host) host_on_done(n->host, &n->op, now);
    else ctrl_on_done(n->ctrl, &n->op, now);
    n->has_op = false;
    n->need_op = true;
}
static void poll(node_t* n) {
    if (n->is_host) host_poll(n->host);
    else ctrl_poll(n->ctrl);
}

//------------------------------------------------------------------ air

typedef struct {
    bool live;
    node_t* from;
    double start, end;  // ADDRESS time, END time (sim)
    radio_op_t op;      // copy of the TX op
} air_t;

static air_t air[4];

static uint32_t tx_base(const radio_addr_t* a) { return a->tx_addr ? a->base1 : a->base0; }

static int rx_match(const radio_addr_t* rx, const radio_addr_t* tx) {
    uint32_t base = tx_base(tx);
    uint8_t prefix = tx->prefix[tx->tx_addr];
    for (int l = 0; l < 8; l++) {
        if (!(rx->rx_mask & (1u << l))) continue;
        if ((l ? rx->base1 : rx->base0) == base && rx->prefix[l] == prefix) return l;
    }
    return -1;
}

static void step(node_t** nodes, int nn) {
    for (int i = 0; i < nn; i++) {
        node_t* n = nodes[i];
        if (n->need_op && !n->has_op) {
            n->need_op = false;
            if (next_op(n, (uint64_t)local_of(n, T), &n->op)) {
                n->has_op = true;
                n->tx_started = false;
                n->op_start = sim_of(n, (double)n->op.start_us);
                if (n->op_start < T) {
                    n->late_ops++;
                    n->op_start = T;
                }
                n->op_end = n->op.kind == RADIO_OP_RX ? n->op_start + n->op.window_us / (1 + n->ppm * 1e-6)
                                                      : n->op_start + pulsar_airtime_us(n->op.addr.profile ? 0 : 1,
                                                                                         n->op.len) - 24;
            }
        }
    }
    // transmissions start
    for (int i = 0; i < nn; i++) {
        node_t* n = nodes[i];
        if (n->has_op && n->op.kind == RADIO_OP_TX && !n->tx_started && T >= n->op_start) {
            n->tx_started = true;
            for (int k = 0; k < 4; k++) {
                if (air[k].live) continue;
                air[k] = (air_t){true, n, n->op_start, n->op_end, n->op};
                break;
            }
        }
    }
    // packets end: deliver to whoever was listening at the ADDRESS time
    for (int k = 0; k < 4; k++) {
        air_t* a = &air[k];
        if (!a->live || T < a->end) continue;
        a->live = false;
        bool lost = outage || (loss > 0 && (double)(xorshift(&loss_rng) % 1000000) / 1e6 < loss);
        for (int i = 0; i < nn && !lost; i++) {
            node_t* r = nodes[i];
            if (r == a->from || !r->has_op || r->op.kind != RADIO_OP_RX) continue;
            if (r->op.addr.freq != a->op.addr.freq || r->op.addr.profile != a->op.addr.profile) continue;
            if (a->start < r->op_start || a->start > r->op_end) continue;
            int l = rx_match(&r->op.addr, &a->op.addr);
            if (l < 0) continue;
            radio_rx_t rx = {(uint64_t)local_of(r, a->start), a->op.addr.freq, a->op.addr.profile, (uint8_t)l, -45,
                             true, a->op.len, a->op.payload};
            on_rx(r, &rx);
            if (!r->op.rx_multi) on_done(r);
        }
        if (a->from->has_op && a->from->op.kind == RADIO_OP_TX) on_done(a->from);
    }
    // RX windows close (a packet still in flight to this node completes first: nRF behaviour)
    for (int i = 0; i < nn; i++) {
        node_t* n = nodes[i];
        if (!n->has_op || n->op.kind != RADIO_OP_RX || T < n->op_end) continue;
        bool busy = false;
        for (int k = 0; k < 4; k++)
            if (air[k].live && air[k].from != n && air[k].start <= n->op_end && air[k].op.addr.freq == n->op.addr.freq)
                busy = true;
        if (!busy) on_done(n);
    }
}

static node_t H, C;
static node_t* nodes[2] = {&H, &C};

static void run(double us) {
    double end = T + us;
    for (; T < end; T += 1) {
        step(nodes, 2);
        if ((uint64_t)T % 50 == 0) {
            poll(&H);
            poll(&C);
        }
    }
}

//------------------------------------------------------------------ helpers

static uint8_t tag_n = 1;

static link_result_t host_cmd(uint8_t cmd, const void* body, size_t len) {
    size_t before = H.nev;
    assert(host_command(H.host, cmd, body, (uint32_t)len));
    for (size_t i = before; i < H.nev; i++)
        if (H.ev[i].type == EVT_RESULT) {
            link_result_t r;
            memcpy(&r, H.ev[i].body, sizeof r);
            if (r.cmd == cmd) return r;
        }
    link_result_t none = {0, cmd, 0xFF, 0};
    return none;
}

#define HOST_CMD(cmd, type, ...)                         \
    ({                                                   \
        type _c = {.tag = tag_n++, __VA_ARGS__};         \
        host_cmd(cmd, &_c, sizeof _c);                   \
    })

static size_t count(node_t* n, uint8_t type, size_t from) {
    size_t k = 0;
    for (size_t i = from; i < n->nev; i++) k += n->ev[i].type == type;
    return k;
}

// last event of `type` (from index `from`) whose byte at `off` equals `val` (off < 0: any)
static ev_t* find(node_t* n, uint8_t type, size_t from, int off, uint8_t val) {
    ev_t* hit = NULL;
    for (size_t i = from; i < n->nev; i++)
        if (n->ev[i].type == type && (off < 0 || n->ev[i].body[off] == val)) hit = &n->ev[i];
    return hit;
}

static void print_texts(node_t* n, size_t from) {
    for (size_t i = from; i < n->nev; i++)
        if (n->ev[i].type == EVT_TEXT) printf("  %s text: %.*s\n", n->name, n->ev[i].len, n->ev[i].body);
}

static const uint8_t KEY[16] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 1, 2, 3, 4, 5, 6, 7, 8};
#define NETADDR 0x5EED1234u
#define FAKE_ID 0x1122334455667788ull

static link_result_t start_host(uint8_t flags) {
    link_host_start_t s = {.tag = tag_n++, .flags = flags, .session_nonce = 0xBEEF, .netaddr = NETADDR,
                           .chmap = {0xff, 0xff, 0xff, 0xff, 0x1f}, .tx_power_dbm = 0};
    memcpy(s.link_key, KEY, 16);
    return host_cmd(CMD_HOST_START, &s, sizeof s);
}

static void start_fake(uint8_t flags, uint8_t slot) {
    link_fake_start_t f = {.tag = tag_n++, .flags = flags, .slot = slot, .device_id = 0, .netaddr = NETADDR};
    memcpy(f.link_key, KEY, 16);
    size_t before = C.nev;
    ctrl_start(C.ctrl, (const uint8_t*)&f, sizeof f);
    ev_t* r = find(&C, EVT_RESULT, before, -1, 0);
    CHECK(r && r->body[2] == LINK_OK, "fake start");
}

//------------------------------------------------------------------ scenarios

static void scenario_pair_connect_stream(void) {
    printf("scenario: pair, connect, stream, registers, LED, haptics, drift %+.0f/%+.0f ppm\n", H.ppm, C.ppm);
    link_result_t r = start_host(LINK_HOST_DM_BEACONS | LINK_HOST_PLACEHOLDER);
    CHECK(r.status == LINK_OK, "host start %u", r.status);
    start_fake(LINK_FAKE_STREAM_INPUT | LINK_FAKE_STREAM_IMU, 2);
    run(20000);
    CHECK(H.host->beacons >= 9, "beacons %u", H.host->beacons);

    // pairing (real 0x12 / 0x11 formats)
    size_t mark = H.nev;
    r = HOST_CMD(CMD_PAIR_START, link_pair_start_t, .flags = LINK_PAIR_AUTO, .timeout_s = 10);
    CHECK(r.status == LINK_OK, "pair start");
    for (int i = 0; i < 300 && !find(&H, EVT_PAIR, mark, 8, LINK_PAIR_DONE); i++) run(10000);
    ev_t* done = find(&H, EVT_PAIR, mark, 8, LINK_PAIR_DONE);
    CHECK(done, "pairing did not finish");
    CHECK(count(&H, EVT_ADVERT, mark) >= 1, "no advert event");
    link_pair_event_t pe;
    if (done) {
        memcpy(&pe, done->body, sizeof pe);
        CHECK(pe.device_id == FAKE_ID && pe.netaddr == NETADDR, "pair event id %llx", (unsigned long long)pe.device_id);
    }
    CHECK(C.ctrl->paired && C.ctrl->netaddr == NETADDR && !memcmp(C.ctrl->key, KEY, 16), "fake not provisioned");
    CHECK(find(&C, EVT_PAIR, 0, 8, LINK_PAIR_DONE), "fake did not report pairing");

    // connect: slot 1 on the host, although the fake asks for 2
    mark = H.nev;
    r = HOST_CMD(CMD_CONNECT, link_connect_t, .slot = 1, .device_id = FAKE_ID);
    CHECK(r.status == LINK_OK && r.detail == 1, "connect %u/%u", r.status, r.detail);
    for (int i = 0; i < 200 && !find(&H, EVT_CONN, mark, 9, LINK_SLOT_CONNECTED); i++) run(10000);
    CHECK(find(&H, EVT_CONN, mark, 9, LINK_SLOT_NEGOTIATING), "never negotiating");
    CHECK(find(&H, EVT_CONN, mark, 9, LINK_SLOT_CONNECTED), "never connected");
    CHECK(C.ctrl->accepted && C.ctrl->slot == 1, "fake slot %u", C.ctrl->slot);

    // streams for one second
    size_t s0 = H.nev;
    run(1000000);
    size_t n_in = count(&H, EVT_INPUT, s0), n_imu = count(&H, EVT_IMU, s0);
    CHECK(n_in > 400 && n_imu == n_in, "input %zu imu %zu per second", n_in, n_imu);
    uint16_t last = 0;
    int gaps = 0;
    uint64_t prev_t = 0;
    for (size_t i = s0; i < H.nev; i++) {
        if (H.ev[i].type != EVT_INPUT) continue;
        link_input_t in;
        memcpy(&in, H.ev[i].body, sizeof in);
        if (last && in.seq != (uint16_t)(last + 1)) gaps++;
        last = in.seq;
        CHECK(in.slot == 1 && (in.flags & 1), "input slot/flags");
        CHECK(in.t_us > prev_t, "input time not increasing");
        uint64_t host_now = (uint64_t)local_of(&H, H.ev[i].t);
        CHECK(in.t_us <= host_now && host_now - in.t_us < 3000, "sample time %llu vs now %llu",
              (unsigned long long)in.t_us, (unsigned long long)host_now);
        prev_t = in.t_us;
    }
    CHECK(gaps == 0, "%d input seq gaps", gaps);

    // registers
    mark = H.nev;
    r = HOST_CMD(CMD_REG_READ, link_reg_cmd_t, .slot = 1, .reg = 0x15);
    CHECK(r.status == LINK_OK, "reg read %u", r.status);
    run(30000);
    ev_t* reg = find(&H, EVT_REG, mark, 10, 0x15);
    CHECK(reg && reg->body[11] == LINK_REG_READ && reg->body[12] == LINK_OK && reg->body[13] == 2 &&
              reg->body[14] == 0x3c && reg->body[15] == 0x0f, "reg 0x15 read");
    CHECK(reg && reg->body[8] == r.tag, "reg tag");
    struct { link_reg_cmd_t c; uint8_t d[3]; } w = {{tag_n++, 1, 0x30, 3}, {7, 8, 9}};
    mark = H.nev;
    r = host_cmd(CMD_REG_WRITE, &w, sizeof w);
    CHECK(r.status == LINK_OK, "reg write");
    run(30000);
    CHECK(find(&H, EVT_REG, mark, 11, LINK_REG_WRITE_ACK), "no write ack");
    CHECK(C.ctrl->reg_len[0x30] == 3 && C.ctrl->regs[0x30][2] == 9, "write not applied");
    mark = H.nev;
    r = HOST_CMD(CMD_REG_SUBSCRIBE, link_reg_sub_t, .slot = 1, .reg = 0x30, .period_ms = 20);
    CHECK(r.status == LINK_OK, "subscribe");
    run(200000);
    size_t notes = 0;
    for (size_t i = mark; i < H.nev; i++) notes += H.ev[i].type == EVT_REG && H.ev[i].body[11] == LINK_REG_NOTIFY;
    CHECK(notes >= 7 && notes <= 11, "%zu notifications in 200 ms at 20 ms", notes);
    HOST_CMD(CMD_REG_SUBSCRIBE, link_reg_sub_t, .slot = 1, .reg = 0x30, .flags = LINK_SUB_UNSUBSCRIBE);
    run(50000);
    mark = H.nev;
    run(100000);
    notes = 0;
    for (size_t i = mark; i < H.nev; i++) notes += H.ev[i].type == EVT_REG && H.ev[i].body[11] == LINK_REG_NOTIFY;
    CHECK(notes == 0, "%zu notifications after unsubscribe", notes);
    r = HOST_CMD(CMD_REG_READ, link_reg_cmd_t, .slot = 3, .reg = 9);
    CHECK(r.status == LINK_ERR_NOT_CONNECTED, "read on empty slot: %u", r.status);
    struct { link_reg_cmd_t c; uint8_t d[1]; } bad = {{tag_n++, 1, 0x30, 3}, {1}};
    r = host_cmd(CMD_REG_WRITE, &bad, sizeof bad);
    CHECK(r.status == LINK_ERR_ARGS, "short write: %u", r.status);

    // LED + haptics
    r = HOST_CMD(CMD_LED, link_led_t, .slot = 1, .mode = LINK_LED_STROBE, .intensity = 200, .period_us = 11111,
                 .on_us = 80, .phase_us = -500, .led_mask = 0);
    CHECK(r.status == LINK_OK, "led");
    r = HOST_CMD(CMD_LED, link_led_t, .slot = 1, .mode = LINK_LED_STROBE, .period_us = 100, .on_us = 200);
    CHECK(r.status == LINK_ERR_ARGS, "bad strobe accepted");
    struct { link_haptic_t h; uint8_t pcm[48]; } hp = {{tag_n++, 1, LINK_HAPTIC_PCM, 255, 2000, 0, 48, 0}, {0}};
    for (int i = 0; i < 48; i++) hp.pcm[i] = (uint8_t)(i * 5);
    r = host_cmd(CMD_HAPTIC, &hp, sizeof hp);
    CHECK(r.status == LINK_OK, "haptic pcm %u", r.status);
    run(60000);
    CHECK(C.ctrl->last_led.u.led.period_us == 11111 && C.ctrl->last_led.u.led.phase_us == -500, "LED not applied");
    CHECK(C.ctrl->haptic_bytes == 48, "haptic bytes %u", C.ctrl->haptic_bytes);
    CHECK(C.ctrl->last_haptic.u.haptic.pcm[47 - 42] == (uint8_t)(47 * 5), "haptic pcm content");

    // status
    mark = H.nev;
    r = HOST_CMD(CMD_HOST_STATUS, link_tag_t);
    ev_t* st = find(&H, EVT_HOST_STATUS, mark, -1, 0);
    CHECK(st, "no status");
    if (st) {
        link_host_status_t s;
        memcpy(&s, st->body, sizeof s);
        CHECK(s.slot[1].state == LINK_SLOT_CONNECTED && s.slot[1].device_id == FAKE_ID, "status slot");
        CHECK(s.slot[1].rx_bad_mic == 0, "bad MICs %u", s.slot[1].rx_bad_mic);
        CHECK(s.dm_beacons > 0 && s.beacons > 500, "beacons %u dm %u", s.beacons, s.dm_beacons);
    }
    CHECK(H.late_ops == 0 && C.late_ops == 0, "late radio ops host %u fake %u", H.late_ops, C.late_ops);
}

static void scenario_loss_and_outage(void) {
    printf("scenario: 10%% packet loss, then a 0.6 s outage and reconnect\n");
    loss = 0.10;
    size_t mark = H.nev;
    size_t before = count(&H, EVT_INPUT, 0);
    link_result_t r = HOST_CMD(CMD_REG_READ, link_reg_cmd_t, .slot = 1, .reg = 0x30);
    CHECK(r.status == LINK_OK, "read under loss");
    run(500000);
    CHECK(find(&H, EVT_REG, mark, 10, 0x30), "reg read lost under 10%% loss");
    size_t got = count(&H, EVT_INPUT, 0) - before;
    CHECK(got > 150 && got < 250, "%zu inputs in 0.5 s at 10%% loss", got);
    CHECK(!find(&H, EVT_CONN, mark, 9, LINK_SLOT_LOST), "lost the link at 10%% loss");

    loss = 0;
    outage = true;
    mark = H.nev;
    size_t cmark = C.nev;
    run(600000);
    outage = false;
    CHECK(find(&H, EVT_CONN, mark, 9, LINK_SLOT_LOST), "host never noticed the outage");
    CHECK(find(&C, EVT_CONN, cmark, 9, LINK_SLOT_LOST), "fake never noticed the outage");
    for (int i = 0; i < 100 && !find(&H, EVT_CONN, mark, 9, LINK_SLOT_CONNECTED); i++) run(10000);
    CHECK(find(&H, EVT_CONN, mark, 9, LINK_SLOT_CONNECTED), "no reconnect after the outage");
}

static void scenario_disconnect_forget(void) {
    printf("scenario: disconnect + forget, the controller is then refused\n");
    size_t mark = H.nev;
    link_result_t r = HOST_CMD(CMD_DISCONNECT, link_disconnect_t, .slot = 1, .flags = 1);
    CHECK(r.status == LINK_OK, "disconnect");
    run(300000);
    CHECK(find(&H, EVT_CONN, mark, 9, LINK_SLOT_FREE), "slot not freed");
    CHECK(!find(&H, EVT_CONN, mark, 9, LINK_SLOT_CONNECTED), "reconnected although forgotten");
    bool refused = false;
    for (size_t i = mark; i < H.nev; i++)
        if (H.ev[i].type == EVT_TEXT && strstr((const char*)H.ev[i].body, "not allowed")) refused = true;
    CHECK(refused, "no 'not allowed' note for the seeking controller");
    // allow it again (any slot) -> it comes back
    mark = H.nev;
    r = HOST_CMD(CMD_CONNECT, link_connect_t, .slot = 0xFF, .device_id = FAKE_ID);
    CHECK(r.status == LINK_OK, "reconnect");
    for (int i = 0; i < 100 && !find(&H, EVT_CONN, mark, 9, LINK_SLOT_CONNECTED); i++) run(10000);
    CHECK(find(&H, EVT_CONN, mark, 9, LINK_SLOT_CONNECTED), "did not come back");
}

static void scenario_real_formats(void) {
    printf("scenario: real formats (no placeholder): RE-pending answers, no connection\n");
    size_t mark = H.nev;
    link_result_t r = start_host(LINK_HOST_DM_BEACONS | LINK_HOST_RAW_UPLINKS);
    CHECK(r.status == LINK_OK, "restart");
    CHECK(find(&H, EVT_CONN, mark, 10, LINK_REASON_HOST_RESTART), "restart did not drop the connection");
    r = HOST_CMD(CMD_REG_READ, link_reg_cmd_t, .slot = 0, .reg = 9);
    CHECK(r.status == LINK_ERR_PENDING_RE, "real read: %u", r.status);
    r = HOST_CMD(CMD_LED, link_led_t, .slot = 0, .mode = LINK_LED_ON);
    CHECK(r.status == LINK_ERR_PENDING_RE, "real LED: %u", r.status);
    mark = H.nev;
    run(1500000);  // the fake loses the restarted hop, re-seeks and asks again: undecryptable here
    CHECK(!find(&H, EVT_CONN, mark, 9, LINK_SLOT_CONNECTED), "connected with unpinned formats");
    CHECK(count(&H, EVT_UPLINK, mark) > 0, "raw uplinks not reported");
    ev_t* u = find(&H, EVT_UPLINK, mark, -1, 0);
    CHECK(u && !(u->body[11] & LINK_UP_DECRYPTED), "real mode tried to decrypt");
}

static void scenario_bad_args(void) {
    printf("scenario: argument and state checks\n");
    link_host_start_t s = {.tag = tag_n++, .netaddr = 1, .chmap = {0x7f}};
    link_result_t r = host_cmd(CMD_HOST_START, &s, sizeof s);
    CHECK(r.status == LINK_ERR_ARGS, "7-channel map accepted");
    r = host_cmd(CMD_HOST_START, &s, 5);
    CHECK(r.status == LINK_ERR_ARGS, "short body accepted");
    r = HOST_CMD(CMD_CONNECT, link_connect_t, .slot = 7, .device_id = 5);
    CHECK(r.status == LINK_ERR_ARGS, "slot 7 accepted");
    r = HOST_CMD(CMD_PAIR_START, link_pair_start_t, .timeout_s = 1);
    CHECK(r.status == LINK_OK, "pair start");
    r = HOST_CMD(CMD_PAIR_START, link_pair_start_t, .timeout_s = 1);
    CHECK(r.status == LINK_ERR_BUSY, "second pair start: %u", r.status);
    size_t mark = H.nev;
    run(1100000);
    CHECK(find(&H, EVT_PAIR, mark, 8, LINK_PAIR_STOPPED), "scan timeout not reported");
    CHECK(H.host->beacons > 0 && H.host->pair_state == LINK_PAIR_IDLE, "beacons did not resume");
    uint32_t b0 = H.host->beacons;
    run(20000);
    CHECK(H.host->beacons >= b0 + 9, "beacons after pairing %u -> %u", b0, H.host->beacons);
    host_stop(H.host);
    r = HOST_CMD(CMD_HOST_STATUS, link_tag_t);
    CHECK(r.status == LINK_ERR_STATE, "status while stopped");
}

int main(int argc, char** argv) {
    double ppm_h = 15, ppm_c = -15;
    if (argc == 3) {
        ppm_h = atof(argv[1]);
        ppm_c = atof(argv[2]);
    }
    node_init(&H, "host", true, 123456789.0, ppm_h, 0xD0D0CAFE00000001ull);
    node_init(&C, "fake", false, 987654.0, ppm_c, FAKE_ID);
    T = 0;
    scenario_pair_connect_stream();
    scenario_loss_and_outage();
    scenario_disconnect_forget();
    scenario_real_formats();
    scenario_bad_args();
    if (failures) {
        print_texts(&H, 0);
        print_texts(&C, 0);
        printf("sim: %d failures\n", failures);
        return 1;
    }
    printf("sim: all scenarios passed (%.1f s simulated, host %u beacons sent)\n", T / 1e6, H.host->beacons);
    return 0;
}
