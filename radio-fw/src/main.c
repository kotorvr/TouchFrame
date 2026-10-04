// TouchFrame radio dongle (nRF52840 Dongle, PCA10059) over USB (CDC-ACM and HID, same stream): a
// raw-radio sniffer, a Pulsar host for Touch Plus controllers, or (loopback rig) a fake controller.
// Wire format: link.h.
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "clock.h"
#include "crypto.h"
#include "ctrl_core.h"
#include "hal.h"
#include "host_core.h"
#include "link.h"
#include "nrf.h"
#include "radio_engine.h"
#include "sniffer.h"
#include "store.h"
#include "tusb.h"

#ifndef BUILD_ID
#define BUILD_ID 0
#endif

// PCA10059 LEDs, active low
#define LED_GREEN 6           // LD1, P0.06
#define LED_BLUE 12           // LD2 blue, P0.12
#define DFU_MAGIC_GPREGRET 0xB1  // Nordic bootloader: enter DFU after reset

static volatile uint32_t ms_ticks;
void SysTick_Handler(void) { ms_ticks++; }
uint32_t tusb_time_millis_api(void) { return ms_ticks; }

static void led(uint32_t pin, bool on) {
    if (on) NRF_P0->OUTCLR = 1u << pin;
    else NRF_P0->OUTSET = 1u << pin;
}

//------------------------------------------------------------------ USB power + IRQ glue

extern void tusb_hal_nrf_power_event(uint32_t event);  // 0 detected, 1 removed, 2 ready

// USB start-of-frame, stamped here (TinyUSB's own SOF callback runs later, in tud_task)
static volatile uint64_t sof_us;
static volatile uint32_t sof_count;
static volatile uint16_t sof_frame;

void USBD_IRQHandler(void) {
    if (NRF_USBD->EVENTS_SOF) {
        sof_us = clock_now64();
        sof_frame = (uint16_t)NRF_USBD->FRAMECNTR;
        sof_count++;
    }
    tud_int_handler(0);
}

void tud_sof_cb(uint32_t frame_count) { (void)frame_count; }

void POWER_CLOCK_IRQHandler(void) {
    if (NRF_POWER->EVENTS_USBDETECTED) {
        NRF_POWER->EVENTS_USBDETECTED = 0;
        tusb_hal_nrf_power_event(0);
    }
    if (NRF_POWER->EVENTS_USBREMOVED) {
        NRF_POWER->EVENTS_USBREMOVED = 0;
        tusb_hal_nrf_power_event(1);
    }
    if (NRF_POWER->EVENTS_USBPWRRDY) {
        NRF_POWER->EVENTS_USBPWRRDY = 0;
        tusb_hal_nrf_power_event(2);
    }
}

static void usb_init(void) {
    NVIC_SetPriority(USBD_IRQn, 2);
    NVIC_SetPriority(POWER_CLOCK_IRQn, 3);
    NRF_POWER->INTENSET = POWER_INTENSET_USBDETECTED_Msk | POWER_INTENSET_USBREMOVED_Msk |
                          POWER_INTENSET_USBPWRRDY_Msk;
    NVIC_EnableIRQ(POWER_CLOCK_IRQn);
    const tusb_rhport_init_t dev_init = {.role = TUSB_ROLE_DEVICE, .speed = TUSB_SPEED_AUTO};
    tusb_init(0, &dev_init);
    // USB power may already be up, in which case no event fires
    uint32_t reg = NRF_POWER->USBREGSTATUS;
    if (reg & POWER_USBREGSTATUS_VBUSDETECT_Msk) tusb_hal_nrf_power_event(0);
    if (reg & POWER_USBREGSTATUS_OUTPUTRDY_Msk) tusb_hal_nrf_power_event(2);
}

//------------------------------------------------------------------ framing

static size_t cobs_encode(const uint8_t* in, size_t len, uint8_t* out) {
    size_t o = 1, code_at = 0;
    uint8_t code = 1;
    for (size_t i = 0; i < len; i++) {
        if (in[i]) {
            out[o++] = in[i];
            code++;
        }
        if (!in[i] || code == 0xFF) {
            out[code_at] = code;
            code_at = o++;
            code = 1;
        }
    }
    out[code_at] = code;
    out[o++] = 0;
    return o;
}

//------------------------------------------------------------------ HID transport (link.h "Framing")
// The stream goes out in 64-byte IN reports [n][n bytes][pad] from a ring; OUT reports carry the
// PC's stream the same way. "Open" = an OUT report within LINK_HID_OPEN_MS; when that lapses the
// ring is dropped, so a reader that comes back starts on fresh events.

#define HID_RING 8192  // power of two
static uint8_t hid_ring[HID_RING];
static uint32_t hid_head, hid_tail;  // main loop only (tud_task callbacks included)
static uint32_t hid_out_ms;
static bool hid_seen;

static bool hid_is_open(void) { return hid_seen && tud_mounted() && ms_ticks - hid_out_ms < LINK_HID_OPEN_MS; }
static uint32_t hid_used(void) { return (hid_head - hid_tail) & (HID_RING - 1); }
static uint32_t hid_free(void) { return HID_RING - 1 - hid_used(); }

static void hid_put(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        hid_ring[hid_head] = p[i];
        hid_head = (hid_head + 1) & (HID_RING - 1);
    }
}

static void hid_pump(void) {
    if (!hid_seen) return;
    if (!hid_is_open()) {  // the reader went away: drop what it did not take
        hid_tail = hid_head;
        hid_seen = false;
        return;
    }
    if (!hid_used() || !tud_hid_ready()) return;
    uint8_t rep[64] = {0};
    uint32_t n = hid_used() < 63 ? hid_used() : 63;
    rep[0] = (uint8_t)n;
    for (uint32_t i = 0; i < n; i++) rep[1 + i] = hid_ring[(hid_tail + i) & (HID_RING - 1)];
    if (tud_hid_report(0, rep, sizeof rep)) hid_tail = (hid_tail + n) & (HID_RING - 1);
}

void tud_hid_report_complete_cb(uint8_t instance, const uint8_t* report, uint16_t len) {
    (void)instance, (void)report, (void)len;
    hid_pump();
}

//------------------------------------------------------------------ frames out

// worst case for a 300-byte frame: 300 + 2 overhead + 1 delimiter
static uint8_t tx_raw[LINK_MAX_FRAME + 20], tx_enc[LINK_MAX_FRAME + 30];

// Room for an encoded frame of n bytes on some open interface.
static bool link_room(size_t n) {
    return (tud_cdc_connected() && tud_cdc_write_available() >= n) || (hid_is_open() && hid_free() >= n);
}

// Queue one frame for the PC on every open interface (CDC with DTR set, HID while open). False
// (frame dropped) if none could take the whole frame: a partial frame would corrupt the stream.
static bool send_frame(uint8_t type, const void* body, size_t len, const void* tail, size_t tail_len) {
    if (1 + len + tail_len > sizeof tx_raw) return false;
    tx_raw[0] = type;
    memcpy(tx_raw + 1, body, len);
    if (tail_len) memcpy(tx_raw + 1 + len, tail, tail_len);
    size_t n = cobs_encode(tx_raw, 1 + len + tail_len, tx_enc);
    bool sent = false;
    if (tud_cdc_connected() && tud_cdc_write_available() >= n) {
        tud_cdc_write(tx_enc, n);
        sent = true;
    }
    if (hid_is_open() && hid_free() >= n) {
        hid_put(tx_enc, n);
        sent = true;
    }
    return sent;
}

static void send_text(const char* s) { send_frame(EVT_TEXT, s, strlen(s), NULL, 0); }

static void config_to_link(const sniffer_config_t* c, link_config_t* l) {
    memset(l, 0, sizeof(*l));
    l->mode = c->mode;
    l->frequency = c->frequency;
    memcpy(l->prefix, c->prefix, sizeof(l->prefix));
    l->base0 = c->base0;
    l->base1 = c->base1;
    l->rx_mask = c->rx_mask;
    l->follow = c->follow;
    l->follow_rx = c->follow_rx;
    l->balen = c->balen;
    l->big_endian = c->big_endian;
    l->lflen = c->lflen;
    l->s0len = c->s0len;
    l->s1len = c->s1len;
    l->statlen = c->statlen;
    l->maxlen = c->maxlen;
    l->crc_len = c->crc_len;
    l->crc_skip_addr = c->crc_skip_addr;
    l->crc_poly = c->crc_poly;
    l->crc_init = c->crc_init;
    l->hop_dwell_ms = c->hop_dwell_ms;
    l->hop_count = c->hop_count;
    memcpy(l->hop_list, c->hop_list, sizeof(l->hop_list));
}

static void link_to_config(const link_config_t* l, sniffer_config_t* c) {
    memset(c, 0, sizeof(*c));
    c->mode = l->mode;
    c->frequency = l->frequency;
    memcpy(c->prefix, l->prefix, sizeof(c->prefix));
    c->base0 = l->base0;
    c->base1 = l->base1;
    c->rx_mask = l->rx_mask;
    c->follow = l->follow != 0;
    c->follow_rx = l->follow_rx;
    c->balen = l->balen;
    c->big_endian = l->big_endian != 0;
    c->lflen = l->lflen;
    c->s0len = l->s0len;
    c->s1len = l->s1len;
    c->statlen = l->statlen;
    c->maxlen = l->maxlen;
    c->crc_len = l->crc_len;
    c->crc_skip_addr = l->crc_skip_addr != 0;
    c->crc_poly = l->crc_poly;
    c->crc_init = l->crc_init;
    c->hop_dwell_ms = l->hop_dwell_ms;
    c->hop_count = l->hop_count;
    memcpy(c->hop_list, l->hop_list, sizeof(c->hop_list));
}

static void send_status(void) {
    link_status_t s;
    s.version = LINK_VERSION;
    s.running = sniffer_running();
    s.now_us = sniffer_now_us();
    s.received = sniffer_received();
    s.dropped = sniffer_dropped();
    sniffer_follow_stats_t fs = sniffer_follow_stats();
    s.follow_beacons = fs.beacons;
    s.follow_blind = fs.blind_hops;
    s.follow_locked = fs.locked;
    config_to_link(sniffer_config(), &s.config);
    send_frame(EVT_STATUS, &s, sizeof(s), NULL, 0);
}

//------------------------------------------------------------------ modes

//------------------------------------------------------------------ flash store (host identity + pairings)
// Two pages at the top of the application area, below the bootloader at 0xE0000. The PCA10059 open
// bootloader leaves the top NRF_DFU_APP_DATA_AREA_SIZE bytes of the app area (3 pages, the SDK
// default; INFERRED for this bootloader build, check that pairings survive a DFU) out of updates;
// pca10059.ld ends the firmware below them.
#define STORE_PAGE0 0xDE000u
#define STORE_PAGE1 0xDF000u
#define STORE_SLICE_MS 1      // partial erase slice (ERASEPAGEPARTIALCFG)
#define STORE_SLICES 90       // tERASEPAGE is 85 ms max
#define STORE_STEP_MS 20      // at most one slice (1 ms CPU stall) per 20 ms: no two missed beacons in a row

static store_t store;

static void nvmc_ready(void) {
    while (!NRF_NVMC->READY) {}
}
static void f_write(void* u, uint32_t* a, uint32_t v) {
    (void)u;
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Wen;
    *(volatile uint32_t*)a = v;  // ~41 us; interrupts run between words
    nvmc_ready();
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
}
static void f_erase_slice(void* u, uint32_t* page) {
    (void)u;
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Een;
    NRF_NVMC->ERASEPAGEPARTIALCFG = STORE_SLICE_MS;
    NRF_NVMC->ERASEPAGEPARTIAL = (uint32_t)page;
    nvmc_ready();
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
}
static const store_flash_t store_flash = {{(uint32_t*)STORE_PAGE0, (uint32_t*)STORE_PAGE1}, NULL, f_write,
                                          f_erase_slice, STORE_SLICES};

//------------------------------------------------------------------ modes

static uint8_t mode = LINK_MODE_IDLE;
static host_t host;
static ctrl_t ctrl;
static platform_t plat;
static uint32_t blink;

static void p_emit(platform_t* p, uint8_t evt, const void* body, size_t len, const void* tail, size_t tail_len) {
    if (!send_frame(evt, body, len, tail, tail_len)) p->events_dropped++;
    else if ((evt == EVT_INPUT || evt == EVT_PACKET) && (++blink & 63) == 0) led(LED_BLUE, (blink >> 6) & 1);
}
static uint64_t p_now(platform_t* p) {
    (void)p;
    return clock_now64();
}
static void p_random(platform_t* p, uint8_t* out, size_t n) {
    (void)p;
    hal_random(out, n);
}
static bool p_ccm(platform_t* p, bool enc, const uint8_t key[16], const uint8_t nonce[13], const uint8_t* in,
                  uint8_t len, uint8_t* out) {
    (void)p;
    return hal_ccm(enc, key, nonce, in, len, out);
}
static void p_kick(platform_t* p) {
    (void)p;
    engine_kick();
}
static void p_halt(platform_t* p) {
    (void)p;
    engine_halt();
}

static bool h_next(void* c, uint64_t now, radio_op_t* op) { return host_next_op(c, now, op); }
static void h_rx(void* c, const radio_rx_t* rx) { host_on_rx(c, rx); }
static void h_done(void* c, const radio_op_t* op, uint64_t now) { host_on_done(c, op, now); }
static bool c_next(void* c, uint64_t now, radio_op_t* op) { return ctrl_next_op(c, now, op); }
static void c_rx(void* c, const radio_rx_t* rx) { ctrl_on_rx(c, rx); }
static void c_done(void* c, const radio_op_t* op, uint64_t now) { ctrl_on_done(c, op, now); }
static const engine_core_t host_engine = {h_next, h_rx, h_done, &host};
static const engine_core_t ctrl_engine = {c_next, c_rx, c_done, &ctrl};

void RADIO_IRQHandler(void) {
    if (mode == LINK_MODE_SNIFFER) sniffer_radio_irq();
    else engine_radio_irq();
}

void TIMER0_IRQHandler(void) { engine_timer_irq(); }

// Leave whatever mode is running; the radio is free afterwards.
static void stop_all(void) {
    if (mode == LINK_MODE_SNIFFER) sniffer_stop();
    if (mode == LINK_MODE_HOST) host_stop(&host);
    if (mode == LINK_MODE_FAKE_CTRL) ctrl_stop(&ctrl);
    engine_detach();
    mode = LINK_MODE_IDLE;
}

static void result(uint8_t tag, uint8_t cmd, uint8_t status, uint8_t detail) {
    link_result_t r = {tag, cmd, status, detail};
    send_frame(EVT_RESULT, &r, sizeof r, NULL, 0);
}

static void send_hello(uint8_t tag) {
    link_hello_t h;
    memset(&h, 0, sizeof h);
    h.version = LINK_VERSION;
    h.mode = mode;
    h.caps = LINK_CAP_SNIFFER | LINK_CAP_HOST | LINK_CAP_FAKE_CTRL | LINK_CAP_PLACEHOLDER | LINK_CAP_HID |
             LINK_CAP_REAL_PAIRING | (store.ok ? LINK_CAP_STORE : 0);
    h.build = BUILD_ID;
    h.dongle_id = hal_device_id();
    h.now_us = clock_now64();
    h.max_slots = LINK_MAX_SLOTS;
    send_frame(EVT_HELLO, &h, sizeof h, NULL, 0);
    result(tag, CMD_HELLO, LINK_OK, 0);
}

static uint64_t rx_stamp_us;  // when the bytes being decoded came out of the USB FIFO

static void time_ping(const uint8_t* body, size_t len) {
    if (len != sizeof(link_time_ping_t)) return;
    link_time_ping_t p;
    memcpy(&p, body, sizeof p);
    link_time_pong_t r;
    memset(&r, 0, sizeof r);
    r.tag = p.tag;
    r.seq = p.seq;
    r.host_t = p.host_t;
    r.dongle_rx_us = rx_stamp_us;
    r.dongle_tx_us = clock_now64();
    send_frame(EVT_TIME, &r, sizeof r, NULL, 0);
    tud_cdc_write_flush();
    hid_pump();
}

//------------------------------------------------------------------ self-test (hardware day, no controller needed)

static bool hexeq(const uint8_t* a, const char* hex, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char ch = hex[2 * i + k];
            v = v << 4 | (unsigned)(ch <= '9' ? ch - '0' : ch - 'a' + 10);
        }
        if (a[i] != v) return false;
    }
    return true;
}

static void selftest(uint8_t tag) {
    if (mode == LINK_MODE_HOST || mode == LINK_MODE_FAKE_CTRL) {
        result(tag, CMD_SELFTEST, LINK_ERR_STATE, 0);
        return;
    }
    uint8_t fail = 0;
    // 1. AES-128, FIPS-197 C.1
    static const uint8_t k[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    static const uint8_t pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t ct[16];
    aes128_t aes;
    aes128_init(&aes, k);
    aes128_encrypt(&aes, pt, ct);
    if (!hexeq(ct, "69c4e0d86a7b0430d8cdb78070b4c55a", 16)) fail |= 1;
    send_text(fail & 1 ? "selftest: AES-128 FAIL" : "selftest: AES-128 ok");
    // 2. X25519, RFC 7748 6.1 (Alice's public key), with timing
    static const uint8_t alice[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
                                      0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
                                      0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
    uint8_t pub[32];
    uint64_t t0 = clock_now64();
    x25519_base(pub, alice);
    uint32_t ms = (uint32_t)((clock_now64() - t0) / 1000);
    if (!hexeq(pub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32)) fail |= 2;
    char buf[64];
    snprintf(buf, sizeof buf, "selftest: X25519 %s (%lu ms)", fail & 2 ? "FAIL" : "ok", (unsigned long)ms);
    send_text(buf);
    // 3. CCM peripheral == software CCM, both directions, several lengths, and MIC rejection
    uint8_t key[16], nonce[13], msg[120], hw[124], sw[124], back[120];
    hal_random(key, sizeof key);
    hal_random(nonce, sizeof nonce);
    hal_random(msg, sizeof msg);
    static const uint8_t lens[] = {1, 2, 16, 17, 30, 35, 59, 120};
    for (unsigned i = 0; i < sizeof lens; i++) {
        uint8_t n = lens[i];
        hal_ccm(true, key, nonce, msg, n, hw);
        pulsar_ccm_encrypt(key, nonce, 0, msg, n, sw);
        if (memcmp(hw, sw, n + 4u)) fail |= 4;
        if (!hal_ccm(false, key, nonce, sw, (uint8_t)(n + 4), back) || memcmp(back, msg, n)) fail |= 4;
        sw[0] ^= 1;
        if (hal_ccm(false, key, nonce, sw, (uint8_t)(n + 4), back)) fail |= 4;
    }
    send_text(fail & 4 ? "selftest: CCM peripheral FAIL (differs from software)" : "selftest: CCM peripheral ok");
    // 4. RNG produces varying bytes; 5. the clock runs at 1 MHz against SysTick
    uint8_t r1[16], r2[16];
    hal_random(r1, sizeof r1);
    hal_random(r2, sizeof r2);
    if (!memcmp(r1, r2, sizeof r1)) fail |= 8;
    send_text(fail & 8 ? "selftest: RNG FAIL" : "selftest: RNG ok");
    uint32_t ms0 = ms_ticks;
    uint64_t c0 = clock_now64();
    while (ms_ticks - ms0 < 50) {}
    uint64_t dt = clock_now64() - c0;
    if (dt < 48000 || dt > 52000) fail |= 16;
    snprintf(buf, sizeof buf, "selftest: clock %s (%lu us per 50 ms)", fail & 16 ? "FAIL" : "ok", (unsigned long)dt);
    send_text(buf);
    result(tag, CMD_SELFTEST, fail ? LINK_ERR_CRYPTO : LINK_OK, fail);
}

//------------------------------------------------------------------ command dispatch

static void handle_command(const uint8_t* f, size_t len) {
    if (!len) return;
    const uint8_t* body = f + 1;
    size_t body_len = len - 1;
    uint8_t tag = body_len ? body[0] : 0;
    switch (f[0]) {
    case CMD_CONFIG: {
        if (body_len != sizeof(link_config_t)) {
            send_text("config: wrong size");
            return;
        }
        link_config_t l;
        sniffer_config_t c;
        memcpy(&l, body, sizeof(l));
        link_to_config(&l, &c);
        stop_all();
        mode = LINK_MODE_SNIFFER;
        if (!sniffer_apply(&c)) {
            send_text("config: rejected");
            mode = LINK_MODE_IDLE;
        }
        send_status();
        break;
    }
    case CMD_STOP:
        stop_all();
        send_status();
        break;
    case CMD_STATUS:
        send_status();
        break;
    case CMD_SWEEP: {
        uint16_t dwell = 1000;
        if (body_len >= 2) dwell = (uint16_t)(body[0] | body[1] << 8);
        if (dwell > 10000) dwell = 10000;
        stop_all();
        static uint8_t peak[101];
        sniffer_rssi_sweep(peak, dwell);
        uint8_t hdr[2] = {(uint8_t)dwell, (uint8_t)(dwell >> 8)};
        send_frame(EVT_SWEEP, hdr, 2, peak, sizeof(peak));
        break;
    }
    case CMD_DFU:
        stop_all();
        NRF_POWER->GPREGRET = DFU_MAGIC_GPREGRET;
        NVIC_SystemReset();
        break;
    case CMD_HELLO:
        send_hello(tag);
        break;
    case CMD_TIME_PING:
        time_ping(body, body_len);
        break;
    case CMD_SELFTEST:
        selftest(tag);
        break;
    case CMD_HOST_START:
        if (mode != LINK_MODE_HOST) {
            stop_all();
            host_init(&host, &plat);
            host.store = &store;
            engine_attach(&host_engine);
        }
        if (body_len == sizeof(link_host_start_t)) engine_set_tx_power(((const link_host_start_t*)body)->tx_power_dbm);
        host_command(&host, f[0], body, (uint32_t)body_len);
        mode = host_running(&host) ? LINK_MODE_HOST : LINK_MODE_IDLE;
        if (mode == LINK_MODE_IDLE) engine_detach();
        break;
    case CMD_FAKE_START:
        stop_all();
        ctrl_init(&ctrl, &plat);
        engine_set_tx_power(0);
        engine_attach(&ctrl_engine);
        mode = LINK_MODE_FAKE_CTRL;
        ctrl_start(&ctrl, body, (uint32_t)body_len);
        if (ctrl.state == CTRL_IDLE) {
            engine_detach();
            mode = LINK_MODE_IDLE;
        }
        break;
    case CMD_PAIR_LIST:
    case CMD_PAIR_FORGET:  // the flash store: any mode
        host_command(&host, f[0], body, (uint32_t)body_len);
        break;
    default:
        if (f[0] >= CMD_HOST_STATUS && f[0] <= CMD_HAPTIC) {
            if (mode != LINK_MODE_HOST) result(tag, f[0], LINK_ERR_STATE, 0);
            else host_command(&host, f[0], body, (uint32_t)body_len);
        } else if (f[0] >= CMD_HELLO) {
            result(tag, f[0], LINK_ERR_UNKNOWN_CMD, 0);
        } else {
            send_text("unknown command");
        }
    }
}

// COBS decoders fed byte by byte, one per interface (frames must not interleave)
typedef struct {
    uint8_t buf[LINK_MAX_FRAME + 8];
    size_t len;
    bool overflow;
} rx_t;

static rx_t cdc_rx, hid_rx;

static void rx_byte(rx_t* r, uint8_t b) {
    if (b) {
        if (r->len < sizeof(r->buf)) r->buf[r->len++] = b;
        else r->overflow = true;
        return;
    }
    if (!r->overflow && r->len) {
        static uint8_t dec[sizeof(r->buf)];
        size_t i = 0, o = 0;
        bool ok = true;
        while (i < r->len) {
            uint8_t code = r->buf[i++];
            if (i + code - 1 > r->len) {
                ok = false;
                break;
            }
            for (uint8_t k = 1; k < code; k++) dec[o++] = r->buf[i++];
            if (code != 0xFF && i < r->len) dec[o++] = 0;
        }
        if (ok) handle_command(dec, o);
    }
    r->len = 0;
    r->overflow = false;
}

//------------------------------------------------------------------ HID callbacks (tud_task context)

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t type, uint8_t* buf,
                               uint16_t reqlen) {
    (void)instance, (void)report_id, (void)type, (void)buf, (void)reqlen;
    return 0;  // no GET_REPORT: the stream is on the interrupt endpoints
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t type, const uint8_t* buf,
                           uint16_t len) {
    (void)instance, (void)report_id;
    if (type != HID_REPORT_TYPE_OUTPUT && type != HID_REPORT_TYPE_INVALID) return;
    if (!len || buf[0] > 63 || buf[0] + 1u > len) return;
    hid_out_ms = ms_ticks;
    hid_seen = true;
    rx_stamp_us = clock_now64();
    for (uint8_t i = 0; i < buf[0]; i++) rx_byte(&hid_rx, buf[1 + i]);
}

//------------------------------------------------------------------ main

int main(void) {
    NRF_CLOCK->EVENTS_HFCLKSTARTED = 0;
    NRF_CLOCK->TASKS_HFCLKSTART = 1;
    while (!NRF_CLOCK->EVENTS_HFCLKSTARTED) {}

    NRF_P0->DIRSET = (1u << LED_GREEN) | (1u << LED_BLUE);
    led(LED_GREEN, false);
    led(LED_BLUE, false);

    SysTick_Config(SystemCoreClock / 1000);
    clock_init();
    sniffer_init();
    engine_init();
    plat = (platform_t){p_now, p_random, p_ccm, p_emit, p_kick, p_halt, hal_device_id(), 0, 0, NULL};
    store_init(&store, &store_flash);  // may erase a page synchronously: before the radio and USB start
    host_init(&host, &plat);
    host.store = &store;
    ctrl_init(&ctrl, &plat);
    usb_init();
    tud_sof_cb_enable(true);
    uint32_t store_ms = 0, sof_ms = 0, sof_seen = 0;

    static sniffer_packet_t pkt;
    for (;;) {
        tud_task();
        led(LED_GREEN, tud_mounted());

        while (tud_cdc_available()) {
            uint8_t buf[64];
            uint32_t n = tud_cdc_read(buf, sizeof(buf));
            rx_stamp_us = clock_now64();
            for (uint32_t i = 0; i < n; i++) rx_byte(&cdc_rx, buf[i]);
        }
        if (store_busy(&store) && ms_ticks - store_ms >= STORE_STEP_MS) {
            store_step(&store);
            store_ms = ms_ticks;
        }
        if (ms_ticks - sof_ms >= 1000 && sof_count != sof_seen) {
            link_sof_t s;
            __disable_irq();
            s = (link_sof_t){sof_frame, 0, sof_count, sof_us};
            __enable_irq();
            send_frame(EVT_SOF, &s, sizeof s, NULL, 0);
            sof_seen = s.sof_count;
            sof_ms = ms_ticks;
        }

        if (!(NRF_CLOCK->HFCLKSTAT & CLOCK_HFCLKSTAT_SRC_Msk)) NRF_CLOCK->TASKS_HFCLKSTART = 1;  // USB suspend stops it
        (void)clock_now64();  // keeps the 64-bit extension current
        plat.radio_late_ops = engine_late_ops();

        switch (mode) {
        case LINK_MODE_SNIFFER:
            sniffer_poll();
            // Forward packets while the PC has the port open; otherwise let the ring fill
            // (overflow shows up as `dropped`).
            if (link_room(sizeof tx_enc)) {
                while (link_room(sizeof tx_enc) && sniffer_pop(&pkt)) {
                    link_packet_t h = {pkt.timestamp_us, pkt.frequency, pkt.rssi, pkt.crc_ok, pkt.rxmatch,
                                       pkt.length};
                    p_emit(&plat, EVT_PACKET, &h, sizeof(h), pkt.data, pkt.length);
                }
            }
            break;
        case LINK_MODE_HOST:
            host_poll(&host);
            break;
        case LINK_MODE_FAKE_CTRL:
            ctrl_poll(&ctrl);
            break;
        default:
            break;
        }
        tud_cdc_write_flush();
        hid_pump();
    }
}
