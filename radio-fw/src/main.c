// TouchFrame radio dongle (nRF52840 Dongle, PCA10059): raw-radio sniffer over USB CDC.
#include <stddef.h>
#include <string.h>

#include "link.h"
#include "nrf.h"
#include "sniffer.h"
#include "tusb.h"

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

void USBD_IRQHandler(void) { tud_int_handler(0); }

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

// worst case for a 300-byte frame: 300 + 2 overhead + 1 delimiter
static uint8_t tx_raw[320], tx_enc[330];

static void send_frame(uint8_t type, const void* body, size_t len, const void* tail, size_t tail_len) {
    tx_raw[0] = type;
    memcpy(tx_raw + 1, body, len);
    if (tail_len) memcpy(tx_raw + 1 + len, tail, tail_len);
    size_t n = cobs_encode(tx_raw, 1 + len + tail_len, tx_enc);
    tud_cdc_write(tx_enc, n);
}

static void send_text(const char* s) { send_frame(EVT_TEXT, s, strlen(s), NULL, 0); }

static void config_to_link(const sniffer_config_t* c, link_config_t* l) {
    memset(l, 0, sizeof(*l));
    l->mode = c->mode;
    l->frequency = c->frequency;
    l->prefix = c->prefix;
    l->base = c->base;
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
    c->prefix = l->prefix;
    c->base = l->base;
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
    config_to_link(sniffer_config(), &s.config);
    send_frame(EVT_STATUS, &s, sizeof(s), NULL, 0);
}

static void handle_command(const uint8_t* f, size_t len) {
    if (!len) return;
    const uint8_t* body = f + 1;
    size_t body_len = len - 1;
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
        if (!sniffer_apply(&c)) send_text("config: rejected");
        send_status();
        break;
    }
    case CMD_STOP:
        sniffer_stop();
        send_status();
        break;
    case CMD_STATUS:
        send_status();
        break;
    case CMD_SWEEP: {
        uint16_t dwell = 1000;
        if (body_len >= 2) dwell = (uint16_t)(body[0] | body[1] << 8);
        if (dwell > 10000) dwell = 10000;
        static uint8_t peak[101];
        sniffer_rssi_sweep(peak, dwell);
        uint8_t hdr[2] = {(uint8_t)dwell, (uint8_t)(dwell >> 8)};
        send_frame(EVT_SWEEP, hdr, 2, peak, sizeof(peak));
        break;
    }
    case CMD_DFU:
        sniffer_stop();
        NRF_POWER->GPREGRET = DFU_MAGIC_GPREGRET;
        NVIC_SystemReset();
        break;
    default:
        send_text("unknown command");
    }
}

// COBS decoder fed byte by byte from the CDC RX stream
static uint8_t rx_buf[128];
static size_t rx_len;
static bool rx_overflow;

static void rx_byte(uint8_t b) {
    if (b) {
        if (rx_len < sizeof(rx_buf)) rx_buf[rx_len++] = b;
        else rx_overflow = true;
        return;
    }
    if (!rx_overflow && rx_len) {
        static uint8_t dec[sizeof(rx_buf)];
        size_t i = 0, o = 0;
        bool ok = true;
        while (i < rx_len) {
            uint8_t code = rx_buf[i++];
            if (i + code - 1 > rx_len) {
                ok = false;
                break;
            }
            for (uint8_t k = 1; k < code; k++) dec[o++] = rx_buf[i++];
            if (code != 0xFF && i < rx_len) dec[o++] = 0;
        }
        if (ok) handle_command(dec, o);
    }
    rx_len = 0;
    rx_overflow = false;
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
    sniffer_init();
    usb_init();

    static sniffer_packet_t pkt;
    uint32_t blink = 0;
    for (;;) {
        tud_task();
        led(LED_GREEN, tud_mounted());

        while (tud_cdc_available()) {
            uint8_t buf[64];
            uint32_t n = tud_cdc_read(buf, sizeof(buf));
            for (uint32_t i = 0; i < n; i++) rx_byte(buf[i]);
        }

        sniffer_poll();

        // Forward packets while the PC has the port open; otherwise let the ring fill
        // (overflow shows up as `dropped`).
        if (tud_cdc_connected()) {
            while (tud_cdc_write_available() >= sizeof(tx_enc) && sniffer_pop(&pkt)) {
                link_packet_t h = {pkt.timestamp_us, pkt.frequency, pkt.rssi, pkt.crc_ok, pkt.length};
                send_frame(EVT_PACKET, &h, sizeof(h), pkt.data, pkt.length);
                if ((++blink & 15) == 0) led(LED_BLUE, (blink >> 4) & 1);
            }
            tud_cdc_write_flush();
        }
    }
}
