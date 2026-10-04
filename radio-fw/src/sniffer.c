// Raw RADIO receiver. EasyDMA writes each packet straight into a ring slot; the END
// interrupt stamps it and points the radio at the next free slot.
#include "sniffer.h"

#include <string.h>

#include "clock.h"
#include "nrf.h"
#include "nrf52_erratas.h"
#include "pulsar_hop.h"

#define RING_SIZE 64  // power of two
#define BEACON_PERIOD_US 2000
#define HOP_AFTER_BEACON_US 1850  // stay for this period's uplinks, then move before the next beacon
#define BLIND_LIMIT 250           // periods without a beacon before we report lost lock

static sniffer_packet_t ring[RING_SIZE];
static volatile uint32_t ring_head, ring_tail;  // ISR writes head, main loop writes tail
static volatile uint32_t dropped, received;

static sniffer_config_t cfg;
static bool running;
static volatile uint8_t cur_freq;
static uint8_t hop_index;
static uint32_t last_hop_us;
static uint8_t hdr_len;  // S0 + LENGTH + S1 bytes in RAM

// Follow mode (connected link). The ISR hands each parsed beacon to the main loop, which does the
// retuning; the ISR never touches the radio config beyond re-arming RX.
static pulsar_hop_t follow_hop;
static volatile uint32_t beacon_us;
static volatile uint64_t beacon_map;
static volatile uint8_t beacon_unmapped;
static volatile uint32_t beacon_seq;  // ISR bumps this on every parsed beacon
static uint32_t follow_seen_seq;      // main loop's view of beacon_seq
static uint8_t follow_next_freq;
static bool follow_armed;             // a next-channel hop is scheduled
static uint32_t follow_due_us;        // when to take it
static uint32_t follow_beacons, follow_blind, follow_consec_blind;

static void radio_disable(void) {
    NVIC_DisableIRQ(RADIO_IRQn);
    NRF_RADIO->SHORTS = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE = 1;
    while (!NRF_RADIO->EVENTS_DISABLED) {}
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_END = 0;
    NVIC_ClearPendingIRQ(RADIO_IRQn);
}

static void radio_rx_start(void) {
    NRF_RADIO->FREQUENCY = cur_freq;
    NRF_RADIO->PACKETPTR = (uint32_t)ring[ring_head].data;
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_ADDRESS_RSSISTART_Msk |
                        RADIO_SHORTS_DISABLED_RSSISTOP_Msk;
    NRF_RADIO->INTENSET = RADIO_INTENSET_END_Msk;
    NVIC_ClearPendingIRQ(RADIO_IRQn);
    NVIC_EnableIRQ(RADIO_IRQn);
    NRF_RADIO->TASKS_RXEN = 1;
}

static void hfxo_request(void) {
    if (!(NRF_CLOCK->HFCLKSTAT & CLOCK_HFCLKSTAT_SRC_Msk)) NRF_CLOCK->TASKS_HFCLKSTART = 1;
}

void sniffer_init(void) {
    if (nrf52_errata_182()) *(volatile uint32_t*)0x4000173C |= (1u << 10);

    NRF_RADIO->POWER = 1;
    hfxo_request();

    // TIMER0 (the 1 us clock, CC[1] = ADDRESS capture via PPI 26) is set up by clock_init().
    NVIC_SetPriority(RADIO_IRQn, 0);
}

uint32_t sniffer_now_us(void) { return clock_now32(); }

bool sniffer_apply(const sniffer_config_t* c) {
    if (c->balen < 1 || c->balen > 4) return false;  // 1 is outside the spec (promiscuous experiments)
    if (c->frequency > 100 || c->crc_len > 3 || c->lflen > 8 || c->s0len > 1 || c->s1len > 8) return false;
    if (c->rx_mask == 0 || c->hop_count > SNIFFER_MAX_HOPS) return false;
    if (c->follow && (c->follow_rx > 7 || !(c->rx_mask & (1u << c->follow_rx)) || !c->crc_len)) return false;
    for (uint8_t i = 0; i < c->hop_count; i++)
        if (c->hop_list[i] > 100) return false;

    sniffer_stop();
    cfg = *c;
    hdr_len = (uint8_t)(cfg.s0len + (cfg.lflen + 7) / 8 + (cfg.s1len + 7) / 8);
    if (cfg.maxlen > sizeof(ring[0].data) - hdr_len) cfg.maxlen = (uint8_t)(sizeof(ring[0].data) - hdr_len);

    uint32_t plen = cfg.mode == RADIO_MODE_MODE_Ble_2Mbit ? RADIO_PCNF0_PLEN_16bit : RADIO_PCNF0_PLEN_8bit;
    NRF_RADIO->MODE = cfg.mode;
    NRF_RADIO->PCNF0 = ((uint32_t)cfg.lflen << RADIO_PCNF0_LFLEN_Pos) |
                       ((uint32_t)cfg.s0len << RADIO_PCNF0_S0LEN_Pos) |
                       ((uint32_t)cfg.s1len << RADIO_PCNF0_S1LEN_Pos) | (plen << RADIO_PCNF0_PLEN_Pos);
    NRF_RADIO->PCNF1 = ((uint32_t)cfg.maxlen << RADIO_PCNF1_MAXLEN_Pos) |
                       ((uint32_t)cfg.statlen << RADIO_PCNF1_STATLEN_Pos) |
                       ((uint32_t)cfg.balen << RADIO_PCNF1_BALEN_Pos) |
                       ((uint32_t)(cfg.big_endian ? 1 : 0) << RADIO_PCNF1_ENDIAN_Pos);
    // BASE0/PREFIX0 serve logical address 0; BASE1 serves logical addresses 1..7 (prefixes AP1..AP7).
    NRF_RADIO->BASE0 = cfg.base0;
    NRF_RADIO->BASE1 = cfg.base1;
    NRF_RADIO->PREFIX0 = (uint32_t)cfg.prefix[0] | (uint32_t)cfg.prefix[1] << 8 |
                         (uint32_t)cfg.prefix[2] << 16 | (uint32_t)cfg.prefix[3] << 24;
    NRF_RADIO->PREFIX1 = (uint32_t)cfg.prefix[4] | (uint32_t)cfg.prefix[5] << 8 |
                         (uint32_t)cfg.prefix[6] << 16 | (uint32_t)cfg.prefix[7] << 24;
    NRF_RADIO->RXADDRESSES = cfg.rx_mask;
    NRF_RADIO->CRCCNF = ((uint32_t)cfg.crc_len << RADIO_CRCCNF_LEN_Pos) |
                        ((uint32_t)(cfg.crc_skip_addr ? 1 : 0) << RADIO_CRCCNF_SKIPADDR_Pos);
    NRF_RADIO->CRCPOLY = cfg.crc_poly;
    NRF_RADIO->CRCINIT = cfg.crc_init;
    NRF_RADIO->MODECNF0 = RADIO_MODECNF0_RU_Fast << RADIO_MODECNF0_RU_Pos;

    hop_index = 0;
    cur_freq = cfg.hop_count ? cfg.hop_list[0] : cfg.frequency;
    last_hop_us = sniffer_now_us();
    beacon_seq = follow_seen_seq = 0;
    follow_armed = false;
    follow_beacons = follow_blind = follow_consec_blind = 0;
    follow_hop.hop = pulsar_hop_increment(cfg.base1);  // connected link: netaddr is in BASE1
    hfxo_request();
    radio_rx_start();
    running = true;
    return true;
}

void sniffer_stop(void) {
    if (!running) return;
    radio_disable();
    running = false;
}

bool sniffer_running(void) { return running; }

void sniffer_radio_irq(void) {
    if (!NRF_RADIO->EVENTS_END) return;
    NRF_RADIO->EVENTS_END = 0;

    sniffer_packet_t* p = &ring[ring_head];
    p->timestamp_us = NRF_TIMER0->CC[1];
    p->frequency = cur_freq;
    p->rssi = (int8_t)-(int32_t)NRF_RADIO->RSSISAMPLE;
    p->crc_ok = cfg.crc_len ? (uint8_t)NRF_RADIO->CRCSTATUS : 0;
    p->rxmatch = (uint8_t)NRF_RADIO->RXMATCH;

    uint32_t payload = cfg.statlen;
    if (cfg.lflen) payload += p->data[cfg.s0len] & ((1u << cfg.lflen) - 1);
    if (payload > cfg.maxlen) payload = cfg.maxlen;
    p->length = (uint8_t)(hdr_len + payload);
    received++;

    // Follow mode: a CRC-good beacon on the followed address re-syncs the hop state. Hand the
    // parsed map/channel to the main loop (sniffer_poll); the ISR does not retune.
    if (cfg.follow && p->crc_ok && p->rxmatch == cfg.follow_rx) {
        uint64_t map;
        uint8_t un;
        if (pulsar_parse_beacon(&p->data[hdr_len], (uint8_t)payload, &map, &un)) {
            beacon_map = map;
            beacon_unmapped = un;
            beacon_us = p->timestamp_us;
            beacon_seq++;
        }
    }

    uint32_t next = (ring_head + 1) & (RING_SIZE - 1);
    if (next != ring_tail) ring_head = next;
    else dropped++;  // ring full: reuse this slot

    NRF_RADIO->PACKETPTR = (uint32_t)ring[ring_head].data;
    NRF_RADIO->TASKS_START = 1;
}

static void retune(uint8_t freq) {
    radio_disable();
    cur_freq = freq;
    radio_rx_start();
}

void sniffer_poll(void) {
    if (!running) return;
    hfxo_request();  // the USB driver stops HFCLK on suspend; the radio needs the crystal

    if (cfg.follow) {
        uint32_t now = sniffer_now_us();
        if (beacon_seq != follow_seen_seq) {  // a new beacon arrived: re-sync and schedule the hop
            follow_seen_seq = beacon_seq;
            follow_hop.map = beacon_map;
            follow_hop.unmapped = beacon_unmapped;
            follow_next_freq = pulsar_channel_mhz(pulsar_hop_next(&follow_hop));
            follow_due_us = beacon_us + HOP_AFTER_BEACON_US;
            follow_armed = true;
            follow_beacons++;
            follow_consec_blind = 0;
        }
        if (follow_armed && (int32_t)(now - follow_due_us) >= 0) {
            retune(follow_next_freq);
            follow_armed = false;
            follow_due_us += BEACON_PERIOD_US;  // next deadline: if no beacon lands, blind-hop here
        } else if (!follow_armed && (int32_t)(now - (follow_due_us + 300)) >= 0) {
            // Expected beacon never came; advance the hop on dead reckoning.
            follow_next_freq = pulsar_channel_mhz(pulsar_hop_next(&follow_hop));
            retune(follow_next_freq);
            follow_due_us += BEACON_PERIOD_US;
            follow_blind++;
            follow_consec_blind++;
        }
        return;
    }

    if (cfg.hop_count < 2 || cfg.hop_dwell_ms == 0) return;
    uint32_t now = sniffer_now_us();
    if (now - last_hop_us < (uint32_t)cfg.hop_dwell_ms * 1000u) return;
    last_hop_us = now;
    hop_index = (uint8_t)((hop_index + 1) % cfg.hop_count);
    retune(cfg.hop_list[hop_index]);
}

sniffer_follow_stats_t sniffer_follow_stats(void) {
    sniffer_follow_stats_t s = {follow_beacons, follow_blind, follow_consec_blind < BLIND_LIMIT && follow_beacons};
    return s;
}

bool sniffer_pop(sniffer_packet_t* out) {
    uint32_t tail = ring_tail;
    if (tail == ring_head) return false;
    const sniffer_packet_t* p = &ring[tail];
    memcpy(out, p, offsetof(sniffer_packet_t, data) + p->length);
    ring_tail = (tail + 1) & (RING_SIZE - 1);
    return true;
}

uint32_t sniffer_dropped(void) { return dropped; }
uint32_t sniffer_received(void) { return received; }
const sniffer_config_t* sniffer_config(void) { return &cfg; }

void sniffer_rssi_sweep(uint8_t out[101], uint16_t dwell_us) {
    sniffer_stop();
    hfxo_request();
    while (!(NRF_CLOCK->HFCLKSTAT & CLOCK_HFCLKSTAT_SRC_Msk)) {}
    NRF_RADIO->MODE = RADIO_MODE_MODE_Nrf_2Mbit;
    for (uint8_t ch = 0; ch <= 100; ch++) {
        NRF_RADIO->FREQUENCY = ch;
        NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk;
        NRF_RADIO->EVENTS_READY = 0;
        NRF_RADIO->TASKS_RXEN = 1;
        while (!NRF_RADIO->EVENTS_READY) {}
        uint8_t best = 127;  // RSSISAMPLE is -dBm: smaller = stronger
        uint32_t t0 = sniffer_now_us();
        do {
            NRF_RADIO->EVENTS_RSSIEND = 0;
            NRF_RADIO->TASKS_RSSISTART = 1;
            while (!NRF_RADIO->EVENTS_RSSIEND) {}
            uint8_t s = (uint8_t)NRF_RADIO->RSSISAMPLE;
            if (s < best) best = s;
        } while (sniffer_now_us() - t0 < dwell_us);
        out[ch] = best;
        radio_disable();
    }
}
