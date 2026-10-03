// Raw Nordic-proprietary receiver for studying the Quest <-> Touch Plus link.
#pragma once
#include <stdbool.h>
#include <stdint.h>

#define SNIFFER_MAX_HOPS 40

typedef struct {
    uint8_t mode;         // RADIO.MODE: 0 Nrf_1Mbit, 1 Nrf_2Mbit, 3 Ble_1Mbit, 4 Ble_2Mbit
    uint8_t frequency;    // MHz above 2400 (2 = 2402 discovery, 26 = 2426 pairing)
    uint32_t base0;       // BASE0: logical address 0
    uint32_t base1;       // BASE1: logical addresses 1..7
    uint8_t prefix[8];    // AP0..AP7
    uint8_t rx_mask;      // RXADDRESSES: which logical addresses to receive (bit n = address n)
    uint8_t balen;        // base address length in bytes, 2-4
    bool big_endian;      // PCNF1.ENDIAN (false = LSB first, BLE style)
    uint8_t lflen;        // PCNF0.LFLEN, bits
    uint8_t s0len;        // PCNF0.S0LEN, bytes
    uint8_t s1len;        // PCNF0.S1LEN, bits
    uint8_t statlen;      // PCNF1.STATLEN: extra bytes after the payload (3 with CRC off = keep the CRC)
    uint8_t maxlen;       // PCNF1.MAXLEN
    uint8_t crc_len;      // CRCCNF.LEN in bytes, 0 = off (accept everything matching the address)
    bool crc_skip_addr;   // CRCCNF.SKIPADDR
    uint32_t crc_poly;
    uint32_t crc_init;
    uint16_t hop_dwell_ms;
    uint8_t hop_count;    // 0: stay on `frequency`
    uint8_t hop_list[SNIFFER_MAX_HOPS];
    // Follow mode (Pulsar connected link): CRC-good packets on logical address `follow_rx` are
    // beacons; each one re-syncs the channel map and hop state, and the radio moves to the next
    // channel 1850 us after it (docs/PROTOCOL.md Q1). hop = (base0 & 0xFF) % 11 + 5.
    bool follow;
    uint8_t follow_rx;
} sniffer_config_t;

typedef struct {
    uint32_t timestamp_us;  // TIMER0 at ADDRESS (PPI channel 26)
    uint8_t frequency;
    int8_t rssi;
    uint8_t crc_ok;         // 1 when CRC was enabled and passed
    uint8_t rxmatch;        // logical address that matched (RXMATCH)
    uint8_t length;         // bytes in data[]: S0, LENGTH, S1 and payload as stored by EasyDMA
    uint8_t data[258];
} sniffer_packet_t;

typedef struct {
    uint32_t beacons;       // beacons that re-synced the hop state
    uint32_t blind_hops;    // hops taken without having heard that period's beacon
    bool locked;            // heard a beacon within the last 250 periods
} sniffer_follow_stats_t;

void sniffer_init(void);
bool sniffer_apply(const sniffer_config_t* cfg);  // reconfigure and (re)start RX; false if cfg is invalid
void sniffer_stop(void);
bool sniffer_running(void);
void sniffer_poll(void);                          // hop timing, call from the main loop
bool sniffer_pop(sniffer_packet_t* out);          // next captured packet, false if none
uint32_t sniffer_dropped(void);
uint32_t sniffer_received(void);
uint32_t sniffer_now_us(void);                    // the TIMER0 clock packets are stamped with
const sniffer_config_t* sniffer_config(void);
sniffer_follow_stats_t sniffer_follow_stats(void);

// Peak RSSI (positive dBm magnitude, e.g. 90 = -90 dBm) on every MHz from 2400 to 2500.
// Stops the sniffer; blocks for about 101 * dwell_us.
void sniffer_rssi_sweep(uint8_t out[101], uint16_t dwell_us);
