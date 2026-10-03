// Raw Nordic-proprietary receiver for studying the Quest <-> Touch Plus link.
#pragma once
#include <stdbool.h>
#include <stdint.h>

#define SNIFFER_MAX_HOPS 40

typedef struct {
    uint8_t mode;         // RADIO.MODE: 0 Nrf_1Mbit, 1 Nrf_2Mbit, 3 Ble_1Mbit, 4 Ble_2Mbit
    uint8_t frequency;    // MHz above 2400 (2 = 2402 discovery, 26 = 2426 pairing)
    uint8_t prefix;       // access address prefix byte (AP0)
    uint32_t base;        // access address base (BASE0)
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
} sniffer_config_t;

typedef struct {
    uint32_t timestamp_us;  // TIMER0 at ADDRESS (PPI channel 26)
    uint8_t frequency;
    int8_t rssi;
    uint8_t crc_ok;         // 1 when CRC was enabled and passed
    uint8_t length;         // bytes in data[]: S0, LENGTH, S1 and payload as stored by EasyDMA
    uint8_t data[258];
} sniffer_packet_t;

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

// Peak RSSI (positive dBm magnitude, e.g. 90 = -90 dBm) on every MHz from 2400 to 2500.
// Stops the sniffer; blocks for about 101 * dwell_us.
void sniffer_rssi_sweep(uint8_t out[101], uint16_t dwell_us);
