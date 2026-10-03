// USB serial link between the dongle and tools/radio.py.
// Every frame is COBS-encoded and ends with a 0x00 byte. Decoded frame = type byte + body.
// All multi-byte fields are little-endian. Keep tools/radio.py in step with this file.
#pragma once
#include <stdint.h>

#define LINK_VERSION 1

// host -> dongle
enum {
    CMD_CONFIG = 0x01,  // body: link_config_t; applies and starts RX, replies EVT_STATUS (or EVT_TEXT on error)
    CMD_STOP = 0x02,    // replies EVT_STATUS
    CMD_STATUS = 0x03,  // replies EVT_STATUS
    CMD_SWEEP = 0x04,   // body: u16 dwell_us; stops RX, replies EVT_SWEEP
    CMD_DFU = 0x05,     // reboot into the Nordic USB bootloader (no reply)
};

// dongle -> host
enum {
    EVT_PACKET = 0x81,  // body: link_packet_t then `length` bytes
    EVT_STATUS = 0x82,  // body: link_status_t
    EVT_SWEEP = 0x83,   // body: u16 dwell_us, u8 peak[101] (-dBm, index = MHz above 2400)
    EVT_TEXT = 0x84,    // body: ASCII
};

typedef struct __attribute__((packed)) {
    uint8_t mode, frequency, prefix;
    uint32_t base;
    uint8_t balen, big_endian, lflen, s0len, s1len, statlen, maxlen, crc_len, crc_skip_addr;
    uint32_t crc_poly, crc_init;
    uint16_t hop_dwell_ms;
    uint8_t hop_count;
    uint8_t hop_list[40];
} link_config_t;

typedef struct __attribute__((packed)) {
    uint32_t timestamp_us;
    uint8_t frequency;
    int8_t rssi;
    uint8_t crc_ok;
    uint8_t length;
} link_packet_t;

typedef struct __attribute__((packed)) {
    uint8_t version;
    uint8_t running;
    uint32_t now_us;
    uint32_t received;
    uint32_t dropped;  // ring overflow: the PC did not read fast enough
    link_config_t config;
} link_status_t;

// tools/radio.py CONFIG_FMT / STATUS_FMT / PACKET_FMT sizes
_Static_assert(sizeof(link_config_t) == 67, "link_config_t layout changed: update tools/radio.py");
_Static_assert(sizeof(link_status_t) == 81, "link_status_t layout changed: update tools/radio.py");
_Static_assert(sizeof(link_packet_t) == 8, "link_packet_t layout changed: update tools/radio.py");
