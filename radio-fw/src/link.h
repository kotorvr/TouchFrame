// USB serial link between the dongle and the PC (tools/radio.py, the driver's RadioSource).
//
// Framing: every frame is COBS-encoded and ends with a 0x00 byte. Decoded frame = type byte + body.
// All multi-byte fields are little-endian; all structs are packed. Keep tools/radio.py in step with
// this file: both sides assert the struct sizes (the _Static_asserts at the bottom, and
// radio.py's FORMATS table).
//
// ------------------------------------------------------------------------------------------------
// Link v3 (host mode). Overview for driver authors (BUILD-2):
//
// * The dongle runs one MODE at a time (link_mode): IDLE, SNIFFER (CMD_CONFIG), HOST
//   (CMD_HOST_START) or FAKE_CTRL (CMD_FAKE_START, the loopback rig). CMD_STOP stops any mode.
// * Start with CMD_HELLO: it returns the link version and capability bits. Refuse to run if
//   version != LINK_VERSION. The LINK_CAP_REAL_* bits say which on-air formats are pinned by RE;
//   for the others the dongle either answers LINK_ERR_PENDING_RE or, with LINK_HOST_PLACEHOLDER,
//   uses TouchFrame's own placeholder formats (only our fake controller speaks them).
// * Host-mode commands (0x06 and up) all start with a `tag` byte. The dongle answers each one with
//   exactly one EVT_RESULT carrying the same tag (plus, for some, a typed event before it). Tags
//   are the caller's; 0 is fine if you don't correlate. Asynchronous events (EVT_CONN, EVT_INPUT,
//   EVT_IMU, EVT_REG notifications, EVT_ADVERT, EVT_PAIR) may arrive at any time.
// * Clock: every t_us is the dongle's microsecond clock (TIMER0, 64-bit extended, starts at
//   boot). It is the Pulsar sync clock: host beacons carry its low 48 bits, so controllers that
//   timestamp in sync-clock units are already on it. Map it to CLOCK_MONOTONIC_RAW with
//   CMD_TIME_PING (see link_time_pong_t). Sniffer packets (link_packet_t) carry its low 32 bits.
// * Controllers live in slots 0..4 (LINK_MAX_SLOTS). On air, slot s transmits with access-address
//   prefix s+1 (docs/PROTOCOL.md Q1).
// * Identity: the dongle stores nothing in flash. The driver owns the host identity (netaddr, link
//   key, session nonce) and the list of paired controllers, persists them, and passes them in
//   CMD_HOST_START / CMD_CONNECT after every dongle reset.
// * Events go out only while the port is open (DTR set). Host mode keeps running with the port
//   closed (controllers stay connected across a driver restart); events are dropped and counted.
// ------------------------------------------------------------------------------------------------
#pragma once
#include <stdint.h>

#define LINK_VERSION 3

#define LINK_MAX_SLOTS 5     // PULSAR_NUM_DEVICE_SLOTS + PULSAR_NUM_AUXILIARY_DEVICE_SLOTS
#define LINK_REG_MAX 32      // largest register payload in CMD_REG_WRITE / EVT_REG
#define LINK_PCM_MAX 48      // largest PCM block in one CMD_HAPTIC
#define LINK_UPLINK_MAX 130  // device-connected MAXLEN (PROTOCOL Q1)
#define LINK_MAX_FRAME 300   // largest decoded frame either way (type byte + body)

// host -> dongle
enum {
    // v2 sniffer commands, unchanged.
    CMD_CONFIG = 0x01,  // body: link_config_t; starts SNIFFER mode, replies EVT_STATUS (or EVT_TEXT on error)
    CMD_STOP = 0x02,    // stops any mode (sniffer, host, fake controller); replies EVT_STATUS
    CMD_STATUS = 0x03,  // replies EVT_STATUS (sniffer view; use CMD_HOST_STATUS in host mode)
    CMD_SWEEP = 0x04,   // body: u16 dwell_us; stops any mode, replies EVT_SWEEP
    CMD_DFU = 0x05,     // reboot into the Nordic USB bootloader (no reply)

    // v3. Every body starts with a u8 tag; every command gets one EVT_RESULT with that tag.
    CMD_HELLO = 0x06,        // link_tag_t                -> EVT_HELLO, EVT_RESULT
    CMD_HOST_START = 0x10,   // link_host_start_t         -> EVT_RESULT (starts beacons)
    CMD_HOST_STATUS = 0x11,  // link_tag_t                -> EVT_HOST_STATUS, EVT_RESULT
    CMD_PAIR_START = 0x12,   // link_pair_start_t         -> EVT_RESULT, then EVT_ADVERT / EVT_PAIR
    CMD_PAIR_STOP = 0x13,    // link_tag_t                -> EVT_PAIR(STOPPED), EVT_RESULT
    CMD_CONNECT = 0x14,      // link_connect_t            -> EVT_RESULT, later EVT_CONN
    CMD_DISCONNECT = 0x15,   // link_disconnect_t         -> EVT_RESULT, EVT_CONN(DISCONNECTED)
    CMD_REG_READ = 0x16,     // link_reg_cmd_t (no data)  -> EVT_RESULT, later EVT_REG(READ)
    CMD_REG_WRITE = 0x17,    // link_reg_cmd_t + data     -> EVT_RESULT, later EVT_REG(WRITE_ACK)
    CMD_REG_SUBSCRIBE = 0x18,// link_reg_sub_t            -> EVT_RESULT, then EVT_REG(NOTIFY) stream
    CMD_LED = 0x19,          // link_led_t                -> EVT_RESULT
    CMD_HAPTIC = 0x1A,       // link_haptic_t + pcm bytes -> EVT_RESULT
    CMD_TIME_PING = 0x1B,    // link_time_ping_t          -> EVT_TIME (no EVT_RESULT: keep it lean)
    CMD_FAKE_START = 0x1C,   // link_fake_start_t         -> EVT_RESULT (loopback rig, second dongle)
    CMD_SELFTEST = 0x1D,     // link_tag_t                -> EVT_TEXT lines, EVT_RESULT (detail = failed-test bits)
};

// dongle -> host
enum {
    EVT_PACKET = 0x81,       // sniffer: link_packet_t then `length` bytes
    EVT_STATUS = 0x82,       // link_status_t (sniffer view)
    EVT_SWEEP = 0x83,        // u16 dwell_us, u8 peak[101] (-dBm, index = MHz above 2400)
    EVT_TEXT = 0x84,         // ASCII, for humans and logs
    EVT_RESULT = 0x85,       // link_result_t
    EVT_HELLO = 0x86,        // link_hello_t
    EVT_HOST_STATUS = 0x87,  // link_host_status_t
    EVT_ADVERT = 0x88,       // link_advert_t: a controller advertising in pairing mode
    EVT_PAIR = 0x89,         // link_pair_event_t: pairing progress / result
    EVT_CONN = 0x8A,         // link_conn_event_t: a slot changed state
    EVT_REG = 0x8B,          // link_reg_event_t then `len` bytes
    EVT_INPUT = 0x8C,        // link_input_t
    EVT_IMU = 0x8D,          // link_imu_t
    EVT_TIME = 0x8E,         // link_time_pong_t
    EVT_UPLINK = 0x8F,       // link_uplink_t then `len` bytes (debug, LINK_HOST_RAW_UPLINKS)
};

enum link_mode { LINK_MODE_IDLE = 0, LINK_MODE_SNIFFER = 1, LINK_MODE_HOST = 2, LINK_MODE_FAKE_CTRL = 3 };

// EVT_RESULT.status
enum link_status_code {
    LINK_OK = 0,
    LINK_ERR_ARGS = 1,           // malformed body or out-of-range field
    LINK_ERR_STATE = 2,          // wrong mode (e.g. CMD_CONNECT before CMD_HOST_START)
    LINK_ERR_BUSY = 3,           // e.g. pairing already running
    LINK_ERR_TIMEOUT = 4,
    LINK_ERR_PENDING_RE = 5,     // the on-air format is not pinned yet (see LINK_CAP_REAL_*)
    LINK_ERR_NO_SLOT = 6,
    LINK_ERR_CRYPTO = 7,
    LINK_ERR_REJECTED = 8,       // the controller refused
    LINK_ERR_UNKNOWN_CMD = 9,
    LINK_ERR_NOT_CONNECTED = 10, // slot has no connected controller
    LINK_ERR_QUEUE_FULL = 11,    // downlink queue for that slot is full; retry later
};

// link_hello_t.caps
enum {
    LINK_CAP_SNIFFER = 1u << 0,
    LINK_CAP_HOST = 1u << 1,
    LINK_CAP_FAKE_CTRL = 1u << 2,
    LINK_CAP_PLACEHOLDER = 1u << 3,       // LINK_HOST_PLACEHOLDER formats available (loopback only)
    // Set when the matching on-air format is pinned by RE and implemented for real controllers.
    LINK_CAP_REAL_PAIRING = 1u << 8,      // discovery + 0x12/0x11 exchange (PROTOCOL Q2)
    LINK_CAP_REAL_CONN_NEG = 1u << 9,     // connected-link negotiation / slot lock (RE-1)
    LINK_CAP_REAL_NONCE = 1u << 10,       // steady-state CCM nonce (RE-1)
    LINK_CAP_REAL_HREG = 1u << 11,        // register read / write / subscribe (RE-1)
    LINK_CAP_REAL_INPUT = 1u << 12,       // EVT_INPUT from real controllers (RE-1 + RE-2)
    LINK_CAP_REAL_IMU = 1u << 13,         // EVT_IMU from real controllers (RE-2)
    LINK_CAP_REAL_LED = 1u << 14,         // CMD_LED (RE-2)
    LINK_CAP_REAL_HAPTIC = 1u << 15,      // CMD_HAPTIC (RE-2)
};

// link_host_start_t.flags
enum {
    LINK_HOST_AUTO_ACCEPT = 1u << 0,  // accept any controller that negotiates with our netaddr+key
                                      // (else only those named by CMD_CONNECT)
    LINK_HOST_DM_BEACONS = 1u << 1,   // send DM beacons on 2402 so seeking controllers find us (normal: on)
    LINK_HOST_RAW_UPLINKS = 1u << 2,  // also report every uplink as EVT_UPLINK (debug, chatty)
    LINK_HOST_PLACEHOLDER = 1u << 3,  // use TouchFrame placeholder formats where RE is pending.
                                      // ONLY for loopback against our fake controller (CMD_FAKE_START).
};

//------------------------------------------------------------------ v2 sniffer structs (unchanged)

typedef struct __attribute__((packed)) {
    uint8_t mode, frequency;
    uint32_t base0, base1;  // base0/prefix[0] = logical addr 0; base1/prefix[1..7] = logical addrs 1..7
    uint8_t prefix[8];      // AP0..AP7
    uint8_t rx_mask;        // RXADDRESSES: bit n = receive logical address n
    uint8_t balen, big_endian, lflen, s0len, s1len, statlen, maxlen, crc_len, crc_skip_addr;
    uint32_t crc_poly, crc_init;
    uint16_t hop_dwell_ms;
    uint8_t hop_count;
    uint8_t hop_list[40];
    uint8_t follow;     // connected-link beacon follow (needs CRC on and follow_rx in rx_mask)
    uint8_t follow_rx;  // logical address the beacons arrive on (host beacon = AP1 = 1)
} link_config_t;

typedef struct __attribute__((packed)) {
    uint32_t timestamp_us;  // low 32 bits of the dongle clock
    uint8_t frequency;
    int8_t rssi;
    uint8_t crc_ok;
    uint8_t rxmatch;  // logical address that matched (0..7)
    uint8_t length;
} link_packet_t;

typedef struct __attribute__((packed)) {
    uint8_t version;
    uint8_t running;          // sniffer running
    uint32_t now_us;
    uint32_t received;
    uint32_t dropped;         // ring overflow: the PC did not read fast enough
    uint32_t follow_beacons;  // beacons that re-synced the hop (follow mode)
    uint32_t follow_blind;    // periods advanced without hearing a beacon
    uint8_t follow_locked;
    link_config_t config;
} link_status_t;

//------------------------------------------------------------------ v3 common

typedef struct __attribute__((packed)) {
    uint8_t tag;
} link_tag_t;

typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t cmd;     // the command this answers
    uint8_t status;  // link_status_code
    uint8_t detail;  // command-specific (slot, failed-test bits, ...)
} link_result_t;

typedef struct __attribute__((packed)) {
    uint8_t version;    // LINK_VERSION
    uint8_t mode;       // link_mode
    uint16_t caps;      // LINK_CAP_*
    uint32_t build;     // firmware build id (yyyymmdd of the build, informational)
    uint64_t dongle_id; // FICR DEVICEID of this dongle
    uint64_t now_us;    // dongle clock when HELLO was answered
    uint8_t max_slots;  // LINK_MAX_SLOTS
    uint8_t reserved[3];
} link_hello_t;

//------------------------------------------------------------------ host mode

// CMD_HOST_START: become the Pulsar host. Beacons start at once (2000 us period, CSA#1 hop over
// `chmap`). Stops any other mode. Calling it again while running applies the new identity and
// drops every connection.
typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t flags;           // LINK_HOST_*
    uint16_t session_nonce;  // beacon bytes 6..7 (PROTOCOL Q1); pick one at random per host start
    uint32_t netaddr;        // connected-link base address, handed to controllers at pairing
    uint8_t link_key[16];    // AES-128 link key, handed to controllers at pairing
    uint8_t chmap[5];        // 37-bit logical channel map, LSB first; all-ones = every channel. >= 8 bits set
    int8_t tx_power_dbm;     // nRF52840 TXPOWER: -40..+8 (rounded down to a supported step)
} link_host_start_t;

enum link_slot_state {
    LINK_SLOT_FREE = 0,         // nothing assigned
    LINK_SLOT_WAITING = 1,      // CMD_CONNECT named a controller; waiting for it to seek us
    LINK_SLOT_NEGOTIATING = 2,  // connection negotiation in progress
    LINK_SLOT_CONNECTED = 3,    // locked; uplinks arriving
    LINK_SLOT_LOST = 4,         // was connected, uplinks stopped (it will seek again)
};

typedef struct __attribute__((packed)) {
    uint8_t state;        // link_slot_state
    int8_t rssi;          // last uplink, dBm
    uint16_t pulsar_version;  // controller's, from negotiation (0x1701 expected), 0 if unknown
    uint64_t device_id;   // controller FICR DEVICEID, 0 if none
    uint32_t rx_packets;  // uplinks received (CRC ok)
    uint32_t rx_bad_mic;  // uplinks whose CCM MIC failed
    uint64_t last_rx_us;  // dongle clock of the last good uplink, 0 if none
} link_slot_status_t;

typedef struct __attribute__((packed)) {
    uint8_t version;
    uint8_t mode;          // link_mode
    uint8_t host_flags;    // LINK_HOST_* in effect
    uint8_t pair_state;    // link_pair_state
    uint64_t now_us;
    uint32_t netaddr;
    uint32_t beacons;      // beacons sent (incl. DM)
    uint32_t dm_beacons;   // of which DM beacons on 2402
    uint32_t uplinks;      // CRC-good uplinks, all slots
    uint32_t crc_errors;   // CRC-bad packets heard
    uint32_t late_beacons; // beacon periods where TX could not be scheduled in time
    uint32_t events_dropped;  // events lost because the PC was not reading
    uint8_t channel_mhz;   // current hop channel (MHz above 2400)
    uint8_t reserved[3];
    link_slot_status_t slot[LINK_MAX_SLOTS];
} link_host_status_t;

//------------------------------------------------------------------ pairing

enum link_pair_state {
    LINK_PAIR_IDLE = 0,
    LINK_PAIR_SCANNING = 1,    // listening for adverts on 2402
    LINK_PAIR_LINKING = 2,     // opening the 2426 MHz DM link with the chosen controller
    LINK_PAIR_KEY_EXCHANGE = 3,// 0x12 SetupX25519Keys sent / ECDH running
    LINK_PAIR_PROVISION = 4,   // 0x11 PairingData sent
    LINK_PAIR_DONE = 5,        // the controller holds our netaddr + key: CMD_CONNECT it next
    LINK_PAIR_FAILED = 6,      // see link_pair_event_t.status
    LINK_PAIR_STOPPED = 7,     // CMD_PAIR_STOP or timeout while scanning
};

enum {
    LINK_PAIR_AUTO = 1u << 0,  // pair the first advertiser that matches device_id (0 = any).
                               // Without it: scan only, report EVT_ADVERT, then call again with an id.
};

// CMD_PAIR_START: needs host mode (the netaddr + key from CMD_HOST_START are what gets provisioned).
// Pairing takes the radio exclusively: beacons pause until it ends, so connected controllers drop
// and seek again afterwards. (The Quest interleaves DM scans with beacons; not needed here.)
typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t flags;        // LINK_PAIR_*
    uint16_t timeout_s;   // give up after this long (0 = 60 s)
    uint64_t device_id;   // pair only this controller; 0 = any
} link_pair_start_t;

typedef struct __attribute__((packed)) {
    uint64_t t_us;
    uint64_t device_id;       // advert bytes 5..12 (FICR DEVICEID); the pairing base is its low word
    int8_t rssi;
    uint8_t type;             // advert byte 0 (2; 1 = older variant)
    uint16_t pulsar_version;  // advert bytes 1..2 (0x1701)
    uint16_t hw;              // advert bytes 3..4 (INFERRED meaning)
    uint8_t len;              // bytes used in raw[]
    uint8_t raw[32];          // the advert payload as received
} link_advert_t;

typedef struct __attribute__((packed)) {
    uint64_t t_us;
    uint8_t state;      // link_pair_state
    uint8_t status;     // link_status_code (LINK_OK unless FAILED/STOPPED)
    uint8_t step;       // pairing-link packets exchanged so far (diagnostic)
    uint8_t reserved;
    uint64_t device_id; // the controller being paired (0 while scanning)
    uint32_t netaddr;   // what it was given (DONE)
} link_pair_event_t;

//------------------------------------------------------------------ connections

// CMD_CONNECT: allow a paired controller into a slot. It connects when it next seeks (it does so
// on its own after pairing and after every link loss). slot 0xFF = first free slot; the EVT_RESULT
// detail byte carries the slot chosen.
typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t slot;        // 0..4, or 0xFF
    uint8_t flags;       // reserved, 0
    uint8_t reserved;
    uint64_t device_id;
} link_connect_t;

typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t slot;
    uint8_t flags;       // bit0: also forget it (slot becomes FREE, else WAITING)
} link_disconnect_t;

enum link_conn_reason {
    LINK_REASON_NONE = 0,
    LINK_REASON_REQUESTED = 1,  // CMD_DISCONNECT / CMD_STOP
    LINK_REASON_TIMEOUT = 2,    // uplinks stopped
    LINK_REASON_REJECTED = 3,   // negotiation failed (wrong key, version, ...)
    LINK_REASON_HOST_RESTART = 4,
};

typedef struct __attribute__((packed)) {
    uint64_t t_us;
    uint8_t slot;
    uint8_t state;            // link_slot_state
    uint8_t reason;           // link_conn_reason
    int8_t rssi;
    uint64_t device_id;
    uint16_t pulsar_version;
    uint16_t reserved;
} link_conn_event_t;

//------------------------------------------------------------------ registers (elk host registers)

// CMD_REG_READ (len = bytes wanted, 0 = the register's natural size; no data follows) and
// CMD_REG_WRITE (len bytes of data follow, len <= LINK_REG_MAX). Register ids are the elk hreg ids
// of PROTOCOL Q4 (buttons 9, analogs 3 / 0x17, touch 4 / 0x2b, battery 0x15, IMU 0xb / 0x16, ...).
typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t slot;
    uint8_t reg;
    uint8_t len;
} link_reg_cmd_t;

enum { LINK_SUB_UNSUBSCRIBE = 1u << 0 };

// CMD_REG_SUBSCRIBE: stream a register as EVT_REG(NOTIFY). period_ms 0 = on change.
typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t slot;
    uint8_t reg;
    uint8_t flags;       // LINK_SUB_*
    uint16_t period_ms;
} link_reg_sub_t;

enum link_reg_kind { LINK_REG_READ = 0, LINK_REG_WRITE_ACK = 1, LINK_REG_NOTIFY = 2 };

typedef struct __attribute__((packed)) {
    uint64_t t_us;    // when the uplink carrying it arrived (dongle clock)
    uint8_t tag;      // the request's tag (READ / WRITE_ACK), 0 for NOTIFY
    uint8_t slot;
    uint8_t reg;
    uint8_t kind;     // link_reg_kind
    uint8_t status;   // link_status_code (the controller can refuse)
    uint8_t len;      // data bytes that follow (<= LINK_REG_MAX)
} link_reg_event_t;

//------------------------------------------------------------------ typed streams

// EVT_INPUT: one input sample. Values are the controller's RAW host-register contents (PROTOCOL
// Q4); the dongle does not label or scale them, so the mapping can change in the driver without a
// reflash. Labels (which bit is A, which analog is the trigger) come from RE-2 / pulsar_input.py.
typedef struct __attribute__((packed)) {
    uint64_t t_us;        // sample time, dongle clock (uplink arrival until RE pins a sample stamp)
    uint8_t slot;
    uint8_t flags;        // bit0: placeholder format (loopback), bit1: sample time is the arrival time
    uint16_t seq;         // per-slot counter, increments by 1 per event (gaps = lost samples)
    uint16_t buttons;     // hreg 9, 12 bits
    uint16_t analog[4];   // 12-bit ADCs: [0],[1] = hreg 3 (A, B); [2],[3] = hreg 0x17 (C, D)
    uint8_t touch;        // bits0..3 = hreg 4, bit4 = hreg 0x2b
    uint8_t reserved;
    uint16_t battery;     // hreg 0x15, raw (mV INFERRED)
} link_input_t;

// EVT_IMU: one IMU sample, raw counts. Scale: accel_g = accel / 2^(bits-1) * accel_fs_g, likewise
// gyro in deg/s with gyro_fs_dps. Axes are the IMU's own; per-unit calibration is the driver's job.
typedef struct __attribute__((packed)) {
    uint64_t t_us;        // sample time, dongle clock (see link_input_t.t_us)
    uint8_t slot;
    uint8_t flags;        // bit0: placeholder format, bit1: sample time is the arrival time,
                          // bit2: scale fields are guesses (RE-2 pending)
    uint16_t seq;
    int32_t accel[3];
    int32_t gyro[3];
    int16_t temp_raw;
    uint8_t bits;         // significant bits per sample (16, or 20 for high-res FIFO)
    uint8_t accel_fs_g;   // full scale, +-g
    uint16_t gyro_fs_dps; // full scale, +-deg/s
    uint16_t reserved;
} link_imu_t;

//------------------------------------------------------------------ peripherals

enum link_led_mode { LINK_LED_OFF = 0, LINK_LED_ON = 1, LINK_LED_STROBE = 2 };

// CMD_LED: IR constellation LEDs. STROBE: on for on_us every period_us, the first edge at dongle
// time phase_us (mod period_us); the controller runs it off the shared Pulsar clock. ON may be
// refused if the controller caps the duty cycle (MASTER-PLAN G-LED): EVT_RESULT says.
typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t slot;
    uint8_t mode;         // link_led_mode
    uint8_t intensity;    // 0..255 (drive current, scaled; RE-2 pins the real range)
    uint32_t period_us;
    uint32_t on_us;
    int32_t phase_us;
    uint32_t led_mask;    // 0 = all LEDs
} link_led_t;

enum link_haptic_mode { LINK_HAPTIC_STOP = 0, LINK_HAPTIC_SIMPLE = 1, LINK_HAPTIC_PCM = 2 };

// CMD_HAPTIC: SIMPLE = a buzz of amplitude/freq_hz for duration_ms. PCM = `pcm_len` unsigned 8-bit
// samples at freq_hz follow the struct (<= LINK_PCM_MAX), queued after any PCM already playing.
typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t slot;
    uint8_t mode;         // link_haptic_mode
    uint8_t amplitude;    // 0..255
    uint16_t freq_hz;     // SIMPLE: vibration frequency; PCM: sample rate
    uint16_t duration_ms;
    uint8_t pcm_len;
    uint8_t reserved;
} link_haptic_t;

//------------------------------------------------------------------ time sync

// CMD_TIME_PING / EVT_TIME: NTP-style mapping of the dongle clock to the PC clock. The PC stamps
// host_t just before writing the ping and again (t_recv) when EVT_TIME arrives; the dongle stamps
// dongle_rx_us when the ping's last byte came out of the USB FIFO and dongle_tx_us when the reply
// was queued. Then
//   rtt    = (t_recv - host_t) - (dongle_tx_us - dongle_rx_us)
//   offset = (dongle_rx_us + dongle_tx_us)/2 - (host_t + t_recv)/2     [dongle = pc + offset]
// USB full speed polls every 1 ms, so single pings jitter by up to ~1 ms: ping at ~10 Hz, keep the
// lowest-rtt sample of each window, and fit drift (crystal: +-20 ppm) over a few seconds.
typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t reserved[3];
    uint32_t seq;
    uint64_t host_t;      // any PC clock (CLOCK_MONOTONIC_RAW ns suggested); echoed back
} link_time_ping_t;

typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t reserved[3];
    uint32_t seq;
    uint64_t host_t;
    uint64_t dongle_rx_us;
    uint64_t dongle_tx_us;
} link_time_pong_t;

//------------------------------------------------------------------ loopback rig

enum {
    LINK_FAKE_PAIRED = 1u << 0,      // start already paired to netaddr/link_key (skip advertising)
    LINK_FAKE_STREAM_INPUT = 1u << 1,// send synthetic input samples when connected
    LINK_FAKE_STREAM_IMU = 1u << 2,  // send synthetic IMU samples when connected
};

// CMD_FAKE_START: this dongle plays a Touch Plus. Unpaired, it advertises on 2402 and answers the
// 2426 pairing exchange like the controller SPL (0x12 / 0x11, real formats). Paired, it seeks the
// host's beacons, follows the hop and talks in its slot using the placeholder connected-link
// formats (the host must run with LINK_HOST_PLACEHOLDER). Reports EVT_PAIR / EVT_CONN for its own
// side. Stop with CMD_STOP.
typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint8_t flags;        // LINK_FAKE_*
    uint8_t slot;         // slot to ask for when paired (0..4)
    uint8_t reserved;
    uint64_t device_id;   // 0 = this dongle's FICR DEVICEID
    uint32_t netaddr;     // with LINK_FAKE_PAIRED
    uint8_t link_key[16]; // with LINK_FAKE_PAIRED
} link_fake_start_t;

//------------------------------------------------------------------ debug

enum {
    LINK_UP_CRC_OK = 1u << 0,
    LINK_UP_MIC_OK = 1u << 1,    // CCM MIC verified; data is plaintext
    LINK_UP_DECRYPTED = 1u << 2, // decryption attempted (else data is as received)
};

typedef struct __attribute__((packed)) {
    uint64_t t_us;
    uint8_t slot;         // 0..4 from the prefix; 0xFF = not an uplink prefix
    uint8_t channel_mhz;
    int8_t rssi;
    uint8_t flags;        // LINK_UP_*
    uint8_t len;          // payload bytes that follow (S0/LENGTH stripped)
} link_uplink_t;

// tools/radio.py FORMATS sizes. Changing any of these is a link version bump.
_Static_assert(sizeof(link_config_t) == 81, "link_config_t layout changed: update tools/radio.py");
_Static_assert(sizeof(link_status_t) == 104, "link_status_t layout changed: update tools/radio.py");
_Static_assert(sizeof(link_packet_t) == 9, "link_packet_t layout changed: update tools/radio.py");
_Static_assert(sizeof(link_tag_t) == 1, "link_tag_t");
_Static_assert(sizeof(link_result_t) == 4, "link_result_t");
_Static_assert(sizeof(link_hello_t) == 28, "link_hello_t");
_Static_assert(sizeof(link_host_start_t) == 30, "link_host_start_t");
_Static_assert(sizeof(link_slot_status_t) == 28, "link_slot_status_t");
_Static_assert(sizeof(link_host_status_t) == 44 + 5 * 28, "link_host_status_t");
_Static_assert(sizeof(link_pair_start_t) == 12, "link_pair_start_t");
_Static_assert(sizeof(link_advert_t) == 55, "link_advert_t");
_Static_assert(sizeof(link_pair_event_t) == 24, "link_pair_event_t");
_Static_assert(sizeof(link_connect_t) == 12, "link_connect_t");
_Static_assert(sizeof(link_disconnect_t) == 3, "link_disconnect_t");
_Static_assert(sizeof(link_conn_event_t) == 24, "link_conn_event_t");
_Static_assert(sizeof(link_reg_cmd_t) == 4, "link_reg_cmd_t");
_Static_assert(sizeof(link_reg_sub_t) == 6, "link_reg_sub_t");
_Static_assert(sizeof(link_reg_event_t) == 14, "link_reg_event_t");
_Static_assert(sizeof(link_input_t) == 26, "link_input_t");
_Static_assert(sizeof(link_imu_t) == 44, "link_imu_t");
_Static_assert(sizeof(link_led_t) == 20, "link_led_t");
_Static_assert(sizeof(link_haptic_t) == 10, "link_haptic_t");
_Static_assert(sizeof(link_time_ping_t) == 16, "link_time_ping_t");
_Static_assert(sizeof(link_time_pong_t) == 32, "link_time_pong_t");
_Static_assert(sizeof(link_fake_start_t) == 32, "link_fake_start_t");
_Static_assert(sizeof(link_uplink_t) == 13, "link_uplink_t");
