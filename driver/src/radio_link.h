// Driver-side mirror of the dongle link (radio-fw/src/link.h, link v3) plus its two transports'
// framing: COBS frames on a byte stream, and that stream tunnelled through 64-byte USB HID reports
// (the Steam Frame kernel has no CDC ACM, docs/re/DEV-1.md §5).
//
// Only what the driver sends or reads is mirrored. driver/test/link_check_test.cpp compiles this
// header next to radio-fw/src/link.h and checks every size and offset, so the two can't drift
// silently. Portable (no SteamVR, no Linux headers): the host tests build it on Windows too.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tf {
namespace radio {

constexpr uint8_t kLinkVersion = 3;
constexpr int kMaxSlots = 5;
constexpr size_t kMaxFrame = 300;
constexpr uint16_t kUsbVid = 0x1209, kUsbPid = 0x0001;  // radio-fw/src/usb_descriptors.c

enum Cmd : uint8_t {
    CMD_STOP = 0x02,
    CMD_HELLO = 0x06,
    CMD_HOST_START = 0x10,
    CMD_HOST_STATUS = 0x11,
    CMD_PAIR_START = 0x12,
    CMD_PAIR_STOP = 0x13,
    CMD_CONNECT = 0x14,
    CMD_DISCONNECT = 0x15,
    CMD_REG_READ = 0x16,
    CMD_REG_WRITE = 0x17,
    CMD_REG_SUBSCRIBE = 0x18,
    CMD_LED = 0x19,
    CMD_HAPTIC = 0x1A,
    CMD_TIME_PING = 0x1B,
    CMD_PAIR_LIST = 0x1E,
    CMD_PAIR_FORGET = 0x1F,
};

enum Evt : uint8_t {
    EVT_TEXT = 0x84,
    EVT_RESULT = 0x85,
    EVT_HELLO = 0x86,
    EVT_HOST_STATUS = 0x87,
    EVT_ADVERT = 0x88,
    EVT_PAIR = 0x89,
    EVT_CONN = 0x8A,
    EVT_REG = 0x8B,
    EVT_INPUT = 0x8C,
    EVT_IMU = 0x8D,
    EVT_TIME = 0x8E,
    EVT_UPLINK = 0x8F,
    EVT_SAMPLE = 0x90,  // LINK_HOST_COMPACT: one input + IMU sample (link_sample_t)
    EVT_SOF = 0x91,     // informational, once a second
    EVT_PAIRINGS = 0x92,
};

enum Caps : uint16_t {
    CAP_HOST = 1u << 1,
    CAP_PLACEHOLDER = 1u << 3,
    CAP_STORE = 1u << 4,  // flash identity + pairings (HOST_STORED, PAIR_LIST / PAIR_FORGET)
    CAP_HID = 1u << 5,
    CAP_REAL_INPUT = 1u << 12,
};

enum Status : uint8_t {
    LINK_OK = 0,
    LINK_ERR_ARGS = 1,
    LINK_ERR_STATE = 2,
    LINK_ERR_BUSY = 3,
    LINK_ERR_TIMEOUT = 4,
    LINK_ERR_PENDING_RE = 5,
    LINK_ERR_NO_SLOT = 6,
    LINK_ERR_CRYPTO = 7,
    LINK_ERR_REJECTED = 8,
    LINK_ERR_UNKNOWN_CMD = 9,
    LINK_ERR_NOT_CONNECTED = 10,
    LINK_ERR_QUEUE_FULL = 11,
};
const char* StatusName(uint8_t status);

enum HostFlags : uint8_t {
    HOST_AUTO_ACCEPT = 1u << 0,
    HOST_DM_BEACONS = 1u << 1,
    HOST_RAW_UPLINKS = 1u << 2,
    HOST_PLACEHOLDER = 1u << 3,  // loopback only (our fake controller)
    HOST_COMPACT = 1u << 4,      // EVT_SAMPLE instead of EVT_INPUT + EVT_IMU (needed on HID: 64 B/ms)
    HOST_STORED = 1u << 5,       // the dongle's flash identity and pairings (netaddr/key ignored)
};
enum { FORGET_ALL = 1u << 0, FORGET_IDENTITY = 1u << 1 };
enum LinkHand : uint8_t { HAND_UNKNOWN = 0, HAND_LEFT = 1, HAND_RIGHT = 2 };

enum SlotState : uint8_t { SLOT_FREE = 0, SLOT_WAITING = 1, SLOT_NEGOTIATING = 2, SLOT_CONNECTED = 3, SLOT_LOST = 4 };
enum PairState : uint8_t {
    PAIR_IDLE = 0, PAIR_SCANNING = 1, PAIR_LINKING = 2, PAIR_KEY_EXCHANGE = 3, PAIR_PROVISION = 4,
    PAIR_DONE = 5, PAIR_FAILED = 6, PAIR_STOPPED = 7,
};
enum { PAIR_AUTO = 1u << 0 };
enum RegKind : uint8_t { REG_READ = 0, REG_WRITE_ACK = 1, REG_NOTIFY = 2 };
enum LedMode : uint8_t { LED_OFF = 0, LED_ON = 1, LED_STROBE = 2 };
enum HapticMode : uint8_t { HAPTIC_STOP = 0, HAPTIC_SIMPLE = 1, HAPTIC_PCM = 2 };

// Sample flags (link_input_t / link_imu_t / link_sample_t).
enum { SAMPLE_PLACEHOLDER = 1u << 0, SAMPLE_ARRIVAL_TIME = 1u << 1, SAMPLE_SCALE_GUESSED = 1u << 2 };

// Controller command register 0x32 imu_config (docs/re/PERIPHERALS.md §3.2).
constexpr uint8_t kRegImuConfig = 0x32;

#pragma pack(push, 1)
struct ResultEvt { uint8_t tag, cmd, status, detail; };
struct HelloEvt {
    uint8_t version, mode;
    uint16_t caps;
    uint32_t build;
    uint64_t dongle_id, now_us;
    uint8_t max_slots, reserved[3];
};
struct HostStart {
    uint8_t tag, flags;
    uint16_t session_nonce;
    uint32_t netaddr;
    uint8_t link_key[16];
    uint8_t chmap[5];
    int8_t tx_power_dbm;
};
struct PairStart { uint8_t tag, flags; uint16_t timeout_s; uint64_t device_id; };
struct PairEvt {
    uint64_t t_us;
    uint8_t state, status, step, hand;  // hand: LinkHand
    uint64_t device_id;
    uint32_t netaddr;
};
struct PairForget { uint8_t tag, flags; uint16_t reserved; uint64_t device_id; };
struct Pairings { uint32_t netaddr; uint8_t count, flags; uint16_t writes_left; };  // + count Pairing
struct Pairing { uint64_t device_id; uint8_t slot, hand; uint16_t reserved; };
struct Connect { uint8_t tag, slot, flags, reserved; uint64_t device_id; };
struct ConnEvt {
    uint64_t t_us;
    uint8_t slot, state, reason;
    int8_t rssi;
    uint64_t device_id;
    uint16_t pulsar_version, reserved;
};
struct RegCmd { uint8_t tag, slot, reg, len; };
struct RegEvt {
    uint64_t t_us;
    uint8_t tag, slot, reg, kind, status, len;
};
// EVT_INPUT. Notification registers per docs/re/PERIPHERALS.md §4.1 (relayout agreed with BUILD-1).
struct InputEvt {
    uint64_t t_us;
    uint8_t slot, flags;
    uint16_t seq;
    uint8_t buttons;      // ntf 4: b0 A/X, b1 B/Y, b2 stick click, b3 system/menu
    uint8_t battery_pct;  // ntf 0, 0xFF unknown
    uint16_t touch;       // ntf 9, 12 bits
    int16_t stick[2];     // ntf 2
    uint16_t trigger;     // ntf 3 bits 0..11
    uint16_t grip;        // ntf 3 bits 12..23
    uint16_t pressure;    // ntf 0x15, 12-bit
};
struct ImuEvt {
    uint64_t t_us;
    uint8_t slot, flags;
    uint16_t seq;
    int32_t accel[3], gyro[3];
    int16_t temp_raw;
    uint8_t bits, accel_fs_g;
    uint16_t gyro_fs_dps, reserved;
};
// EVT_SAMPLE (LINK_HOST_COMPACT): InputEvt followed by the raw IMU counts.
struct SampleEvt {
    InputEvt in;
    int16_t accel[3], gyro[3];
};
struct Led {
    uint8_t tag, slot, mode, intensity;
    uint32_t period_us, on_us;
    int32_t phase_us;  // pulse CENTRE on the dongle clock, mod period (reg 0x28 d)
    uint32_t led_mask;
};
struct Haptic {
    uint8_t tag, slot, mode, amplitude;
    uint16_t freq_hz, duration_ms;
    uint8_t pcm_len, reserved;
};
struct TimePing { uint8_t tag, reserved[3]; uint32_t seq; uint64_t host_t; };
struct TimePong { uint8_t tag, reserved[3]; uint32_t seq; uint64_t host_t, dongle_rx_us, dongle_tx_us; };
#pragma pack(pop)

static_assert(sizeof(ResultEvt) == 4, "link_result_t");
static_assert(sizeof(HelloEvt) == 28, "link_hello_t");
static_assert(sizeof(HostStart) == 30, "link_host_start_t");
static_assert(sizeof(PairStart) == 12, "link_pair_start_t");
static_assert(sizeof(PairEvt) == 24, "link_pair_event_t");
static_assert(sizeof(PairForget) == 12, "link_pair_forget_t");
static_assert(sizeof(Pairings) == 8, "link_pairings_t");
static_assert(sizeof(Pairing) == 12, "link_pairing_t");
static_assert(sizeof(Connect) == 12, "link_connect_t");
static_assert(sizeof(ConnEvt) == 24, "link_conn_event_t");
static_assert(sizeof(RegCmd) == 4, "link_reg_cmd_t");
static_assert(sizeof(RegEvt) == 14, "link_reg_event_t");
static_assert(sizeof(InputEvt) == 26, "link_input_t");
static_assert(sizeof(ImuEvt) == 44, "link_imu_t");
static_assert(sizeof(SampleEvt) == 38, "link_sample_t");
static_assert(sizeof(Led) == 20, "link_led_t");
static_assert(sizeof(Haptic) == 10, "link_haptic_t");
static_assert(sizeof(TimePing) == 16, "link_time_ping_t");
static_assert(sizeof(TimePong) == 32, "link_time_pong_t");

// ---------------------------------------------------------------------------------------------
// COBS framing: every frame is COBS-encoded and ends with 0x00.

// Appends the encoded frame (with the trailing 0x00) to out.
void CobsEncode(const uint8_t* data, size_t n, std::vector<uint8_t>* out);
// Decodes one frame without its 0x00. False on a malformed frame.
bool CobsDecode(const uint8_t* data, size_t n, std::vector<uint8_t>* out);

// Splits a byte stream into decoded frames (type byte + body). Feed it whatever the transport
// read; it keeps partial frames across calls and drops malformed or oversized ones.
class FrameDecoder {
public:
    // Calls fn(const uint8_t* frame, size_t n) for every complete frame in data.
    template <class Fn>
    void Feed(const uint8_t* data, size_t n, Fn&& fn) {
        for (size_t i = 0; i < n; i++) {
            if (data[i] != 0) {
                if (raw_.size() < 2 * kMaxFrame) raw_.push_back(data[i]);
                else overflow_ = true;
                continue;
            }
            if (!raw_.empty() && !overflow_ && CobsDecode(raw_.data(), raw_.size(), &frame_) && !frame_.empty())
                fn(frame_.data(), frame_.size());
            else if (!raw_.empty())
                bad_++;
            raw_.clear();
            overflow_ = false;
        }
    }
    uint64_t bad_frames() const { return bad_; }
    void Reset() { raw_.clear(), overflow_ = false; }

private:
    std::vector<uint8_t> raw_, frame_;
    bool overflow_ = false;
    uint64_t bad_ = 0;
};

// Builds one command frame: type byte + body, COBS-encoded.
std::vector<uint8_t> EncodeCommand(uint8_t cmd, const void* body, size_t n, const void* tail = nullptr,
                                   size_t tail_n = 0);

// ---------------------------------------------------------------------------------------------
// HID tunnel (agreed with BUILD-1): vendor HID, no report IDs, 64-byte reports both ways.
// report[0] = n (0..63), report[1..n] = the next n bytes of the COBS stream, rest zero.
// n = 0 is a keepalive. hidraw writes carry a leading 0x00 report-ID byte (65 bytes).
constexpr size_t kHidReport = 64;
constexpr size_t kHidPayload = kHidReport - 1;

// Appends ceil(n/63) reports (64 bytes each) carrying the stream bytes.
void HidPack(const uint8_t* stream, size_t n, std::vector<uint8_t>* reports);
// Stream bytes of one received report; false if the length byte is invalid.
bool HidUnpack(const uint8_t* report, size_t n, const uint8_t** payload, size_t* payload_n);

}  // namespace radio
}  // namespace tf
