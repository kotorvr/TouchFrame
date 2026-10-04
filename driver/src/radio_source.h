// RadioSource: Touch Plus controllers through our nRF52840 dongle (radio-fw/, link v3).
//
// One worker thread owns the transport (hidraw on the Frame, tcp to tools/fake_dongle.py in
// tests) and runs the link session:
//   HELLO (version check) -> [PAIR_LIST] -> HOST_START (or adopt a dongle that is already hosting
//   as us, so controllers stay connected across a driver restart) -> stream.
// It pings the dongle at ping_hz for the time sync (dongle µs -> CLOCK_MONOTONIC_RAW, the clock
// XRService stamps IMU and camera frames with), and turns each sample into:
//   * IMU: raw counts -> m/s^2 and rad/s with the controller's own cmd 0x32 scale, rectified into
//     the LED-model frame (Rectifier: model = M (si - offset)), at the native 500 Hz;
//   * inputs: notification registers -> HandState (radio_decode.h MapInputs).
// Haptics go back as CMD_HAPTIC (re-sent while a long buzz lasts). With led_loop on, each
// connected hand runs an LedPhaseLoop fed by ObservePose()/LedStatsHit(), and its schedule goes
// out as CMD_LED in dongle time.
//
// Identity, two ways (link.h):
//   * stored (firmware with LINK_CAP_STORE, the normal case): the dongle keeps netaddr + key and
//     its pairings in flash and lets paired controllers in by itself (LINK_HOST_STORED). The
//     driver lists them (CMD_PAIR_LIST) and forgets a replaced one (CMD_PAIR_FORGET).
//   * driver-owned (older firmware, or identity_mode "driver"): netaddr, key and the paired list
//     live in the state file (compatible with `tools/radio.py host --identity`), sent with
//     HOST_START and CMD_CONNECT after every dongle reset.
// Either way the state file records which hand each controller is. The hand comes from the
// controller if the firmware learns it (EVT_PAIR hand, RE pending), else from RequestPair(hand),
// else the first free hand, right first.
#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "led_phase.h"
#include "protocol.h"
#include "radio_decode.h"
#include "radio_link.h"
#include "radio_transport.h"
#include "touch_source.h"
#include "time_sync.h"

namespace tf {
namespace radio {

// Host clock (CLOCK_MONOTONIC_RAW) in ns: XRService's clock.
int64_t HostNowNs();

class RadioSource : public ITouchSource {
public:
    struct Options {
        std::string transport = "hidraw";  // radio_transport.h MakeTransport spec
        std::string identity_path;          // state file (hands; identity in driver-owned mode)
        std::string identity_mode = "auto"; // auto (stored if the firmware can) | stored | driver
        bool compact = true;                // LINK_HOST_COMPACT; forced on for HID (64 B/ms)
        bool placeholder = false;           // LINK_HOST_PLACEHOLDER: loopback with our fake controller ONLY
        int tx_power_dbm = 8;
        double ping_hz = 20;
        std::string imu_cal[2];             // Meta calibration JSON per hand ("" = identity)
        bool led_loop = false;              // run the LED phase loop (camera tracking)
        LedPhaseLoop::Options led;
        double led_min_sync_span_s = 20;    // start the loop once the time sync's slope is solid
        std::function<void(const std::string&)> log;  // default: stderr
    };
    struct Callbacks {
        // t: host clock seconds (CLOCK_MONOTONIC_RAW). accel m/s^2 (specific force), gyro rad/s,
        // both in the LED-model frame.
        std::function<void(int hand, double t, const float accel[3], const float gyro[3])> imu;
        // Buttons/axes/battery; pose fields zero.
        std::function<void(int hand, const HandState& inputs, double t)> inputs;
        std::function<void(int hand, bool connected)> connection;
    };

    RadioSource(Options opt, Callbacks cb);
    ~RadioSource() override;

    bool Start() override;  // starts the worker; true even if no dongle is plugged in yet
    void Stop() override;
    void SendHaptic(int hand, float amplitude, float frequency, float duration_s) override;

    // Pair the next controller that advertises (or only device_id) as `hand`; it replaces that
    // hand's previous controller in the identity file.
    void RequestPair(int hand, uint64_t device_id = 0, int timeout_s = 60);
    // LED loop feedback: a pose block from XRService for this hand / an XRService LED match.
    void ObservePose(int hand, double t, bool valid);
    void LedStatsHit(int hand, double t);
    // XRService logged a controller-frame timestamp (host clock s), read by us at read_t.
    void FrameTimestamp(double read_t, double frame_t);

    struct HandStatus {
        bool connected = false;
        uint64_t device_id = 0;
        int slot = -1;
        uint64_t inputs = 0, imu = 0, gaps = 0, unsynced = 0;
        ImuScale scale;
        int led_state = -1;  // LedPhaseLoop::State, -1 = loop not running
        double led_centre_us = 0, led_width_us = 0, led_drift = 0;
    };
    struct LinkStatus {
        bool open = false, hosting = false;
        std::string transport;
        uint16_t caps = 0;
        double drift_ppm = 0, best_rtt_us = 0, sync_band_us = 0, sync_span_s = 0;
        uint64_t frames = 0, bad_frames = 0;
    };
    HandStatus hand_status(int hand) const;
    LinkStatus link_status() const;

private:
    enum SessionState { kClosed, kHello, kListing, kAdopting, kStarting, kRunning };
    struct Pending {
        uint8_t cmd = 0;
        int hand = -1;
        uint64_t device_id = 0;
        uint8_t reg = 0;
    };
    struct Hand {
        bool connected = false;
        uint64_t device_id = 0;
        int slot = -1;
        uint16_t seq_input = 0, seq_imu = 0;
        bool have_seq_input = false, have_seq_imu = false;
        double last_t = 0;  // last IMU/input stamp handed out (monotonic)
        ImuScale scale;
        bool scale_from_controller = false;
        int scale_reads = 0;
        Rectifier rect;
        HapticScheduler haptic;
        std::unique_ptr<LedPhaseLoop> led;
        int led_logged_state = -1;
        bool led_logged_fine = false;
        // The frame phase this hand last tracked at P (camera property: survives reconnects).
        bool have_phase = false;
        double phase_us = 0, phase_t = 0, phase_rate = 0;
        uint64_t inputs = 0, imu = 0, gaps = 0, unsynced = 0;
    };
    struct Identity {
        uint32_t netaddr = 0;
        uint8_t key[16] = {};
        std::map<uint64_t, int> paired;  // device id -> last slot (0xFF unknown)
        std::map<uint64_t, int> hand;    // device id -> 0 left / 1 right
    };

    void Run();
    void Session(Transport* t);
    void HandleFrame(const uint8_t* f, size_t n, int64_t now_ns);
    void OnResult(const ResultEvt& r);
    void OnConn(const ConnEvt& c);
    void OnSample(const InputEvt& in, const int32_t* acc, const int32_t* gyr, const ImuEvt* imu_evt, int64_t now_ns);
    void ConnectPaired();
    void StartHost(int64_t now);
    uint8_t HostFlags() const;
    void ForgetOrDrop(uint64_t device_id, int hand);
    void Send(uint8_t cmd, const void* body, size_t n, const void* tail = nullptr, size_t tail_n = 0);
    uint8_t Tag(const Pending& p);
    int HandOfSlot(int slot) const;
    int HandForDevice(uint64_t device_id);
    void Disconnected(int hand, const char* why);
    void LoadIdentity();
    void SaveIdentity();
    void Logf(const char* fmt, ...);
    void ServiceHands(int64_t now_ns);

    Options opt_;
    Callbacks cb_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    mutable std::mutex mu_;  // everything below that other threads touch
    Hand hands_[2];
    Identity id_;
    bool haptic_due_[2] = {false, false};
    Haptic haptic_cmd_[2] = {};
    struct PairRequest {
        bool pending = false, active = false;
        int hand = 0;
        uint64_t device_id = 0;
        int timeout_s = 60;
    } pair_;
    // Radio thread only.
    Transport* tr_ = nullptr;
    FrameDecoder dec_;
    TimeSync sync_;
    SessionState state_ = kClosed;
    bool stored_ = false;          // this session uses the dongle's flash identity
    bool restart_ = false;         // end the session (the dongle rebooted under us)
    double pairlist_due_s_ = 0;    // stored mode: re-read the pairings (hands) after a connect
    uint8_t hello_mode_ = 0;       // link_mode at HELLO
    uint32_t dongle_netaddr_ = 0;  // stored identity's netaddr (PAIR_LIST)
    std::map<uint8_t, Pending> pending_;
    uint8_t next_tag_ = 1;
    uint32_t ping_seq_ = 0;
    int64_t last_ping_ns_ = 0, last_pong_ns_ = 0, state_since_ns_ = 0, last_status_ns_ = 0;
    std::map<uint8_t, int64_t> result_logged_;  // cmd -> last time an error for it was logged
    LinkStatus link_;
};

// Reads and writes the identity file. Exposed for tests.
bool ParseIdentityJson(const std::string& text, uint32_t* netaddr, uint8_t key[16], std::map<uint64_t, int>* paired,
                       std::map<uint64_t, int>* hands);
std::string IdentityJson(uint32_t netaddr, const uint8_t key[16], const std::map<uint64_t, int>& paired,
                         const std::map<uint64_t, int>& hands);

}  // namespace radio
}  // namespace tf
