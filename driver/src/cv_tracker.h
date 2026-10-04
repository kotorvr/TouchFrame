// CvTracker: puts one controller into Valve's camera tracker (XRService) through vrserver's
// IVRBlockQueue channels, the same way driver_cv does for Steam Frame controllers
// (docs/FRAME-TRACKER.md §1, §2, §4 and §8).
//
// In:  an LED-model config (XRService controller JSON: lighthouse_config, imu, head, ...), then a
//      ~240 Hz IMU stream on XRService's clock (PushImu).
// Out: 6DoF poses from XRService, via the pose callback, already turned into SteamVR's frame the
//      way driver_cv does it (180° about X).
//
// Any feed can drive it: the clone validation (cv_clone.cpp) synthesizes IMU from a Frame
// controller's pose; later a Touch Plus radio source will push its real IMU.
//
// Order of operations (all from §8, do not change):
//  1. Create our pose queue (0x90, header 0x200, count 4, OwnerIsReader) and start reading it.
//  2. CONNECT (never Create) the shared /event and /data queues. They exist only once a Frame
//     controller has connected since SteamVR started; until then we wait and retry, because if
//     we created them, driver_cv (which always Creates) could no longer enrol a real controller.
//     Exception: Options::create_shared_queues (docs/re/DEV-1.md G-Touch-only, CONFIRMED to work)
//     Creates them with driver_cv's parameters when Connect still says QueueNotFound after
//     create_after_s. Cost: the first Frame controller turned on later in that SteamVR session
//     fails its own Create and gets no pose until SteamVR restarts (buttons/haptics still work).
//  3. Send the connect event with the JSON in both slots and both blockDataSize properties set on
//     the block before release.
//  4. IMU blocks then flow; poses come back on our queue.
//
// Re-announce (FRAME-TRACKER §9.3): a device announced while another controller holds its hand's
// tracker slot does not get the slot when it frees. Reannounce() sends a disconnect, then after
// ≥ 1.1 s connects again under a FRESH deviceId with its own new pose queue: XRService reads the
// event queue about once a second and skips deviceIds it already knows (AUDIT-1 F2/F3). Every
// event write is spaced ≥ 1.1 s from the previous one for the same reason.
#pragma once
#include <atomic>
#include <cstdint>
#include <ctime>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "blockqueue.h"
#include "cv_math.h"

namespace tf {
namespace cv {

// XRService stamps IMU and poses with oc::now_seconds(), which is clock_gettime(4) =
// CLOCK_MONOTONIC_RAW (libArcturusPerception 0x322070: `mov w0, #4; bl clock_gettime`). On the
// Frame it is ~0.1 s/h away from CLOCK_MONOTONIC, so the choice matters.
constexpr clockid_t kXrClock = CLOCK_MONOTONIC_RAW;
double NowSeconds(clockid_t clock = kXrClock);

// What a controller config carries that the driver itself needs.
struct ControllerConfig {
    std::string json;          // the config object to send (compact JSON)
    std::string serial;        // device_serial_number
    std::string model_number;
    std::string role;          // tracked_controller_role
    Pose model_from_imu;       // "imu" extrinsics (model = lighthouse_config / LED frame)
    Pose model_from_head;      // "head" extrinsics (the frame SteamVR reports for the device)
    int led_count = 0;
};

// Accepts a bare config object, an XRService log excerpt with {"default":{...},"onboard":{...}},
// or any text containing one; uses the object that has lighthouse_config. Optional overrides
// replace device_serial_number / model_number / tracked_controller_role before re-emitting the
// JSON. XRService accepts only "left_hand" and "right_hand" as roles (anything else becomes
// left_hand), and it keeps some per-role state: two controllers with the same role corrupt each
// other's pose history (docs/FRAME-TRACKER.md §9).
bool ParseControllerConfig(const std::string& text, ControllerConfig* out, std::string* err,
                           const std::string& serial_override = "",
                           const std::string& model_override = "",
                           const std::string& role_override = "");

// XRService's pose block is NOT the LED-model frame: it has the model's axes but the IMU's origin
// (measured against driver_cv's SteamVR pose, 2026-10-03: 0.85 mm / 0.32 deg residual; the
// onboard IMU extrinsic driver_cv uses has identity rotation). The device pose SteamVR shows is
//     flip(block) ∘ HeadFromPoseBlock(cfg).
Pose HeadFromPoseBlock(const struct ControllerConfig& cfg);

// One pose from XRService's pose block, plus the same pose in SteamVR's frame.
struct CvPose {
    uint32_t device_id = 0;
    bool valid = false;        // false: XRService reported "no pose" (timestamp -1)
    double t = 0;              // XRService clock seconds (same as the IMU)
    double recv_t = 0;         // NowSeconds() when we read it
    vrint::ControllerPoseBlock raw{};
    Pose pose;                 // pose-block frame (model axes, IMU origin) in SteamVR space (180° about X)
    V3 vel;                    // m/s, same rotation applied
    V3 ang_vel;                // as XRService reports it; driver_cv does not rotate it
};

// Converts a pose block the way driver_cv's readControllerPosesThread does (rotation (x=1) i.e.
// 180° about X on orientation, position and linear velocity; angular velocity untouched).
CvPose ConvertPoseBlock(const vrint::ControllerPoseBlock& b);

// The vrserver-internal interfaces; null if this runtime doesn't provide them.
vrint::IVRBlockQueue* BlockQueue();
vrint::IVRPaths* Paths();
std::string PoseQueueName(uint32_t device_id);

class CvTracker {
public:
    struct Options {
        uint32_t device_id = 40;       // keep 16..63: XRService sizes a table to deviceId+1
        uint64_t hardware_id = 0;      // 0: derive one ("TF" + device id)
        std::string config_json;       // sent in both event slots
        std::string serial;            // optional, /controllerConfigData/deviceSerialNumber
        const char* tag = "cv";        // log prefix
        // Experiment (DEV-1, G-Touch-only): on QueueNotFound, Create /event and /data ourselves
        // with driver_cv's parameters (0x6010 / 0x30, header 0x200, count 4, flags 0) instead of
        // waiting for a Frame controller. Destroyed again in Stop().
        bool create_shared_queues = false;
        double create_after_s = 0;            // ... after waiting this long for a Frame controller
        bool destroy_created_queues = true;   // Stop() destroys queues we created (experiment).
                                              // Touch-only use keeps them: re-Creating later would
                                              // fail driver_cv again, and vrserver frees them at exit.
    };
    using PoseCallback = std::function<void(const CvPose&)>;

    CvTracker(Options opt, PoseCallback cb);
    ~CvTracker();
    CvTracker(const CvTracker&) = delete;
    CvTracker& operator=(const CvTracker&) = delete;

    // Non-blocking: queues are set up on a worker thread that waits for the shared queues.
    bool Start();
    // Sends a disconnect event (if connected), stops reading and destroys our pose queue.
    void Stop();

    // One IMU sample: t on kXrClock seconds, accel m/s^2 and gyro rad/s in the config's IMU frame.
    // Dropped (returns false) until connected or while XRService isn't reading.
    bool PushImu(double t, const float accel[3], const float gyro[3], uint32_t flags = 0);

    // Announce again under new_device_id (16..63, not used before in this SteamVR session).
    void Reannounce(uint32_t new_device_id) { reannounce_to_ = new_device_id; }

    bool connected() const { return connected_; }
    uint32_t device_id() const { return device_id_; }
    bool created_shared_queues() const { return created_event_ || created_data_; }

    struct Stats {
        uint64_t imu_sent = 0, imu_dropped = 0, poses = 0, poses_valid = 0, connect_events = 0;
    };
    Stats stats() const;

private:
    void SetupLoop();
    void PoseLoop();
    bool SendEvent(uint32_t type);
    bool CreatePoseQueue(uint32_t id, vrint::BlockQueueHandle_t* out);
    bool DoReannounce(uint32_t new_id);

    Options opt_;
    PoseCallback cb_;
    vrint::IVRBlockQueue* bq_ = nullptr;
    vrint::IVRPaths* paths_ = nullptr;
    std::mutex pose_mu_;  // pose_q_ swaps (re-announce) vs the pose reader
    vrint::BlockQueueHandle_t pose_q_ = 0;
    std::atomic<uint32_t> device_id_{0}, reannounce_to_{0};
    bool derived_hwid_ = false;
    double last_event_t_ = -1e9;
    std::atomic<vrint::BlockQueueHandle_t> event_q_{0}, data_q_{0};  // 0 = not connected
    std::atomic<bool> created_event_{false}, created_data_{false};  // we Created them (Touch-only)
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::atomic<bool> pose_q_ready_{false};
    std::thread setup_thread_, pose_thread_;
    std::mutex write_mu_;  // event/data writes
    std::atomic<uint64_t> imu_sent_{0}, imu_dropped_{0}, poses_{0}, poses_valid_{0}, events_{0};
    std::atomic<double> last_pose_recv_{0};
    double last_reader_check_ = 0;
    bool data_has_reader_ = false;
};

}  // namespace cv
}  // namespace tf
