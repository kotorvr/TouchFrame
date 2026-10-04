// RadioBackend: the Touch Plus radio dongle as the Provider's ITouchSource, in one of two modes.
//
//   camera  RadioSource IMU → CvTouchSource (XRService's camera tracker does 6DoF from the LEDs);
//           inputs ride along; XRService's poses feed the LED phase loop, and so do the
//           "[ContrLedsStats]" / frame-timestamp lines in XRService's log (XrLogWatcher). A hand is
//           announced to XRService when its controller first connects. Poses are in SteamVR's
//           tracking space (no relay calibration).
//   3dof    no camera: orientation from the IMU (Mahony filter, gravity → +Y), yaw aligned with
//           the headset's when the controller connects (and on Recenter), position at a fixed
//           offset from the headset (an arm model without the elbow). SteamVR shows it as
//           rotation-only.
//
// Both hand the Provider HandState per hand via the callback, with the pose's age.
#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "cv_math.h"
#include "cv_source.h"
#include "protocol.h"
#include "radio_source.h"
#include "touch_source.h"
#include "xr_log.h"

namespace tf {

// Mahony complementary filter: q = world_from_body, world +Y up, accel = specific force (reads
// +g up at rest), gyro rad/s in the body frame.
class ImuOrientation {
public:
    struct Options {
        double kp = 1.0, ki = 0.02;      // steady-state gains
        double kp_init = 10.0;           // the first init_s: converge on gravity fast
        double init_s = 0.5;
        double accel_tolerance = 0.15;   // use the accelerometer only within ±15 % of 1 g
    };
    ImuOrientation() : ImuOrientation(Options()) {}
    explicit ImuOrientation(Options o) : opt_(o) {}

    void Reset() { *this = ImuOrientation(opt_); }
    void Update(double t, const float accel[3], const float gyro[3]);
    // Rotate about world Y so the body's -Z (forward) points along `forward` (world, projected
    // on the horizontal plane).
    void AlignYaw(cv::V3 forward);
    bool settled(double t) const { return started_ && t - t0_ >= opt_.init_s; }
    cv::Q q() const { return q_; }

private:
    Options opt_;
    cv::Q q_;
    cv::V3 bias_;
    bool started_ = false;
    double t0_ = 0, last_t_ = 0;
};

class RadioBackend : public ITouchSource {
public:
    enum class Mode { kCamera, k3Dof };
    struct Options {
        Mode mode = Mode::kCamera;
        radio::RadioSource::Options radio;
        std::string config_text[2];  // XRService controller config per hand (camera mode; "" = no hand)
        uint32_t device_id[2] = {0, 0};
        CvTouchSource::Options cv;
        std::string xr_logs_dir;     // "" = $HOME/.local/share/Steam/logs, "-" = don't read XRService's log
        // 3dof: grip position in the headset's yaw frame (m; x right, y up, -z forward).
        float arm[2][3] = {{-0.18f, -0.40f, -0.30f}, {0.18f, -0.40f, -0.30f}};
        ImuOrientation::Options filter;
        double status_every_s = 60;
        std::function<void(const std::string&)> log;
    };
    using HandCallback = std::function<void(int hand, const HandState& s, double age_s)>;
    // The headset pose in SteamVR's tracking space now (3dof). False if unknown.
    using HeadPoseFn = std::function<bool(cv::Pose* world_from_head)>;

    RadioBackend(Options opt, HandCallback cb, HeadPoseFn head = nullptr);
    ~RadioBackend() override;

    bool Start() override;
    void Stop() override;
    void SendHaptic(int hand, float amplitude, float frequency, float duration_s) override;

    void RequestPair(int hand) { radio_->RequestPair(hand); }
    // Camera: announce the hand again under a fresh deviceId. 3dof: no-op.
    void Reannounce(int hand);
    // 3dof: re-align the hand's yaw with the headset on its next sample.
    void Recenter(int hand) { recenter_[hand & 1] = true; }
    bool connected(int hand) const { return connected_[hand & 1]; }
    std::string Status() const;

private:
    void OnImu(int hand, double t, const float a[3], const float g[3]);
    void OnInputs(int hand, const HandState& in);
    void OnConnection(int hand, bool c);
    void Service();
    void Log(const std::string& s) const;

    Options opt_;
    HandCallback cb_;
    HeadPoseFn head_;
    std::unique_ptr<radio::RadioSource> radio_;
    std::unique_ptr<CvTouchSource> cv_;
    std::unique_ptr<XrLogWatcher> xrlog_;
    std::atomic<bool> connected_[2] = {{false}, {false}};
    std::atomic<bool> recenter_[2] = {{false}, {false}};
    // 3dof state (radio thread)
    std::mutex mu3_;
    ImuOrientation ori_[2];
    bool aligned_[2] = {false, false};
    HandState state3_[2] = {};
    double last_emit3_[2] = {0, 0};
    std::thread service_;
    std::atomic<bool> running_{false};
};

}  // namespace tf
