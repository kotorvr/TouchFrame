// CvTouchSource: an ITouchSource whose 6DoF comes from Valve's camera tracker (XRService) via
// CvTracker, and whose inputs come from a feed (the Touch Plus radio, RadioBackend). The feed
// hands over, per hand:
//   - the LED model config once (XRService controller JSON: lighthouse_config, imu, head, ...);
//   - IMU samples (500 Hz from the radio), stamped on XRService's clock (cv::NowSeconds(), MONOTONIC_RAW);
//   - button/axis state whenever it changes, and whether the controller is connected.
// The source calls back once per XRService pose with that hand's state and the pose's age
// (XRService clock now minus pose time), so the Provider can set poseTimeOffset from real data.
// When no poses come (XRService not tracking us yet, headset off) inputs still go out, at most
// every 11 ms, with the pose flags cleared once the last pose is 0.25 s old.
//
// Frames. XRService returns a pose with the LED model's axes at the IMU's origin. The emitted pose
// is the config's "head" frame (cv::HeadFromPoseBlock), which for a Touch config we define as the OpenXR grip
// pose, so TouchController's grip→raw offset applies unchanged. The pose is already in SteamVR's
// tracking space: WorldSpace() is true, and the Provider must not apply the relay calibration.
//
// The config is sent as given: model_number must stay "TouchFrame_TouchPlus_<Hand>_Roy_EV1.5"
// (tools/touchplus_config.py; docs/re/FRAME-MODEL.md §1.7), and the serial stable per hand
// (XRService keeps per-serial IMU calibration).
#pragma once
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "cv_tracker.h"
#include "protocol.h"
#include "touch_source.h"

namespace tf {

class CvTouchSource : public ITouchSource {
public:
    // Haptics go back to the feed (the radio).
    using HapticSink = std::function<void(int hand, float amplitude, float frequency, float duration_s)>;

    struct HandConfig {
        std::string config_text;  // LED-model config (see cv::ParseControllerConfig)
        uint32_t device_id = 0;   // XRService deviceId, 16..63; 0 = 48 + hand
    };
    struct Options {
        // Touch-only (docs/re/DEV-1.md): with no Steam Frame controller since SteamVR started,
        // Create the shared queues after this long. The queues are then kept until SteamVR exits.
        bool create_shared_queues = true;
        double create_after_s = 20;
    };

    using HandCallback = std::function<void(int hand, const HandState& s, double age_s)>;
    // Every pose block XRService sends for the hand (t = when read, valid = it has a pose): the
    // LED phase loop's feedback. Set before Start.
    using PoseObserver = std::function<void(int hand, double t, bool valid)>;

    CvTouchSource(HandCallback cb, HapticSink haptics = nullptr) : CvTouchSource(Options(), cb, haptics) {}
    CvTouchSource(Options opt, HandCallback cb, HapticSink haptics = nullptr)
        : opt_(opt), cb_(std::move(cb)), haptics_(std::move(haptics)) {}
    ~CvTouchSource() override { Stop(); }

    // Call before Start for each hand the feed has. Returns false if the config doesn't parse.
    bool SetHand(int hand, const HandConfig& cfg, std::string* err);

    // Starts every configured hand's tracker.
    bool Start() override;
    // Starts one hand's tracker (announces it to XRService); a no-op if it runs already.
    bool StartHand(int hand);
    void Stop() override;
    void SendHaptic(int hand, float amplitude, float frequency, float duration_s) override {
        if (haptics_) haptics_(hand, amplitude, frequency, duration_s);
    }
    static constexpr bool WorldSpace() { return true; }

    // Announce the hand again under a fresh deviceId (a competing controller let go of the hand's
    // tracker slot; FRAME-TRACKER §9.3). Ids step by 2 within 16..63, keeping the hand's parity.
    void Reannounce(int hand);

    // Feed side. Thread-safe; call from the radio thread.
    // t: cv::NowSeconds() clock. accel m/s^2 (specific force), gyro rad/s, in the config's IMU frame.
    bool PushImu(int hand, double t, const float accel[3], const float gyro[3], uint32_t flags = 0);
    // Inputs as in protocol.h HandState; pose fields and flags are ignored (the tracker owns them).
    void PushInputs(int hand, const HandState& inputs);
    // Radio link state: a disconnected hand is reported with no flags (SteamVR: not connected).
    void SetConnected(int hand, bool connected);
    void SetPoseObserver(PoseObserver f) { observer_ = std::move(f); }

    std::string serial(int hand) const;
    uint32_t device_id(int hand) const;
    bool started(int hand) const;
    cv::CvTracker::Stats stats(int hand) const;

private:
    void OnPose(int hand, const cv::CvPose& p);
    void Emit(int hand, const HandState& s, double age);
    cv::CvTracker* Tracker(int hand) const;

    struct Hand {
        cv::ControllerConfig cfg;
        uint32_t device_id = 0;
        std::unique_ptr<cv::CvTracker> tracker;
        HandState state{};
        bool configured = false, connected = true;
        double last_valid_t = 0, last_pose_recv = 0, last_emit = 0;
    };
    Options opt_;
    HandCallback cb_;
    HapticSink haptics_;
    PoseObserver observer_;
    mutable std::mutex mu_;
    Hand hands_[2];
};

}  // namespace tf
