// CvTouchSource: an ITouchSource whose 6DoF comes from Valve's camera tracker (XRService) via
// CvTracker, and whose inputs come from a feed: today nothing, later the Touch Plus radio
// dongle. The feed hands over, per hand:
//   - the LED model config once (XRService controller JSON: lighthouse_config, imu, head, ...);
//   - IMU samples at ~240 Hz, stamped on XRService's clock (cv::NowSeconds(), MONOTONIC_RAW);
//   - button/axis state whenever it changes.
// The source calls back once per XRService pose with that hand's state and the pose's age
// (XRService clock now minus pose time), so the Provider can set poseTimeOffset from real data.
//
// Frames. XRService returns the pose of the LED-model frame. The emitted pose is the config's
// "head" frame (model ∘ model_from_head), which for a Touch config we define as the OpenXR grip
// pose, so TouchController's grip→raw offset applies unchanged. The pose is already in SteamVR's
// tracking space: WorldSpace() is true, and the Provider must not apply the relay calibration.
#pragma once
#include <memory>
#include <mutex>
#include <string>

#include "cv_tracker.h"
#include "source.h"

namespace tf {

class CvTouchSource : public ITouchSource {
public:
    // Haptics go back to the feed (the radio).
    using HapticSink = std::function<void(int hand, float amplitude, float frequency, float duration_s)>;

    struct HandConfig {
        std::string config_text;  // LED-model config (see cv::ParseControllerConfig)
        uint32_t device_id = 0;   // XRService deviceId, 16..63; 0 = 48 + hand
    };

    using HandCallback = std::function<void(int hand, const HandState& s, double age_s)>;

    CvTouchSource(HandCallback cb, HapticSink haptics = nullptr) : cb_(std::move(cb)), haptics_(std::move(haptics)) {}
    ~CvTouchSource() override { Stop(); }

    // Call before Start for each hand the feed has. Returns false if the config doesn't parse.
    bool SetHand(int hand, const HandConfig& cfg, std::string* err);

    bool Start() override;
    void Stop() override;
    void SendHaptic(int hand, float amplitude, float frequency, float duration_s) override {
        if (haptics_) haptics_(hand, amplitude, frequency, duration_s);
    }
    static constexpr bool WorldSpace() { return true; }

    // Feed side. Thread-safe; call from the radio thread.
    // t: cv::NowSeconds() clock. accel m/s^2 (specific force), gyro rad/s, in the config's IMU frame.
    bool PushImu(int hand, double t, const float accel[3], const float gyro[3], uint32_t flags = 0);
    // Inputs as in protocol.h HandState; pose fields and flags are ignored (the tracker owns them).
    void PushInputs(int hand, const HandState& inputs);

private:
    void OnPose(int hand, const cv::CvPose& p);

    struct Hand {
        cv::ControllerConfig cfg;
        uint32_t device_id = 0;
        std::unique_ptr<cv::CvTracker> tracker;
        HandState state{};
        bool configured = false;
        double last_valid_t = 0;
    };
    HandCallback cb_;
    HapticSink haptics_;
    std::mutex mu_;
    Hand hands_[2];
};

}  // namespace tf
