// Touch Plus raw radio data -> driver units: IMU counts -> SI with per-unit rectification, input
// notification registers -> protocol.h HandState, SteamVR haptics -> link v3 commands.
// Sources: docs/re/PERIPHERALS.md §3 (IMU), §4.1 (inputs), §5 (battery), §7 (haptics).
// Portable; unit-tested by driver/test/radio_unit_test.cpp.
#pragma once
#include <cstdint>
#include <string>

#include "protocol.h"
#include "radio_link.h"

namespace tf {
namespace radio {

constexpr double kStandardGravity = 9.80665;

// Controller command 0x32 imu_config (16 B, PERIPHERALS §3.2). The f32 factors are what the
// controller itself says; the ICM-42686 values (±32 g / ±4000 dps) are the fallback.
struct ImuScale {
    float g_per_lsb = 1.0f / 1024.0f;
    float dps_per_lsb = 1.0f / 8.192f;
    uint16_t accel_hz = 500, gyro_hz = 500;
    enum Source { Default, Event, Controller } source = Default;
};
bool ParseImuConfig(const uint8_t* data, size_t n, ImuScale* out);
// link_imu_t's own scale fields (accel_g = raw / 2^(bits-1) * fs). Used only when cmd 0x32 can't
// be read; false if the fields are empty.
bool ScaleFromImuEvent(const ImuEvt& e, ImuScale* out);

// Per-unit rectification into the LED-model frame: model = M (si - offset), separately for
// accel (m/s^2) and gyro (rad/s). M and offset come from Meta's AccCalibration / GyroCalibration
// (12 numbers: M row-major, then offset), the format tools/touchplus_config.py writes as
// touchplus_<hand>_meta_cal.json (an array of unit calibrations, averaged here) and the format
// INFERRED for the controller's cmd 0x2b blob. Units of the offset (SI) and the subtract-then-
// multiply order are INFERRED (PERIPHERALS §3.3, touchplus_config.py docstring): check with a
// resting controller (accel ≈ +g on the model's up axis, gyro ≈ 0).
struct Rectifier {
    double acc_m[9] = {1, 0, 0, 0, 1, 0, 0, 0, 1}, acc_off[3] = {0, 0, 0};
    double gyr_m[9] = {1, 0, 0, 0, 1, 0, 0, 0, 1}, gyr_off[3] = {0, 0, 0};
    int units = 0;  // calibrations averaged in (0 = identity)
};
bool ParseMetaCalibration(const std::string& text, Rectifier* out, std::string* err);

// Raw counts -> accel m/s^2 (specific force) and gyro rad/s in the model frame.
void ImuToSI(const ImuScale& s, const Rectifier& r, const int32_t raw_acc[3], const int32_t raw_gyr[3],
             float acc[3], float gyr[3]);

// Input notification registers -> HandState (buttons, touches, axes, battery). Pose fields and
// flags are left zero. Touch Plus has no grip touch sensor; kBtnGripTouch stays clear.
HandState MapInputs(const InputEvt& in);

// SteamVR haptic pulses -> CMD_HAPTIC. The controller auto-stops 2 s after the last request, so
// a long buzz is re-sent every `refresh_s`; amplitude 0 stops. One per hand; not thread-safe.
class HapticScheduler {
public:
    static constexpr double kRefreshS = 1.5;
    static constexpr double kMinDurationS = 0.02;  // SteamVR sends 0 for "one tick"
    static constexpr uint16_t kDefaultHz = 160;    // when SteamVR passes no frequency

    // A new request replaces the current one. Returns the command to send now.
    Haptic Request(double now, float amplitude, float frequency, float duration_s);
    // A refresh to send now, if one is due (false otherwise).
    bool Poll(double now, Haptic* out);
    bool active() const { return active_; }

private:
    Haptic Make(double now) const;
    bool active_ = false;
    double end_ = 0, last_sent_ = 0;
    uint8_t amp_ = 0;
    uint16_t hz_ = kDefaultHz;
};

}  // namespace radio
}  // namespace tf
