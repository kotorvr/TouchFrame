#include "radio_decode.h"

#include <algorithm>
#include <cmath>
#include <cstring>

#include "small_json.h"

namespace tf {
namespace radio {

bool ParseImuConfig(const uint8_t* d, size_t n, ImuScale* out) {
    if (n < 16) return false;
    uint16_t acc_hz, gyr_hz;
    float g, dps;
    memcpy(&acc_hz, d + 4, 2);
    memcpy(&gyr_hz, d + 6, 2);
    memcpy(&g, d + 8, 4);
    memcpy(&dps, d + 12, 4);
    if (!(g > 0 && g < 1) || !(dps > 0 && dps < 10)) return false;  // sanity: not a scale
    out->g_per_lsb = g;
    out->dps_per_lsb = dps;
    out->accel_hz = acc_hz;
    out->gyro_hz = gyr_hz;
    out->source = ImuScale::Controller;
    return true;
}

bool ScaleFromImuEvent(const ImuEvt& e, ImuScale* out) {
    if (e.bits < 8 || e.bits > 24 || !e.accel_fs_g || !e.gyro_fs_dps) return false;
    double full = double(1u << (e.bits - 1));
    out->g_per_lsb = float(e.accel_fs_g / full);
    out->dps_per_lsb = float(e.gyro_fs_dps / full);
    out->source = ImuScale::Event;
    return true;
}

static bool ReadCal12(const json::Value* v, double m[9], double off[3]) {
    if (!v || v->type != json::Value::Array || v->arr.size() != 12) return false;
    for (int i = 0; i < 12; i++) {
        if (v->arr[i].type != json::Value::Number) return false;
        (i < 9 ? m[i] : off[i - 9]) = v->arr[i].num;
    }
    return true;
}

bool ParseMetaCalibration(const std::string& text, Rectifier* out, std::string* err) {
    json::Value root;
    size_t start = text.find_first_of("[{");
    if (start == std::string::npos) {
        *err = "no JSON";
        return false;
    }
    json::Parser p(text.data() + start, text.data() + text.size());
    if (!p.Parse(&root)) {
        *err = "JSON parse error";
        return false;
    }
    std::vector<const json::Value*> units;
    if (root.type == json::Value::Array)
        for (auto& u : root.arr) units.push_back(&u);
    else
        units.push_back(&root);
    Rectifier sum;
    for (double& x : sum.acc_m) x = 0;
    for (double& x : sum.gyr_m) x = 0;
    int n = 0;
    for (const json::Value* u : units) {
        const json::Value* to = u->Get("TrackedObject");
        if (!to) to = u;
        double am[9], ao[3], gm[9], go[3];
        if (!ReadCal12(to->Get("AccCalibration"), am, ao) || !ReadCal12(to->Get("GyroCalibration"), gm, go)) continue;
        for (int i = 0; i < 9; i++) sum.acc_m[i] += am[i], sum.gyr_m[i] += gm[i];
        for (int i = 0; i < 3; i++) sum.acc_off[i] += ao[i], sum.gyr_off[i] += go[i];
        n++;
    }
    if (!n) {
        *err = "no AccCalibration/GyroCalibration (12 numbers each) found";
        return false;
    }
    for (int i = 0; i < 9; i++) sum.acc_m[i] /= n, sum.gyr_m[i] /= n;
    for (int i = 0; i < 3; i++) sum.acc_off[i] /= n, sum.gyr_off[i] /= n;
    sum.units = n;
    *out = sum;
    return true;
}

static void Apply(const double m[9], const double off[3], const double v[3], float out[3]) {
    double d[3] = {v[0] - off[0], v[1] - off[1], v[2] - off[2]};
    for (int r = 0; r < 3; r++) out[r] = float(m[3 * r] * d[0] + m[3 * r + 1] * d[1] + m[3 * r + 2] * d[2]);
}

void ImuToSI(const ImuScale& s, const Rectifier& r, const int32_t raw_acc[3], const int32_t raw_gyr[3], float acc[3],
             float gyr[3]) {
    double a[3], g[3];
    for (int i = 0; i < 3; i++) {
        a[i] = raw_acc[i] * double(s.g_per_lsb) * kStandardGravity;
        g[i] = raw_gyr[i] * double(s.dps_per_lsb) * (M_PI / 180.0);
    }
    Apply(r.acc_m, r.acc_off, a, acc);
    Apply(r.gyr_m, r.gyr_off, g, gyr);
}

HandState MapInputs(const InputEvt& in) {
    HandState s{};
    uint16_t b = 0;
    // ntf 4 (PERIPHERALS §4.1): b0 A/X, b1 B/Y, b2 thumbstick click, b3 system/menu.
    if (in.buttons & 0x01) b |= kBtnLowerClick;
    if (in.buttons & 0x02) b |= kBtnUpperClick;
    if (in.buttons & 0x04) b |= kBtnStickClick;
    if (in.buttons & 0x08) b |= kBtnSystemClick;
    // ntf 9 touch bits: 0 A/X, 1 B/Y, 2 stick, 3 thumbrest (INFERRED label), 4 index trigger.
    // Proximity bits 5..9 and the "trigger2" bits 10/11 have no SteamVR component.
    if (in.touch & 0x001) b |= kBtnLowerTouch;
    if (in.touch & 0x002) b |= kBtnUpperTouch;
    if (in.touch & 0x004) b |= kBtnStickTouch;
    if (in.touch & 0x008) b |= kBtnThumbrestTouch;
    if (in.touch & 0x010) b |= kBtnTriggerTouch;
    s.buttons = b;
    // ntf 2: i16 ÷ 32767 if > 0 else ÷ 32768; ntf 3: 12-bit ÷ 4095 (host decode, §4.1).
    auto axis = [](int16_t v) { return v > 0 ? v / 32767.0f : v / 32768.0f; };
    s.stick_x = axis(in.stick[0]);
    s.stick_y = axis(in.stick[1]);
    s.trigger = std::min(1.0f, (in.trigger & 0xfff) / 4095.0f);
    s.grip = std::min(1.0f, (in.grip & 0xfff) / 4095.0f);
    s.battery = in.battery_pct <= 100 ? in.battery_pct : 255;
    return s;
}

Haptic HapticScheduler::Make(double now) const {
    Haptic h{};
    if (!active_) {
        h.mode = HAPTIC_STOP;
        return h;
    }
    h.mode = HAPTIC_SIMPLE;
    h.amplitude = amp_;
    h.freq_hz = hz_;
    double left = std::max(end_ - now, kMinDurationS);
    h.duration_ms = uint16_t(std::min(left * 1000.0, 65535.0) + 0.5);
    return h;
}

Haptic HapticScheduler::Request(double now, float amplitude, float frequency, float duration_s) {
    float a = std::isfinite(amplitude) ? std::min(std::max(amplitude, 0.0f), 1.0f) : 0.0f;
    amp_ = uint8_t(std::lround(a * 255.0f));
    // cmd 0xa0 accepts 40..561 Hz (PERIPHERALS §7).
    hz_ = frequency > 0 && std::isfinite(frequency) ? uint16_t(std::min(std::max(frequency, 40.0f), 561.0f) + 0.5f)
                                                     : kDefaultHz;
    double d = std::isfinite(duration_s) ? std::max(double(duration_s), kMinDurationS) : kMinDurationS;
    active_ = amp_ > 0;
    end_ = now + d;
    last_sent_ = now;
    return Make(now);
}

bool HapticScheduler::Poll(double now, Haptic* out) {
    if (!active_) return false;
    if (now >= end_) {
        active_ = false;  // the dongle stops a < 2 s request by itself
        return false;
    }
    // The controller stops 2 s after the last request; a request whose end is closer than that
    // is stopped on time by the dongle (duration_ms < 2000), so it needs no refresh.
    if (now - last_sent_ < kRefreshS || end_ - last_sent_ <= 2.0) return false;
    last_sent_ = now;
    *out = Make(now);
    return true;
}

}  // namespace radio
}  // namespace tf
