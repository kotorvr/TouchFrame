// CvClone implementation. Everything here is diagnostics around a CvTracker; nothing in the relay
// path depends on it.
//
// IMU synthesis. The real controller's SteamVR raw pose is its "head" frame (lighthouse config
// convention: driver_cv reports model ∘ head). So
//     world_from_imu = world_from_head ∘ inverse(model_from_head) ∘ model_from_imu,
// gyro  = body-frame angular velocity of world_from_imu (finite difference over one tick),
// accel = body-frame specific force (a_imu + g up, g up = +Y in SteamVR), times cv_clone_accel_sign.
//
// Probe (cv_clone_probe, default on). Read-only peeks with read type Latest:
//  - /xrservice/controller/data: the real controllers' IMU samples, to check our synthesized
//    sample's sign, frame and clock against a real one;
//  - /xrservice/controller_<n>/pose of the real controller: XRService's own pose for it, in the
//    same frame as the clone's, so the clone error needs no frame guesses.
// The real controller's deviceId changes per connection; it is found by correlating |angular
// velocity| (frame-independent) with the SteamVR pose, or set with cv_clone_ref_device_id.
//
// Touch-only experiment (docs/re/DEV-1.md, G-Touch-only), both off by default:
//  - cv_clone_imu = "static": no real device needed (cv_clone_serial must still be non-empty, any
//    value); push a resting IMU (gravity on +Y, zero gyro) so XRService gets a stream from a
//    device that never existed in SteamVR.
//  - cv_create_shared_queues = true: CvTracker Creates /xrservice/controller/{event,data} itself
//    when no Frame controller has created them.
#include "cv_clone.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include <openvr_driver.h>

#include "cv_tracker.h"
#include "log.h"

namespace tf {
namespace {

using namespace cv;
using namespace vrint;

const char* kSection = "driver_touchframe";
constexpr double kRate = 240.0;
constexpr double kG = 9.80665;

std::string GetStringSetting(const char* key) {
    char buf[1024] = {};
    vr::EVRSettingsError e = vr::VRSettingsError_None;
    vr::VRSettings()->GetString(kSection, key, buf, sizeof(buf), &e);
    return e == vr::VRSettingsError_None ? buf : "";
}
int32_t GetIntSetting(const char* key, int32_t def) {
    vr::EVRSettingsError e = vr::VRSettingsError_None;
    int32_t v = vr::VRSettings()->GetInt32(kSection, key, &e);
    return e == vr::VRSettingsError_None ? v : def;
}
bool GetBoolSetting(const char* key, bool def) {
    vr::EVRSettingsError e = vr::VRSettingsError_None;
    bool v = vr::VRSettings()->GetBool(kSection, key, &e);
    return e == vr::VRSettingsError_None ? v : def;
}
float GetFloatSetting(const char* key, float def) {
    vr::EVRSettingsError e = vr::VRSettingsError_None;
    float v = vr::VRSettings()->GetFloat(kSection, key, &e);
    return e == vr::VRSettingsError_None ? v : def;
}

std::string Lower(std::string s) {
    for (auto& c : s) c = char(tolower(c));
    return s;
}

// Time-stamped pose history with interpolation.
struct PoseHistory {
    struct S {
        double t;
        Pose pose;
    };
    std::deque<S> s;
    void Add(double t, const Pose& p) {
        if (!s.empty() && t <= s.back().t) return;
        s.push_back({t, p});
        while (s.size() > 512) s.pop_front();
    }
    bool At(double t, Pose* out) const {
        if (s.size() < 2 || t < s.front().t || t > s.back().t + 0.02) return false;
        if (t >= s.back().t) {
            *out = s.back().pose;
            return true;
        }
        auto it = std::lower_bound(s.begin(), s.end(), t, [](const S& a, double v) { return a.t < v; });
        if (it == s.begin()) {
            *out = it->pose;
            return true;
        }
        const S& b = *it;
        const S& a = *(it - 1);
        double u = (t - a.t) / (b.t - a.t);
        Q qa = a.pose.q, qb = b.pose.q;
        if (qa.w * qb.w + qa.x * qb.x + qa.y * qb.y + qa.z * qb.z < 0) qb = {-qb.w, -qb.x, -qb.y, -qb.z};
        out->q = Normalized({qa.w + (qb.w - qa.w) * u, qa.x + (qb.x - qa.x) * u, qa.y + (qb.y - qa.y) * u,
                             qa.z + (qb.z - qa.z) * u});
        out->p = a.pose.p + (b.pose.p - a.pose.p) * u;
        return true;
    }
};

// Running mean/RMS/max of a scalar plus mean of a vector, reset on each report.
struct Acc {
    int n = 0;
    double sum = 0, sum2 = 0, max = 0;
    V3 vsum, vsum2;
    void Add(double v, V3 vec = {}) {
        n++;
        sum += v;
        sum2 += v * v;
        max = std::max(max, v);
        vsum = vsum + vec;
        vsum2 = vsum2 + V3{vec.x * vec.x, vec.y * vec.y, vec.z * vec.z};
    }
    double mean() const { return n ? sum / n : 0; }
    double rms() const { return n ? std::sqrt(sum2 / n) : 0; }
    V3 vmean() const { return n ? vsum * (1.0 / n) : V3{}; }
    V3 vstd() const {
        if (!n) return {};
        V3 m = vmean(), m2 = vsum2 * (1.0 / n);
        return {std::sqrt(std::max(0.0, m2.x - m.x * m.x)), std::sqrt(std::max(0.0, m2.y - m.y * m.y)),
                std::sqrt(std::max(0.0, m2.z - m.z * m.z))};
    }
};

// Pearson correlation over a sliding window.
struct Corr {
    std::deque<std::pair<double, double>> w;
    void Add(double a, double b) {
        w.push_back({a, b});
        if (w.size() > 720) w.pop_front();
    }
    double r(double* std_a) const {
        size_t n = w.size();
        if (n < 240) return 0;
        double ma = 0, mb = 0;
        for (auto& p : w) ma += p.first, mb += p.second;
        ma /= n, mb /= n;
        double sab = 0, saa = 0, sbb = 0;
        for (auto& p : w) {
            sab += (p.first - ma) * (p.second - mb);
            saa += (p.first - ma) * (p.first - ma);
            sbb += (p.second - mb) * (p.second - mb);
        }
        *std_a = std::sqrt(saa / n);
        return saa > 0 && sbb > 0 ? sab / std::sqrt(saa * sbb) : 0;
    }
};

class CvCloneImpl : public CvClone {
public:
    bool Init() {
        serial_match_ = Lower(GetStringSetting("cv_clone_serial"));
        if (serial_match_.empty()) return false;
        std::string path = GetStringSetting("cv_clone_config");
        device_id_ = uint32_t(GetIntSetting("cv_clone_device_id", 40));
        ref_id_ = uint32_t(GetIntSetting("cv_clone_ref_device_id", 0));
        probe_ = GetBoolSetting("cv_clone_probe", true);
        accel_sign_ = GetFloatSetting("cv_clone_accel_sign", 1.0f);
        std::string imu_mode = GetStringSetting("cv_clone_imu");
        mirror_imu_ = imu_mode == "mirror";
        static_imu_ = imu_mode == "static";
        bool create_queues = GetBoolSetting("cv_create_shared_queues", false);
        std::string csv = GetStringSetting("cv_clone_csv");
        std::string role = GetStringSetting("cv_clone_role");
        if (device_id_ < 16 || device_id_ > 63) {
            Log("cvclone: cv_clone_device_id %u out of range 16..63", device_id_);
            return false;
        }
        std::ifstream f(path);
        if (!f) {
            Log("cvclone: can't read cv_clone_config '%s'", path.c_str());
            return false;
        }
        std::stringstream ss;
        ss << f.rdbuf();
        std::string err;
        // A different serial keeps XRService's per-serial calibration (accBias, controllerFromImu)
        // of the real controller untouched; the model number stays so the same DIPr model applies.
        std::string clone_serial;
        {
            ControllerConfig probe;
            if (!ParseControllerConfig(ss.str(), &probe, &err)) {
                Log("cvclone: %s: %s", path.c_str(), err.c_str());
                return false;
            }
            clone_serial = "tfclone_" + probe.serial;
        }
        if (!ParseControllerConfig(ss.str(), &cfg_, &err, clone_serial, "", role)) {
            Log("cvclone: %s: %s", path.c_str(), err.c_str());
            return false;
        }
        imu_from_head_ = Compose(Inverse(cfg_.model_from_imu), cfg_.model_from_head);
        head_from_imu_ = Inverse(imu_from_head_);
        Log("cvclone: config %s: serial %s, model %s, role %s, %d LEDs, %zu bytes; clone device id %u, imu %s, probe %d",
            path.c_str(), cfg_.serial.c_str(), cfg_.model_number.c_str(), cfg_.role.c_str(), cfg_.led_count,
            cfg_.json.size(), device_id_,
            mirror_imu_ ? "mirror" : static_imu_ ? "static" : "synth", int(probe_));
        if (create_queues) Log("cvclone: experiment cv_create_shared_queues ON");
        if (!csv.empty()) {
            csv_ = fopen(csv.c_str(), "w");
            if (csv_) fprintf(csv_, "# kind,fields... see cv_clone.cpp\n");
            Log("cvclone: csv %s -> %s", csv.c_str(), csv_ ? "open" : "FAILED");
        }

        CvTracker::Options o;
        o.device_id = device_id_;
        o.config_json = cfg_.json;
        o.serial = cfg_.serial;
        o.tag = "cvclone";
        o.create_shared_queues = create_queues;
        tracker_ = std::make_unique<CvTracker>(o, [this](const CvPose& p) { OnClonePose(p); });
        if (!tracker_->Start()) return false;
        running_ = true;
        thread_ = std::thread(&CvCloneImpl::Loop, this);
        return true;
    }

    ~CvCloneImpl() override { Stop(); }

    void Stop() override {
        if (!running_.exchange(false)) return;
        if (thread_.joinable()) thread_.join();
        tracker_->Stop();
        std::lock_guard<std::mutex> lk(mu_);
        if (csv_) fclose(csv_);
        csv_ = nullptr;
    }

private:
    // Finds the real controller in SteamVR by serial substring; logs every serial once.
    bool FindReal() {
        auto* props = vr::VRProperties();
        bool log_all = !logged_serials_;
        logged_serials_ = true;
        for (uint32_t i = 0; i < vr::k_unMaxTrackedDeviceCount; i++) {
            auto c = props->TrackedDeviceToPropertyContainer(i);
            vr::ETrackedPropertyError e = vr::TrackedProp_Success;
            char sn[128] = {};
            props->GetStringProperty(c, vr::Prop_SerialNumber_String, sn, sizeof(sn), &e);
            if (e != vr::TrackedProp_Success) continue;
            if (log_all) Log("cvclone: SteamVR device %u serial '%s'", i, sn);
            if (Lower(sn).find(serial_match_) != std::string::npos) {
                real_index_ = i;
                Log("cvclone: real controller is SteamVR device %u ('%s')", i, sn);
                return true;
            }
        }
        return false;
    }

    void Loop() {
        const double dt = 1.0 / kRate;
        timespec next;
        clock_gettime(CLOCK_MONOTONIC, &next);
        double last_find = -1e9, last_report = NowSeconds(), last_probe_scan = -1e9;
        std::vector<vr::TrackedDevicePose_t> poses(vr::k_unMaxTrackedDeviceCount);
        while (running_) {
            next.tv_nsec += long(dt * 1e9);
            while (next.tv_nsec >= 1000000000L) next.tv_nsec -= 1000000000L, next.tv_sec++;
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, nullptr);
            double now = NowSeconds();

            if (static_imu_) {
                // A device at rest: specific force +g on the IMU's +Y, no rotation.
                float accel[3] = {0, float(kG), 0}, gyro[3] = {0, 0, 0};
                bool sent = tracker_->PushImu(now, accel, gyro);
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    last_synth_[0] = {accel[0], accel[1], accel[2]};
                    last_synth_[1] = {0, 0, 0};
                    if (csv_ && sent) fprintf(csv_, "imu,%.6f,0,%.4f,0,0,0,0\n", now, kG);
                }
                if (now - last_report > 2.0) {
                    last_report = now;
                    Report(now, false);
                }
                continue;
            }
            if (real_index_ == vr::k_unTrackedDeviceIndexInvalid) {
                if (now - last_find > 2.0) {
                    last_find = now;
                    if (!FindReal() && now - last_wait_log_ > 30) {
                        last_wait_log_ = now;
                        Log("cvclone: no SteamVR device with serial containing '%s' yet", serial_match_.c_str());
                    }
                }
                continue;
            }
            if (probe_ && now - last_probe_scan > 2.0) {
                last_probe_scan = now;
                ProbeScan();
            }

            vr::VRServerDriverHost()->GetRawTrackedDevicePoses(0.0f, poses.data(), real_index_ + 1);
            const vr::TrackedDevicePose_t& rp = poses[real_index_];
            bool real_ok = rp.bPoseIsValid && rp.bDeviceIsConnected;
            Pose world_head = FromMatrix(rp.mDeviceToAbsoluteTracking);
            V3 w_world{rp.vAngularVelocity.v[0], rp.vAngularVelocity.v[1], rp.vAngularVelocity.v[2]};
            if (real_ok) {
                std::lock_guard<std::mutex> lk(mu_);
                steam_hist_.Add(now, world_head);
                if (csv_)
                    fprintf(csv_, "steam,%.6f,%.6f,%.6f,%.6f,%.7f,%.7f,%.7f,%.7f,%d\n", now, world_head.p.x,
                            world_head.p.y, world_head.p.z, world_head.q.w, world_head.q.x, world_head.q.y,
                            world_head.q.z, int(rp.eTrackingResult));
            }
            if (probe_) ProbeRead(now, Len(w_world), real_ok, world_head, w_world);

            float accel[3], gyro[3];
            bool have = false;
            if (mirror_imu_) {
                have = TakeMirroredImu(accel, gyro);
            } else if (real_ok) {
                have = Synthesize(now, world_head, rp, accel, gyro);
            } else {
                prev_valid_ = false;
            }
            if (have) {
                bool sent = tracker_->PushImu(now, accel, gyro);
                std::lock_guard<std::mutex> lk(mu_);
                last_synth_[0] = {accel[0], accel[1], accel[2]};
                last_synth_[1] = {gyro[0], gyro[1], gyro[2]};
                if (csv_ && sent)
                    fprintf(csv_, "imu,%.6f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n", now, accel[0], accel[1], accel[2],
                            gyro[0], gyro[1], gyro[2]);
            }
            if (now - last_report > 2.0) {
                last_report = now;
                Report(now, real_ok);
            }
        }
    }

    bool Synthesize(double now, const Pose& world_head, const vr::TrackedDevicePose_t& rp, float accel[3],
                    float gyro[3]) {
        Pose world_imu = Compose(world_head, imu_from_head_inv());
        V3 w_world{rp.vAngularVelocity.v[0], rp.vAngularVelocity.v[1], rp.vAngularVelocity.v[2]};
        V3 v_head{rp.vVelocity.v[0], rp.vVelocity.v[1], rp.vVelocity.v[2]};
        // Velocity of the IMU point: v_head + w × r.
        V3 v_imu = v_head + Cross(w_world, world_imu.p - world_head.p);
        bool ok = prev_valid_ && now - prev_t_ > 1e-4 && now - prev_t_ < 0.05;
        V3 gyro_body;
        if (ok) {
            gyro_body = RotVec(Mul(Conj(prev_q_), world_imu.q)) * (1.0 / (now - prev_t_));
        } else {
            gyro_body = Rot(Conj(world_imu.q), w_world);
        }
        // Acceleration from the velocity over ~1/60 s, then a light low-pass (SteamVR velocities
        // step at each pose update; gravity dominates the signal anyway).
        vel_hist_.push_back({now, v_imu});
        while (vel_hist_.size() > 2 && now - vel_hist_[1].first >= 1.0 / 60) vel_hist_.pop_front();
        V3 a_world;
        double span = now - vel_hist_.front().first;
        if (span > 1e-3) a_world = (v_imu - vel_hist_.front().second) * (1.0 / span);
        a_lp_ = ok ? a_lp_ + (a_world - a_lp_) * 0.35 : a_world;
        V3 f_world = a_lp_ + V3{0, kG, 0};
        V3 f_body = Rot(Conj(world_imu.q), f_world) * double(accel_sign_);
        accel[0] = float(f_body.x), accel[1] = float(f_body.y), accel[2] = float(f_body.z);
        gyro[0] = float(gyro_body.x), gyro[1] = float(gyro_body.y), gyro[2] = float(gyro_body.z);
        // Sanity: finite-difference gyro vs the reported angular velocity rotated into the body.
        gyro_check_.Add(Len(gyro_body - Rot(Conj(world_imu.q), w_world)));
        prev_valid_ = true;
        prev_t_ = now;
        prev_q_ = world_imu.q;
        return true;
    }
    // head_from_imu: world_imu = world_head ∘ head_from_imu.
    const Pose& imu_from_head_inv() const { return head_from_imu_; }

    // ---- probe -------------------------------------------------------------------------------
    void ProbeScan() {
        auto* bq = BlockQueue();
        if (!bq) return;
        if (!probe_data_q_) {
            BlockQueueHandle_t h = 0;
            if (bq->Connect(&h, kControllerDataQueue) == BlockQueueError_None) {
                probe_data_q_ = h;
                Log("cvclone: probe reading %s (Latest)", kControllerDataQueue);
            }
        }
        // Real controllers' pose queues, ids 1..15, until one is chosen.
        if (ref_chosen_) return;
        for (uint32_t n = 1; n < 16; n++) {
            if (n == device_id_ || ref_q_.count(n)) continue;
            if (ref_id_ && n != ref_id_) continue;
            BlockQueueHandle_t h = 0;
            if (bq->Connect(&h, PoseQueueName(n).c_str()) == BlockQueueError_None) {
                ref_q_[n] = h;
                Log("cvclone: probe found %s", PoseQueueName(n).c_str());
            }
        }
        if (ref_id_ && ref_q_.count(ref_id_)) {
            ref_chosen_ = ref_id_;
            Log("cvclone: reference XRService device %u (set by cv_clone_ref_device_id)", ref_chosen_.load());
        }
    }

    void ProbeRead(double now, double steam_w, bool real_ok, const Pose& world_head, V3 w_world) {
        auto* bq = BlockQueue();
        // Latest IMU block (any writer).
        if (probe_data_q_) {
            BlockHandle_t blk = 0;
            void* buf = nullptr;
            if (bq->AcquireReadOnlyBlock(probe_data_q_, &blk, &buf, BlockQueueRead_Latest) == BlockQueueError_None && buf) {
                ControllerImuBlock s;
                memcpy(&s, buf, sizeof(s));
                bq->ReleaseReadOnlyBlock(probe_data_q_, blk);
                auto& last = real_imu_[s.deviceId];
                if (s.deviceId != device_id_ && s.sampleTime != last.sampleTime) {
                    last = s;
                    real_imu_seen_[s.deviceId] = now;
                    if (!imu_clock_logged_) {
                        imu_clock_logged_ = true;
                        Log("cvclone: probe first real IMU sample dev %u t=%.6f: now_raw-t = %.2f ms, now_mono-t = %.2f ms",
                            s.deviceId, s.sampleTime, (now - s.sampleTime) * 1e3,
                            (NowSeconds(CLOCK_MONOTONIC) - s.sampleTime) * 1e3);
                    }
                    imu_age_[s.deviceId].Add((now - s.sampleTime) * 1e3);
                    if (mirror_imu_ && s.deviceId == ref_chosen_) {
                        std::lock_guard<std::mutex> lk(mirror_mu_);
                        mirror_pending_ = s;
                        mirror_have_ = true;
                    }
                    std::lock_guard<std::mutex> lk(mu_);
                    if (csv_)
                        fprintf(csv_, "rimu,%u,%.6f,%.6f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%u\n", s.deviceId, now,
                                s.sampleTime, s.accel[0], s.accel[1], s.accel[2], s.gyro[0], s.gyro[1], s.gyro[2],
                                s.flags);
                }
            }
        }
        // Latest pose of each candidate real controller.
        for (auto it = ref_q_.begin(); it != ref_q_.end();) {
            uint32_t n = it->first;
            BlockHandle_t blk = 0;
            void* buf = nullptr;
            EBlockQueueError e = bq->AcquireReadOnlyBlock(it->second, &blk, &buf, BlockQueueRead_Latest);
            if (e == BlockQueueError_InvalidHandle || e == BlockQueueError_QueueNotFound) {
                Log("cvclone: probe lost %s (err %d)", PoseQueueName(n).c_str(), int(e));
                if (ref_chosen_ == n) ref_chosen_ = 0;
                it = ref_q_.erase(it);
                continue;
            }
            if (e == BlockQueueError_None && buf) {
                ControllerPoseBlock b;
                memcpy(&b, buf, sizeof(b));
                bq->ReleaseReadOnlyBlock(it->second, blk);
                if (b.timestamp != -1.0 && b.timestamp != ref_last_t_[n]) {
                    ref_last_t_[n] = b.timestamp;
                    V3 w{b.angularVelocity[0], b.angularVelocity[1], b.angularVelocity[2]};
                    if (real_ok) ref_corr_[n].Add(steam_w, Len(w));
                    std::lock_guard<std::mutex> lk(mu_);
                    if (n == ref_chosen_ && real_ok && Len(w_world) > 0.5) {
                        // Which frame is the pose block's angular velocity in? Compare it with
                        // SteamVR's (world) angular velocity, as a body-frame and as a world vector.
                        Q world_model = Compose(world_head, Inverse(HeadFromPoseBlock(cfg_))).q;
                        V3 body = Rot(Conj(world_model), w_world);
                        V3 as_world = Rot(Q{0, 1, 0, 0}, w);
                        w_frame_body_.Add(Len(w - body) / Len(w_world));
                        w_frame_world_.Add(Len(as_world - w_world) / Len(w_world));
                    }
                    if (n == ref_chosen_) {
                        ref_hist_.Add(b.timestamp, {Normalized(Q{b.qw, b.qx, b.qy, b.qz}),
                                                    {b.position[0], b.position[1], b.position[2]}});
                    }
                    if (csv_)
                        fprintf(csv_, "ref,%u,%.6f,%.6f,%.6f,%.6f,%.6f,%.7f,%.7f,%.7f,%.7f\n", n, now, b.timestamp,
                                b.position[0], b.position[1], b.position[2], b.qw, b.qx, b.qy, b.qz);
                }
            }
            ++it;
        }
        if (!ref_chosen_ && !ref_id_) {
            for (auto& kv : ref_corr_) {
                double sd = 0, r = kv.second.r(&sd);
                if (r > 0.8 && sd > 0.3) {
                    ref_chosen_ = kv.first;
                    Log("cvclone: reference XRService device %u (|w| correlation %.3f, sd %.2f rad/s)", kv.first, r, sd);
                    // Stop peeking at the other controllers' pose queues.
                    for (auto it = ref_q_.begin(); it != ref_q_.end();)
                        it = it->first == ref_chosen_ ? std::next(it) : ref_q_.erase(it);
                    break;
                }
            }
        }
    }

    bool TakeMirroredImu(float accel[3], float gyro[3]) {
        std::lock_guard<std::mutex> lk(mirror_mu_);
        if (!mirror_have_) return false;
        mirror_have_ = false;
        for (int i = 0; i < 3; i++) accel[i] = mirror_pending_.accel[i], gyro[i] = mirror_pending_.gyro[i];
        return true;
    }

    // ---- clone poses ---------------------------------------------------------------------------
    void OnClonePose(const CvPose& p) {
        std::lock_guard<std::mutex> lk(mu_);
        if (csv_)
            fprintf(csv_, "clone,%.6f,%.6f,%d,%.6f,%.6f,%.6f,%.7f,%.7f,%.7f,%.7f\n", p.recv_t, p.t, int(p.valid),
                    p.valid ? p.raw.position[0] : 0, p.valid ? p.raw.position[1] : 0, p.valid ? p.raw.position[2] : 0,
                    p.valid ? p.raw.qw : 0, p.valid ? p.raw.qx : 0, p.valid ? p.raw.qy : 0, p.valid ? p.raw.qz : 0);
        clone_n_++;
        if (!p.valid) return;
        clone_valid_++;
        clone_latency_.Add((p.recv_t - p.t) * 1e3);
        // Against XRService's own pose of the real controller (same frame, no conversions).
        Pose clone_raw{Normalized(Q{p.raw.qw, p.raw.qx, p.raw.qy, p.raw.qz}),
                       {p.raw.position[0], p.raw.position[1], p.raw.position[2]}};
        Pose ref;
        if (ref_hist_.At(p.t, &ref)) {
            V3 d = clone_raw.p - ref.p;
            err_ref_pos_.Add(Len(d) * 1e3, d * 1e3);
            err_ref_ang_.Add(AngleDeg(clone_raw.q, ref.q));
        }
        // Against the real controller's SteamVR pose: the clone's block pose (SteamVR axes) should be
        // world_head ∘ inverse(HeadFromPoseBlock). Log the residual and the raw relative transform.
        Pose steam;
        if (steam_hist_.At(p.t, &steam)) {
            Pose expect = Compose(steam, Inverse(HeadFromPoseBlock(cfg_)));
            V3 d = p.pose.p - expect.p;
            err_steam_pos_.Add(Len(d) * 1e3, d * 1e3);
            err_steam_ang_.Add(AngleDeg(p.pose.q, expect.q));
            Pose rel = Compose(Inverse(steam), p.pose);  // head_from_clone
            rel_pos_.Add(0, rel.p * 1e3);
            rel_rot_.Add(0, RotVec(rel.q) * (180.0 / M_PI));
        }
    }

    void Report(double now, bool real_ok) {
        auto st = tracker_->stats();
        std::lock_guard<std::mutex> lk(mu_);
        Log("cvclone: imu sent %llu dropped %llu | clone poses %d (valid %d) in 2 s, latency %.1f ms | events %llu | real %s",
            (unsigned long long)st.imu_sent, (unsigned long long)st.imu_dropped, clone_n_, clone_valid_,
            clone_latency_.mean(), (unsigned long long)st.connect_events, real_ok ? "tracked" : "NOT tracked");
        if (err_ref_pos_.n)
            Log("cvclone: vs XRService real dev %u: pos err mean %.1f / rms %.1f / max %.1f mm, mean d=(%.1f %.1f %.1f) mm; "
                "ang err mean %.2f max %.2f deg (n=%d)",
                ref_chosen_.load(), err_ref_pos_.mean(), err_ref_pos_.rms(), err_ref_pos_.max, err_ref_pos_.vmean().x,
                err_ref_pos_.vmean().y, err_ref_pos_.vmean().z, err_ref_ang_.mean(), err_ref_ang_.max, err_ref_pos_.n);
        if (err_steam_pos_.n) {
            V3 rp = rel_pos_.vmean(), rps = rel_pos_.vstd(), rr = rel_rot_.vmean(), rrs = rel_rot_.vstd();
            Log("cvclone: vs SteamVR real: pos err mean %.1f / rms %.1f mm, ang err mean %.2f deg; head_from_clone "
                "p=(%.1f %.1f %.1f)±(%.1f %.1f %.1f) mm r=(%.2f %.2f %.2f)±(%.2f %.2f %.2f) deg",
                err_steam_pos_.mean(), err_steam_pos_.rms(), err_steam_ang_.mean(), rp.x, rp.y, rp.z, rps.x, rps.y,
                rps.z, rr.x, rr.y, rr.z, rrs.x, rrs.y, rrs.z);
        }
        if (w_frame_body_.n)
            Log("cvclone: XRService angular velocity vs SteamVR: relative error as body frame %.2f, as world frame %.2f (n=%d)",
                w_frame_body_.mean(), w_frame_world_.mean(), w_frame_body_.n);
        if (gyro_check_.n) Log("cvclone: synth gyro |fd - reported| mean %.3f rad/s", gyro_check_.mean());
        if (probe_) {
            for (auto& kv : real_imu_) {
                if (now - real_imu_seen_[kv.first] > 2.0) continue;
                const auto& s = kv.second;
                Log("cvclone: probe real IMU dev %u: a=(%.2f %.2f %.2f) g=(%.2f %.2f %.2f) flags %u, age mean %.1f ms",
                    kv.first, s.accel[0], s.accel[1], s.accel[2], s.gyro[0], s.gyro[1], s.gyro[2], s.flags,
                    imu_age_[kv.first].mean());
            }
            Log("cvclone: synth IMU now: a=(%.2f %.2f %.2f) g=(%.2f %.2f %.2f)", last_synth_[0].x, last_synth_[0].y,
                last_synth_[0].z, last_synth_[1].x, last_synth_[1].y, last_synth_[1].z);
            if (!ref_chosen_) {
                for (auto& kv : ref_corr_) {
                    double sd = 0, r = kv.second.r(&sd);
                    Log("cvclone: probe candidate dev %u: |w| corr %.2f (sd %.2f), %zu samples", kv.first, r, sd,
                        kv.second.w.size());
                }
            }
        }
        if (csv_) fflush(csv_);
        clone_n_ = clone_valid_ = 0;
        clone_latency_ = err_ref_pos_ = err_ref_ang_ = err_steam_pos_ = err_steam_ang_ = rel_pos_ = rel_rot_ =
            gyro_check_ = w_frame_body_ = w_frame_world_ = Acc{};
        for (auto& kv : imu_age_) kv.second = Acc{};
    }

    // config / settings
    std::string serial_match_;
    uint32_t device_id_ = 40, ref_id_ = 0;
    bool probe_ = true, mirror_imu_ = false, static_imu_ = false;
    float accel_sign_ = 1.0f;
    ControllerConfig cfg_;
    Pose imu_from_head_, head_from_imu_;

    std::unique_ptr<CvTracker> tracker_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    uint32_t real_index_ = vr::k_unTrackedDeviceIndexInvalid;
    bool logged_serials_ = false;
    double last_wait_log_ = -1e9;

    // synthesis state (loop thread)
    bool prev_valid_ = false;
    double prev_t_ = 0;
    Q prev_q_;
    std::deque<std::pair<double, V3>> vel_hist_;
    V3 a_lp_;

    // probe state (loop thread)
    BlockQueueHandle_t probe_data_q_ = 0;
    std::map<uint32_t, BlockQueueHandle_t> ref_q_;
    std::map<uint32_t, double> ref_last_t_;
    std::map<uint32_t, Corr> ref_corr_;
    std::map<uint32_t, ControllerImuBlock> real_imu_;
    std::map<uint32_t, double> real_imu_seen_;
    bool imu_clock_logged_ = false;
    std::atomic<uint32_t> ref_chosen_{0};
    std::mutex mirror_mu_;
    ControllerImuBlock mirror_pending_{};
    bool mirror_have_ = false;

    // shared with the pose callback (mu_)
    std::mutex mu_;
    FILE* csv_ = nullptr;
    PoseHistory steam_hist_, ref_hist_;
    int clone_n_ = 0, clone_valid_ = 0;
    Acc w_frame_body_, w_frame_world_;  // loop thread
    Acc clone_latency_, err_ref_pos_, err_ref_ang_, err_steam_pos_, err_steam_ang_, rel_pos_, rel_rot_, gyro_check_;
    std::map<uint32_t, Acc> imu_age_;
    V3 last_synth_[2];
};

}  // namespace

std::unique_ptr<CvClone> CvClone::CreateFromSettings() {
    auto c = std::make_unique<CvCloneImpl>();
    if (!c->Init()) return nullptr;
    return c;
}

}  // namespace tf
