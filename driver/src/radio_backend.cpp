#include "radio_backend.h"

#include <chrono>
#include <cmath>
#include <cstdio>

#include "log.h"

namespace tf {

using namespace cv;

// ---------------------------------------------------------------------------------------------
// ImuOrientation

void ImuOrientation::Update(double t, const float accel[3], const float gyro[3]) {
    V3 w{gyro[0], gyro[1], gyro[2]};
    V3 a{accel[0], accel[1], accel[2]};
    if (!started_) {
        started_ = true;
        t0_ = last_t_ = t;
        // Start level with gravity: the shortest rotation taking the measured up to world +Y.
        double n = Len(a);
        if (n > 1e-3) {
            V3 up = a * (1.0 / n), y{0, 1, 0};
            V3 axis = Cross(up, y);
            double s = Len(axis), c = Dot(up, y);
            q_ = s < 1e-9 ? (c > 0 ? Q{} : Q{0, 1, 0, 0}) : FromRotVec(axis * (std::atan2(s, c) / s));
        }
        return;
    }
    double dt = t - last_t_;
    last_t_ = t;
    if (dt <= 0 || dt > 0.1) return;  // a gap: hold rather than integrate garbage
    double n = Len(a);
    const double g = 9.80665;
    if (n > g * (1 - opt_.accel_tolerance) && n < g * (1 + opt_.accel_tolerance)) {
        V3 meas = a * (1.0 / n);
        V3 est = Rot(Conj(q_), V3{0, 1, 0});  // where world up should be in the body frame
        V3 e = Cross(meas, est);              // rotate the estimate towards the measurement
        bool init = t - t0_ < opt_.init_s;
        double kp = init ? opt_.kp_init : opt_.kp;
        if (!init) bias_ = bias_ + e * (opt_.ki * dt);
        w = w + e * kp + bias_;
    }
    q_ = Normalized(Mul(q_, FromRotVec(w * dt)));
}

void ImuOrientation::AlignYaw(V3 forward) {
    V3 fc = Rot(q_, V3{0, 0, -1});
    fc.y = 0;
    forward.y = 0;
    if (Len(fc) < 1e-3 || Len(forward) < 1e-3) return;  // pointing straight up/down: no heading
    fc = fc * (1.0 / Len(fc));
    forward = forward * (1.0 / Len(forward));
    double ang = std::atan2(Cross(fc, forward).y, Dot(fc, forward));
    q_ = Normalized(Mul(FromRotVec(V3{0, ang, 0}), q_));
}

// ---------------------------------------------------------------------------------------------
// RadioBackend

RadioBackend::RadioBackend(Options opt, HandCallback cb, HeadPoseFn head)
    : opt_(std::move(opt)), cb_(std::move(cb)), head_(std::move(head)) {
    for (auto& o : ori_) o = ImuOrientation(opt_.filter);
    radio::RadioSource::Options ro = opt_.radio;
    if (!ro.log) ro.log = [this](const std::string& s) { Log(s); };
    ro.led_loop = ro.led_loop && opt_.mode == Mode::kCamera;  // no camera, no LEDs to phase
    radio::RadioSource::Callbacks rc;
    rc.imu = [this](int h, double t, const float a[3], const float g[3]) { OnImu(h, t, a, g); };
    rc.inputs = [this](int h, const HandState& s, double) { OnInputs(h, s); };
    rc.connection = [this](int h, bool c) { OnConnection(h, c); };
    radio_ = std::make_unique<radio::RadioSource>(ro, rc);
    if (opt_.mode == Mode::kCamera) {
        cv_ = std::make_unique<CvTouchSource>(
            opt_.cv,
            [this](int h, const HandState& s, double age) {
                if (cb_) cb_(h, s, age);
            },
            [this](int h, float a, float f, float d) { radio_->SendHaptic(h, a, f, d); });
        cv_->SetPoseObserver([this](int h, double t, bool valid) { radio_->ObservePose(h, t, valid); });
        for (int h = 0; h < 2; h++) {
            if (opt_.config_text[h].empty()) continue;
            CvTouchSource::HandConfig hc;
            hc.config_text = opt_.config_text[h];
            hc.device_id = opt_.device_id[h];
            std::string err;
            if (!cv_->SetHand(h, hc, &err)) Log(std::string("radio: ") + (h ? "right" : "left") + " config: " + err);
        }
        if (opt_.xr_logs_dir != "-") {
            XrLogWatcher::Callbacks wc;
            wc.serial_of_hand = [this](int h) { return cv_->serial(h); };
            wc.led_hit = [this](int h, double now) { radio_->LedStatsHit(h, now); };
            wc.frame_stamp = [this](double now, double ft) { radio_->FrameTimestamp(now, ft); };
            wc.log = [this](const std::string& s) { Log(s); };
            xrlog_ = std::make_unique<XrLogWatcher>(opt_.xr_logs_dir, wc);
        }
    }
}

RadioBackend::~RadioBackend() { Stop(); }

void RadioBackend::Log(const std::string& s) const {
    if (opt_.log) opt_.log(s);
    else tf::Log("%s", s.c_str());
}

bool RadioBackend::Start() {
    if (running_.exchange(true)) return true;
    Log(std::string("radio: mode ") + (opt_.mode == Mode::kCamera ? "camera (XRService tracks the LEDs)" : "3dof (IMU orientation, arm-model position)") +
        ", transport " + opt_.radio.transport);
    radio_->Start();  // hands are announced to XRService as their controllers connect
    service_ = std::thread(&RadioBackend::Service, this);
    return true;
}

void RadioBackend::Stop() {
    if (!running_.exchange(false)) return;
    if (service_.joinable()) service_.join();
    radio_->Stop();
    if (cv_) cv_->Stop();
}

void RadioBackend::SendHaptic(int hand, float amplitude, float frequency, float duration_s) {
    radio_->SendHaptic(hand, amplitude, frequency, duration_s);
}

void RadioBackend::Reannounce(int hand) {
    if (cv_) cv_->Reannounce(hand);
}

void RadioBackend::OnConnection(int hand, bool c) {
    connected_[hand] = c;
    if (cv_) {
        if (c && !cv_->started(hand)) cv_->StartHand(hand);
        cv_->SetConnected(hand, c);
        return;
    }
    HandState s;
    {
        std::lock_guard<std::mutex> lk(mu3_);
        ori_[hand].Reset();
        aligned_[hand] = false;
        state3_[hand].flags = c ? kConnected : 0;
        s = state3_[hand];
    }
    if (cb_) cb_(hand, s, 0.0);
}

void RadioBackend::OnInputs(int hand, const HandState& in) {
    if (cv_) {
        cv_->PushInputs(hand, in);
        return;
    }
    std::lock_guard<std::mutex> lk(mu3_);
    HandState& s = state3_[hand];
    s.battery = in.battery;
    s.buttons = in.buttons;
    s.trigger = in.trigger;
    s.grip = in.grip;
    s.stick_x = in.stick_x;
    s.stick_y = in.stick_y;
}

void RadioBackend::OnImu(int hand, double t, const float a[3], const float g[3]) {
    if (cv_) {
        cv_->PushImu(hand, t, a, g);
        return;
    }
    HandState out;
    double age;
    {
        std::lock_guard<std::mutex> lk(mu3_);
        ImuOrientation& o = ori_[hand];
        o.Update(t, a, g);
        Pose head;
        bool have_head = head_ && head_(&head);
        V3 head_fwd = have_head ? Rot(head.q, V3{0, 0, -1}) : V3{0, 0, -1};
        if (o.settled(t) && (!aligned_[hand] || recenter_[hand].exchange(false))) {
            o.AlignYaw(head_fwd);
            aligned_[hand] = true;
        }
        if (!aligned_[hand] || t - last_emit3_[hand] < 0.0035) return;  // ~250 Hz is plenty
        last_emit3_[hand] = t;
        HandState& s = state3_[hand];
        Q q = o.q();
        // Position: the arm offset in the headset's yaw-only frame.
        V3 hf = head_fwd;
        hf.y = 0;
        double yaw = Len(hf) > 1e-3 ? std::atan2(-hf.x, -hf.z) : 0;
        V3 base = have_head ? head.p : V3{0, 1.6, 0};
        V3 p = base + Rot(FromRotVec(V3{0, yaw, 0}), V3{opt_.arm[hand][0], opt_.arm[hand][1], opt_.arm[hand][2]});
        V3 w = Rot(q, V3{g[0], g[1], g[2]});
        s.pos[0] = float(p.x), s.pos[1] = float(p.y), s.pos[2] = float(p.z);
        s.rot[0] = float(q.x), s.rot[1] = float(q.y), s.rot[2] = float(q.z), s.rot[3] = float(q.w);
        s.lin_vel[0] = s.lin_vel[1] = s.lin_vel[2] = 0;
        s.ang_vel[0] = float(w.x), s.ang_vel[1] = float(w.y), s.ang_vel[2] = float(w.z);
        s.flags = kConnected | kOrientationValid | kPositionValid | kOrientationTracked;
        out = s;
        age = std::max(0.0, radio::HostNowNs() * 1e-9 - t);  // the radio's stamps are on its host clock
    }
    if (cb_) cb_(hand, out, age);
}

std::string RadioBackend::Status() const {
    radio::RadioSource::LinkStatus ls = radio_->link_status();
    char buf[512];
    int n = snprintf(buf, sizeof(buf), "radio: %s%s, drift %+.1f ppm, sync band %.0f us over %.0f s",
                     ls.transport.empty() ? "no dongle" : ls.transport.c_str(), ls.hosting ? " hosting" : "",
                     ls.drift_ppm, ls.sync_band_us, ls.sync_span_s);
    std::string s(buf, size_t(std::max(0, n)));
    for (int h = 0; h < 2; h++) {
        radio::RadioSource::HandStatus hs = radio_->hand_status(h);
        n = snprintf(buf, sizeof(buf), " | %s: %s", h ? "right" : "left", hs.connected ? "connected" : "off");
        s.append(buf, size_t(std::max(0, n)));
        if (!hs.connected) continue;
        n = snprintf(buf, sizeof(buf), ", imu %llu (gaps %llu), led %s", (unsigned long long)hs.imu,
                     (unsigned long long)hs.gaps,
                     hs.led_state < 0 ? "off" : radio::LedPhaseLoop::StateName(radio::LedPhaseLoop::State(hs.led_state)));
        s.append(buf, size_t(std::max(0, n)));
        if (cv_ && cv_->started(h)) {
            cv::CvTracker::Stats st = cv_->stats(h);
            n = snprintf(buf, sizeof(buf), ", xr device %u: imu sent %llu dropped %llu, poses %llu valid %llu",
                         cv_->device_id(h), (unsigned long long)st.imu_sent, (unsigned long long)st.imu_dropped,
                         (unsigned long long)st.poses, (unsigned long long)st.poses_valid);
            s.append(buf, size_t(std::max(0, n)));
        }
    }
    if (xrlog_) {
        n = snprintf(buf, sizeof(buf), " | xrlog: %llu LED hits, %llu frame stamps", (unsigned long long)xrlog_->led_hits(),
                     (unsigned long long)xrlog_->frame_stamps());
        s.append(buf, size_t(std::max(0, n)));
    }
    return s;
}

void RadioBackend::Service() {
    double next_status = NowSeconds() + 10;
    while (running_) {
        double now = NowSeconds();
        if (xrlog_ && (connected_[0] || connected_[1])) xrlog_->Poll(now);
        if (opt_.status_every_s > 0 && now >= next_status) {
            next_status = now + opt_.status_every_s;
            Log(Status());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

}  // namespace tf
