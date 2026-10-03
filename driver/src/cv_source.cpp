#include "cv_source.h"

#include "log.h"

namespace tf {

using namespace cv;

bool CvTouchSource::SetHand(int hand, const HandConfig& hc, std::string* err) {
    if (hand < 0 || hand > 1) return false;
    std::lock_guard<std::mutex> lk(mu_);
    Hand& h = hands_[hand];
    if (!ParseControllerConfig(hc.config_text, &h.cfg, err)) return false;
    h.device_id = hc.device_id ? hc.device_id : 48 + uint32_t(hand);
    if (h.device_id < 16 || h.device_id > 63) {
        *err = "device_id must be 16..63";
        return false;
    }
    h.configured = true;
    return true;
}

bool CvTouchSource::Start() {
    bool any = false;
    for (int i = 0; i < 2; i++) {
        Hand& h = hands_[i];
        if (!h.configured || h.tracker) continue;
        CvTracker::Options o;
        o.device_id = h.device_id;
        o.config_json = h.cfg.json;
        o.serial = h.cfg.serial;
        o.tag = i == 0 ? "cv-left" : "cv-right";
        h.tracker = std::make_unique<CvTracker>(o, [this, i](const CvPose& p) { OnPose(i, p); });
        if (!h.tracker->Start()) {
            h.tracker.reset();
            continue;
        }
        Log("%s: %s (%s, %d LEDs) as XRService device %u", o.tag, h.cfg.serial.c_str(), h.cfg.model_number.c_str(),
            h.cfg.led_count, h.device_id);
        any = true;
    }
    return any;
}

void CvTouchSource::Stop() {
    for (auto& h : hands_)
        if (h.tracker) h.tracker->Stop();
}

bool CvTouchSource::PushImu(int hand, double t, const float accel[3], const float gyro[3], uint32_t flags) {
    if (hand < 0 || hand > 1 || !hands_[hand].tracker) return false;
    return hands_[hand].tracker->PushImu(t, accel, gyro, flags);
}

void CvTouchSource::PushInputs(int hand, const HandState& in) {
    if (hand < 0 || hand > 1) return;
    std::lock_guard<std::mutex> lk(mu_);
    HandState& s = hands_[hand].state;
    s.battery = in.battery;
    s.buttons = in.buttons;
    s.trigger = in.trigger;
    s.grip = in.grip;
    s.stick_x = in.stick_x;
    s.stick_y = in.stick_y;
}

void CvTouchSource::OnPose(int hand, const CvPose& p) {
    HandState out;
    {
        std::lock_guard<std::mutex> lk(mu_);
        Hand& h = hands_[hand];
        HandState& s = h.state;
        s.flags = kConnected;
        if (p.valid) {
            // pose-block frame -> head (grip) frame.
            Pose grip = Compose(p.pose, HeadFromPoseBlock(h.cfg));
            V3 w = p.ang_vel;  // body frame per driver_cv; rotate into tracking space for SteamVR
            V3 w_world = Rot(p.pose.q, w);
            V3 v = p.vel + Cross(w_world, grip.p - p.pose.p);
            s.pos[0] = float(grip.p.x), s.pos[1] = float(grip.p.y), s.pos[2] = float(grip.p.z);
            s.rot[0] = float(grip.q.x), s.rot[1] = float(grip.q.y), s.rot[2] = float(grip.q.z), s.rot[3] = float(grip.q.w);
            s.lin_vel[0] = float(v.x), s.lin_vel[1] = float(v.y), s.lin_vel[2] = float(v.z);
            s.ang_vel[0] = float(w_world.x), s.ang_vel[1] = float(w_world.y), s.ang_vel[2] = float(w_world.z);
            s.flags |= kOrientationValid | kPositionValid | kOrientationTracked | kPositionTracked;
            h.last_valid_t = p.t;
        } else if (h.last_valid_t > 0 && p.recv_t - h.last_valid_t < 0.5) {
            // Brief dropout: hold the last pose as valid-but-untracked (SteamVR shows it greyed).
            s.flags |= kOrientationValid | kPositionValid;
        }
        out = s;
    }
    if (cb_) cb_(hand, out, p.valid ? p.recv_t - p.t : 0.0);
}

}  // namespace tf
