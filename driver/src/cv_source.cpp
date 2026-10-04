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
    for (int i = 0; i < 2; i++) any |= StartHand(i);
    return any;
}

bool CvTouchSource::StartHand(int i) {
    if (i < 0 || i > 1) return false;
    Hand& h = hands_[i];
    if (!h.configured) return false;
    if (h.tracker) return true;
    CvTracker::Options o;
    o.device_id = h.device_id;
    o.config_json = h.cfg.json;
    o.serial = h.cfg.serial;
    o.tag = i == 0 ? "cv-left" : "cv-right";
    o.create_shared_queues = opt_.create_shared_queues;
    o.create_after_s = opt_.create_after_s;
    o.destroy_created_queues = false;  // re-Creating later would cost a Frame controller again
    auto t = std::make_unique<CvTracker>(o, [this, i](const CvPose& p) { OnPose(i, p); });
    if (!t->Start()) return false;
    Log("%s: %s (%s, %d LEDs) as XRService device %u", o.tag, h.cfg.serial.c_str(), h.cfg.model_number.c_str(),
        h.cfg.led_count, h.device_id);
    std::lock_guard<std::mutex> lk(mu_);
    h.tracker = std::move(t);
    return true;
}

void CvTouchSource::Stop() {
    for (int i = 0; i < 2; i++)
        if (CvTracker* tr = Tracker(i)) tr->Stop();
}

void CvTouchSource::Reannounce(int hand) {
    CvTracker* tr = Tracker(hand);
    if (!tr) return;
    uint32_t id = tr->device_id() + 2;
    if (id > 63) id = 16 + uint32_t(hand);  // XRService skips ids it knows; 24 per hand per session
    Log("%s: re-announcing as device %u", hand == 0 ? "cv-left" : "cv-right", id);
    tr->Reannounce(id);
}

CvTracker* CvTouchSource::Tracker(int hand) const {
    // Trackers are created by StartHand and live as long as the source.
    std::lock_guard<std::mutex> lk(mu_);
    return hand < 0 || hand > 1 ? nullptr : hands_[hand].tracker.get();
}

bool CvTouchSource::PushImu(int hand, double t, const float accel[3], const float gyro[3], uint32_t flags) {
    CvTracker* tr = Tracker(hand);
    return tr && tr->PushImu(t, accel, gyro, flags);
}

void CvTouchSource::PushInputs(int hand, const HandState& in) {
    if (hand < 0 || hand > 1) return;
    HandState out;
    {
        std::lock_guard<std::mutex> lk(mu_);
        Hand& h = hands_[hand];
        HandState& s = h.state;
        s.battery = in.battery;
        s.buttons = in.buttons;
        s.trigger = in.trigger;
        s.grip = in.grip;
        s.stick_x = in.stick_x;
        s.stick_y = in.stick_y;
        // Poses carry the inputs out; without them (not tracked yet), send them ourselves.
        double now = NowSeconds();
        if (now - h.last_pose_recv < 0.05 || now - h.last_emit < 0.011) return;
        h.last_emit = now;
        if (now - h.last_pose_recv > 0.25) s.flags = h.connected ? kConnected : 0;
        out = s;
    }
    Emit(hand, out, 0.0);
}

void CvTouchSource::SetConnected(int hand, bool connected) {
    if (hand < 0 || hand > 1) return;
    HandState out;
    {
        std::lock_guard<std::mutex> lk(mu_);
        Hand& h = hands_[hand];
        h.connected = connected;
        if (!connected) h.state.flags = 0;
        else h.state.flags |= kConnected;
        out = h.state;
    }
    Emit(hand, out, 0.0);
}

std::string CvTouchSource::serial(int hand) const {
    std::lock_guard<std::mutex> lk(mu_);
    return hand < 0 || hand > 1 ? std::string() : hands_[hand].cfg.serial;
}

uint32_t CvTouchSource::device_id(int hand) const {
    std::lock_guard<std::mutex> lk(mu_);
    if (hand < 0 || hand > 1) return 0;
    return hands_[hand].tracker ? hands_[hand].tracker->device_id() : hands_[hand].device_id;
}

bool CvTouchSource::started(int hand) const {
    std::lock_guard<std::mutex> lk(mu_);
    return hand >= 0 && hand <= 1 && hands_[hand].tracker != nullptr;
}

CvTracker::Stats CvTouchSource::stats(int hand) const {
    std::lock_guard<std::mutex> lk(mu_);
    return hand >= 0 && hand <= 1 && hands_[hand].tracker ? hands_[hand].tracker->stats() : CvTracker::Stats();
}

void CvTouchSource::Emit(int hand, const HandState& s, double age) {
    if (cb_) cb_(hand, s, age);
}

void CvTouchSource::OnPose(int hand, const CvPose& p) {
    if (observer_) observer_(hand, p.recv_t, p.valid);
    HandState out;
    {
        std::lock_guard<std::mutex> lk(mu_);
        Hand& h = hands_[hand];
        HandState& s = h.state;
        h.last_pose_recv = h.last_emit = p.recv_t;
        s.flags = h.connected ? kConnected : 0;
        if (!h.connected) {
            // XRService may still hold a pose for a while after the radio link dropped.
        } else if (p.valid) {
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
    Emit(hand, out, p.valid ? p.recv_t - p.t : 0.0);
}

}  // namespace tf
