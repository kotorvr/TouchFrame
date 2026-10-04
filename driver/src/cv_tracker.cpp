#include "cv_tracker.h"

#include <chrono>
#include <cstring>

#include "log.h"
#include "small_json.h"

namespace tf {
namespace cv {

using namespace vrint;

double NowSeconds(clockid_t clock) {
    timespec ts;
    clock_gettime(clock, &ts);
    return double(ts.tv_sec) + double(ts.tv_nsec) * 1e-9;
}

static void SleepS(double s) { std::this_thread::sleep_for(std::chrono::microseconds(int64_t(s * 1e6))); }

// ---------------------------------------------------------------------------------------------
// Config

static bool ReadV3(const json::Value* a, V3* out) {
    if (!a || a->type != json::Value::Array || a->arr.size() != 3) return false;
    for (auto& e : a->arr)
        if (e.type != json::Value::Number) return false;
    *out = {a->arr[0].num, a->arr[1].num, a->arr[2].num};
    return true;
}

static bool ReadFrame(const json::Value* f, Pose* out) {
    V3 x, z, p;
    if (!f || !ReadV3(f->Get("plus_x"), &x) || !ReadV3(f->Get("plus_z"), &z) || !ReadV3(f->Get("position"), &p))
        return false;
    out->q = FromAxes(x, z);
    out->p = p;
    return true;
}

bool ParseControllerConfig(const std::string& text, ControllerConfig* out, std::string* err,
                           const std::string& serial_override, const std::string& model_override,
                           const std::string& role_override) {
    json::Value root;
    bool found = json::FindObject(text, &root, [](const json::Value& v) {
        if (v.Get("lighthouse_config")) return true;
        const json::Value* d = v.Get("default");
        return d && d->Get("lighthouse_config");
    });
    if (!found) {
        *err = "no JSON object with lighthouse_config found";
        return false;
    }
    json::Value cfg = root.Get("lighthouse_config") ? root : *root.Get("default");
    if (!serial_override.empty()) cfg.Set("device_serial_number", json::Value::Str(serial_override));
    if (!model_override.empty()) cfg.Set("model_number", json::Value::Str(model_override));
    if (!role_override.empty()) cfg.Set("tracked_controller_role", json::Value::Str(role_override));

    const json::Value* lh = cfg.Get("lighthouse_config");
    const json::Value* pts = lh->Get("modelPoints");
    const json::Value* nrm = lh->Get("modelNormals");
    if (!pts || pts->type != json::Value::Array || !nrm || nrm->arr.size() != pts->arr.size()) {
        *err = "lighthouse_config needs modelPoints and modelNormals of equal length";
        return false;
    }
    if (!ReadFrame(cfg.Get("imu"), &out->model_from_imu)) {
        *err = "missing imu {plus_x, plus_z, position}";
        return false;
    }
    if (!ReadFrame(cfg.Get("head"), &out->model_from_head)) {
        *err = "missing head {plus_x, plus_z, position}";
        return false;
    }
    out->led_count = int(pts->arr.size());
    const json::Value* s = cfg.Get("device_serial_number");
    out->serial = s && s->type == json::Value::String ? s->str : "";
    const json::Value* m = cfg.Get("model_number");
    out->model_number = m && m->type == json::Value::String ? m->str : "";
    const json::Value* r = cfg.Get("tracked_controller_role");
    out->role = r && r->type == json::Value::String ? r->str : "";
    out->json.clear();
    json::Emit(cfg, &out->json);
    if (out->json.size() >= kControllerConfigMax) {
        *err = "config JSON is " + std::to_string(out->json.size()) + " bytes, max 0x2fff";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------------------------
// Interfaces and pose conversion

IVRBlockQueue* BlockQueue() {
    static IVRBlockQueue* bq = [] {
        vr::EVRInitError e = vr::VRInitError_None;
        auto* p = static_cast<IVRBlockQueue*>(vr::VRDriverContext()->GetGenericInterface(IVRBlockQueue_Version, &e));
        Log("cv: GetGenericInterface(%s) = %p (err %d)", IVRBlockQueue_Version, (void*)p, int(e));
        return e == vr::VRInitError_None ? p : nullptr;
    }();
    return bq;
}

IVRPaths* Paths() {
    static IVRPaths* paths = [] {
        vr::EVRInitError e = vr::VRInitError_None;
        auto* p = static_cast<IVRPaths*>(vr::VRDriverContext()->GetGenericInterface(IVRPaths_Version, &e));
        Log("cv: GetGenericInterface(%s) = %p (err %d)", IVRPaths_Version, (void*)p, int(e));
        return e == vr::VRInitError_None ? p : nullptr;
    }();
    return paths;
}

Pose HeadFromPoseBlock(const ControllerConfig& cfg) {
    return {cfg.model_from_head.q, cfg.model_from_head.p - cfg.model_from_imu.p};
}

std::string PoseQueueName(uint32_t device_id) {
    return std::string(kControllerPoseQueuePrefix) + std::to_string(int(device_id)) + kControllerPoseQueueSuffix;
}

CvPose ConvertPoseBlock(const ControllerPoseBlock& b) {
    // driver_cv's constant at 0x4a4db0: quaternion (x=1, y=0, z=0, w=0).
    static const Q kFlip{0, 1, 0, 0};
    CvPose out;
    out.device_id = b.deviceId;
    out.raw = b;
    out.t = b.timestamp;
    out.valid = b.timestamp != -1.0;
    if (!out.valid) return out;
    Pose xr{Normalized(Q{b.qw, b.qx, b.qy, b.qz}), {b.position[0], b.position[1], b.position[2]}};
    out.pose = {Mul(kFlip, xr.q), Rot(kFlip, xr.p)};
    out.vel = Rot(kFlip, V3{b.velocity[0], b.velocity[1], b.velocity[2]});
    out.ang_vel = {b.angularVelocity[0], b.angularVelocity[1], b.angularVelocity[2]};
    return out;
}

// ---------------------------------------------------------------------------------------------
// CvTracker

CvTracker::CvTracker(Options opt, PoseCallback cb) : opt_(std::move(opt)), cb_(std::move(cb)) {
    derived_hwid_ = !opt_.hardware_id;
    if (derived_hwid_) opt_.hardware_id = 0x5446000000000000ull | opt_.device_id;  // "TF"
    device_id_ = opt_.device_id;
}

CvTracker::~CvTracker() { Stop(); }

bool CvTracker::Start() {
    if (running_) return true;
    bq_ = BlockQueue();
    paths_ = Paths();
    if (!bq_ || !paths_) {
        Log("%s: block-queue interfaces unavailable; camera tracking disabled", opt_.tag);
        return false;
    }
    if (opt_.config_json.empty() || opt_.config_json.size() >= kControllerConfigMax) {
        Log("%s: bad config (%zu bytes)", opt_.tag, opt_.config_json.size());
        return false;
    }
    running_ = true;
    setup_thread_ = std::thread(&CvTracker::SetupLoop, this);
    return true;
}

void CvTracker::Stop() {
    if (!running_.exchange(false)) return;
    if (setup_thread_.joinable()) setup_thread_.join();
    if (connected_.exchange(false)) {
        SendEvent(ControllerEvent_Disconnect);
        Log("%s: sent disconnect for device %u", opt_.tag, device_id_.load());
    }
    if (pose_thread_.joinable()) pose_thread_.join();
    // Queues we created are ours to destroy (driver_cv destroys its own at shutdown), unless the
    // Touch-only setup keeps them for the rest of the SteamVR session.
    if (opt_.destroy_created_queues) {
        if (created_event_ && event_q_)
            Log("%s: destroyed %s (err %d)", opt_.tag, kControllerEventQueue, int(bq_->Destroy(event_q_)));
        if (created_data_ && data_q_)
            Log("%s: destroyed %s (err %d)", opt_.tag, kControllerDataQueue, int(bq_->Destroy(data_q_)));
    }
    created_event_ = created_data_ = false;
    event_q_ = data_q_ = 0;
    std::lock_guard<std::mutex> lk(pose_mu_);
    if (pose_q_) {
        auto e = bq_->Destroy(pose_q_);
        Log("%s: destroyed %s (err %d)", opt_.tag, PoseQueueName(device_id_).c_str(), int(e));
        pose_q_ = 0;
    }
    pose_q_ready_ = false;
}

CvTracker::Stats CvTracker::stats() const {
    Stats s;
    s.imu_sent = imu_sent_;
    s.imu_dropped = imu_dropped_;
    s.poses = poses_;
    s.poses_valid = poses_valid_;
    s.connect_events = events_;
    return s;
}

void CvTracker::SetupLoop() {
    const char* tag = opt_.tag;
    // 1. Our pose queue first, read before anything is announced.
    {
        std::lock_guard<std::mutex> lk(pose_mu_);
        if (!CreatePoseQueue(device_id_, &pose_q_)) {
            Log("%s: no pose queue; giving up", tag);
            return;
        }
    }
    pose_q_ready_ = true;
    pose_thread_ = std::thread(&CvTracker::PoseLoop, this);

    double last_wait_log = -1e9;
    const double setup_start = NowSeconds();
    bool caveat_logged = false;
    bool event_had_reader = false;
    double connect_time = 0;
    bool resent_for_silence = false;
    while (running_) {
        double now = NowSeconds();
        // 2. Connect (never Create) the shared queues. driver_cv's first controller creates them.
        if (!event_q_ || !data_q_) {
            connected_ = false;
            EBlockQueueError ee = BlockQueueError_None, de = BlockQueueError_None;
            BlockQueueHandle_t h = 0;
            if (!event_q_ && (ee = bq_->Connect(&h, kControllerEventQueue)) == BlockQueueError_None) event_q_ = h;
            if (!data_q_ && (de = bq_->Connect(&h, kControllerDataQueue)) == BlockQueueError_None) data_q_ = h;
            if (opt_.create_shared_queues && now - setup_start >= opt_.create_after_s &&
                (ee == BlockQueueError_QueueNotFound || de == BlockQueueError_QueueNotFound)) {
                if (!caveat_logged) {
                    caveat_logged = true;
                    Log("%s: Touch-only: no Steam Frame controller created the shared queues in %.0f s; creating "
                        "them ourselves. CAVEAT: the first Steam Frame controller turned on later in this SteamVR "
                        "session gets no pose (buttons and haptics still work) until SteamVR restarts "
                        "(docs/re/DEV-1.md). Turn one on before SteamVR starts to avoid this.",
                        tag, now - setup_start);
                }
                // driver_cv's own Create parameters (FRAME-TRACKER §8.2).
                if (!event_q_ && ee == BlockQueueError_QueueNotFound) {
                    ee = bq_->Create(&h, kControllerEventQueue, sizeof(ControllerEventBlock),
                                     kControllerQueueHeaderSize, kControllerQueueBlockCount, 0);
                    Log("%s: Create %s -> err %d", tag, kControllerEventQueue, int(ee));
                    if (ee == BlockQueueError_None) event_q_ = h, created_event_ = true;
                }
                if (!data_q_ && de == BlockQueueError_QueueNotFound) {
                    de = bq_->Create(&h, kControllerDataQueue, sizeof(ControllerImuBlock),
                                     kControllerQueueHeaderSize, kControllerQueueBlockCount, 0);
                    Log("%s: Create %s -> err %d", tag, kControllerDataQueue, int(de));
                    if (de == BlockQueueError_None) data_q_ = h, created_data_ = true;
                }
            }
            if (!event_q_ || !data_q_) {
                if (now - last_wait_log > 30) {
                    Log("%s: waiting for a Steam Frame controller to create the shared queues "
                        "(connect event err %d, data err %d); retrying every 1 s%s", tag, int(ee), int(de),
                        opt_.create_shared_queues ? ", creating them ourselves after the grace period" : "");
                    last_wait_log = now;
                }
                SleepS(1.0);
                continue;
            }
            Log("%s: connected %s and %s", tag, kControllerEventQueue, kControllerDataQueue);
        }
        // 3. XRService must be reading the event queue before we announce ourselves.
        bool has_reader = false;
        EBlockQueueError re = bq_->QueueHasReader(event_q_, &has_reader);
        if (re == BlockQueueError_InvalidHandle || re == BlockQueueError_QueueNotFound) {
            Log("%s: event queue went away (err %d); reconnecting", tag, int(re));
            event_q_ = data_q_ = 0;
            created_event_ = created_data_ = false;
            continue;
        }
        if (!has_reader) {
            if (event_had_reader) Log("%s: XRService stopped reading the event queue", tag);
            event_had_reader = false;
            connected_ = false;
            if (now - last_wait_log > 30) {
                Log("%s: waiting for XRService to read %s", tag, kControllerEventQueue);
                last_wait_log = now;
            }
            SleepS(0.5);
            continue;
        }
        // Re-announce under a fresh deviceId (a competing controller let go of our hand's slot).
        if (uint32_t to = reannounce_to_.exchange(0)) {
            if (to != device_id_ && DoReannounce(to)) {
                event_had_reader = true;  // announce below as the new device
                connected_ = false;
            }
        }
        // 4. Announce (again after an XRService restart, i.e. a new reader).
        if (!event_had_reader || !connected_) {
            event_had_reader = true;
            if (SendEvent(ControllerEvent_Connect)) {
                connected_ = true;
                connect_time = now;
                resent_for_silence = false;
                Log("%s: sent connect for device %u (hardware id 0x%016llx, %zu-byte config)", tag,
                    device_id_.load(), (unsigned long long)opt_.hardware_id, opt_.config_json.size());
            } else {
                SleepS(1.0);
                continue;
            }
        }
        // XRService answers a config with a pose-queue connection and pose blocks. If nothing at
        // all comes back, say so and re-announce once.
        if (!resent_for_silence && connected_ && now - connect_time > 10 && last_pose_recv_.load() < connect_time) {
            resent_for_silence = true;
            Log("%s: no pose blocks 10 s after connect; re-sending connect once", tag);
            SendEvent(ControllerEvent_Connect);
        }
        SleepS(0.5);
    }
}

bool CvTracker::CreatePoseQueue(uint32_t id, BlockQueueHandle_t* out) {
    std::string name = PoseQueueName(id);
    EBlockQueueError e = bq_->Create(out, name.c_str(), sizeof(ControllerPoseBlock), kControllerQueueHeaderSize,
                                     kControllerQueueBlockCount, BlockQueueFlag_OwnerIsReader);
    if (e == BlockQueueError_QueueAlreadyExists) {
        e = bq_->Connect(out, name.c_str());
        Log("%s: %s already existed; connected instead (err %d)", opt_.tag, name.c_str(), int(e));
    }
    if (e != BlockQueueError_None) {
        Log("%s: Create %s failed: %d", opt_.tag, name.c_str(), int(e));
        *out = 0;
        return false;
    }
    Log("%s: created %s (handle 0x%llx)", opt_.tag, name.c_str(), (unsigned long long)*out);
    return true;
}

// Setup thread. Disconnect the old identity, then (SendEvent spaces it ≥ 1.1 s) the setup loop
// connects the new one.
bool CvTracker::DoReannounce(uint32_t new_id) {
    const uint32_t old_id = device_id_;
    BlockQueueHandle_t q = 0;
    if (!CreatePoseQueue(new_id, &q)) return false;  // keep the old identity
    if (connected_.exchange(false)) {
        SendEvent(ControllerEvent_Disconnect);
        Log("%s: re-announce: sent disconnect for device %u", opt_.tag, old_id);
    }
    BlockQueueHandle_t old_q;
    {
        std::lock_guard<std::mutex> lk(pose_mu_);
        old_q = pose_q_;
        pose_q_ = q;
        device_id_ = new_id;
        if (derived_hwid_) opt_.hardware_id = 0x5446000000000000ull | new_id;
    }
    if (old_q) Log("%s: destroyed %s (err %d)", opt_.tag, PoseQueueName(old_id).c_str(), int(bq_->Destroy(old_q)));
    Log("%s: re-announcing as device %u (was %u)", opt_.tag, new_id, old_id);
    return true;
}

void CvTracker::PoseLoop() {
    bool logged_first = false, logged_first_valid = false;
    while (running_ || connected_) {
        BlockHandle_t blk = 0;
        void* buf = nullptr;
        ControllerPoseBlock b;
        EBlockQueueError e;
        {
            std::lock_guard<std::mutex> lk(pose_mu_);  // DoReannounce swaps the queue
            e = pose_q_ ? bq_->WaitAndAcquireReadOnlyBlock(pose_q_, &blk, &buf, BlockQueueRead_New, 50)
                        : BlockQueueError_InvalidHandle;
            if (e == BlockQueueError_None && buf) {
                memcpy(&b, buf, sizeof(b));
                bq_->ReleaseReadOnlyBlock(pose_q_, blk);
            }
        }
        if (e != BlockQueueError_None || !buf) {
            SleepS(e == BlockQueueError_BlockNotAvailable ? 0.001 : 0.05);
            if (!running_) break;
            continue;
        }
        CvPose p = ConvertPoseBlock(b);
        p.recv_t = NowSeconds();
        last_pose_recv_ = p.recv_t;
        poses_++;
        if (p.valid) poses_valid_++;
        if (!logged_first) {
            logged_first = true;
            Log("%s: first pose block: device %u, t %.4f (now %.4f), valid %d", opt_.tag, b.deviceId, b.timestamp,
                p.recv_t, int(p.valid));
        }
        if (p.valid && !logged_first_valid) {
            logged_first_valid = true;
            Log("%s: first VALID pose: p=(%.3f %.3f %.3f) latency %.1f ms", opt_.tag, b.position[0], b.position[1],
                b.position[2], (p.recv_t - p.t) * 1e3);
        }
        if (cb_) cb_(p);
    }
}

bool CvTracker::SendEvent(uint32_t type) {
    // XRService takes about one event a second from a 4-block ring (AUDIT-1 F2): space ours.
    double wait = last_event_t_ + 1.1 - NowSeconds();
    if (wait > 0) SleepS(wait);
    last_event_t_ = NowSeconds();
    std::lock_guard<std::mutex> lk(write_mu_);
    if (!event_q_) return false;
    BlockHandle_t blk = 0;
    void* buf = nullptr;
    EBlockQueueError e = BlockQueueError_BlockNotAvailable;
    for (int i = 0; i < 20 && e != BlockQueueError_None; i++) {
        e = bq_->AcquireWriteOnlyBlock(event_q_, &blk, &buf);
        if (e != BlockQueueError_None) SleepS(0.01);
    }
    if (e != BlockQueueError_None || !buf) {
        Log("%s: AcquireWriteOnlyBlock(event) failed: %d", opt_.tag, int(e));
        return false;
    }
    auto* ev = static_cast<ControllerEventBlock*>(buf);
    memset(ev, 0, sizeof(*ev));
    ev->deviceId = device_id_;
    ev->eventType = type;
    ev->hardwareId = opt_.hardware_id;
    uint64_t len = 0;
    if (type == ControllerEvent_Connect) {
        len = opt_.config_json.size();
        memcpy(ev->onboardConfig, opt_.config_json.data(), len);
        memcpy(ev->defaultConfig, opt_.config_json.data(), len);
    }
    // The lengths travel as uint64 properties on the block (driver_cv FUN_001dfe78 layout:
    // writeType Set, 8 bytes, tag 3, bPostEvents 1).
    static PathHandle_t h_onboard = 0, h_default = 0, h_serial = 0;
    if (!h_onboard) paths_->StringToHandle(&h_onboard, kOnboardConfigSizePath);
    if (!h_default) paths_->StringToHandle(&h_default, kDefaultConfigSizePath);
    if (!h_serial) paths_->StringToHandle(&h_serial, kConfigSerialPath);
    uint64_t len_onboard = len, len_default = len;
    PathWrite_t w[3];
    memset(w, 0, sizeof(w));
    w[0].ulPath = h_onboard;
    w[0].pvBuffer = &len_onboard;
    w[1].ulPath = h_default;
    w[1].pvBuffer = &len_default;
    for (int i = 0; i < 2; i++) {
        w[i].writeType = PropertyWrite_Set;
        w[i].unBufferSize = sizeof(uint64_t);
        w[i].unTag = vr::k_unUint64PropertyTag;
        w[i].bPostEvents = true;
    }
    uint32_t n = 2;
    if (!opt_.serial.empty()) {
        w[2].ulPath = h_serial;
        w[2].writeType = PropertyWrite_Set;
        w[2].pvBuffer = const_cast<char*>(opt_.serial.c_str());
        w[2].unBufferSize = uint32_t(opt_.serial.size() + 1);
        w[2].unTag = vr::k_unStringPropertyTag;
        w[2].bPostEvents = true;
        n = 3;
    }
    auto pe = paths_->WritePathBatch(blk, w, n);
    if (pe != vr::TrackedProp_Success || w[0].eError != vr::TrackedProp_Success || w[1].eError != vr::TrackedProp_Success)
        Log("%s: WritePathBatch on event block: %d (%d %d)", opt_.tag, int(pe), int(w[0].eError), int(w[1].eError));
    e = bq_->ReleaseWriteOnlyBlock(event_q_, blk);
    if (e != BlockQueueError_None) {
        Log("%s: ReleaseWriteOnlyBlock(event) failed: %d", opt_.tag, int(e));
        return false;
    }
    events_++;
    return true;
}

bool CvTracker::PushImu(double t, const float accel[3], const float gyro[3], uint32_t flags) {
    if (!connected_ || !data_q_) {
        imu_dropped_++;
        return false;
    }
    std::lock_guard<std::mutex> lk(write_mu_);
    // driver_cv writes IMU only while XRService reads the data queue; check twice a second.
    if (t - last_reader_check_ > 0.5 || t < last_reader_check_) {
        last_reader_check_ = t;
        bool r = false;
        data_has_reader_ = bq_->QueueHasReader(data_q_, &r) == BlockQueueError_None && r;
    }
    if (!data_has_reader_) {
        imu_dropped_++;
        return false;
    }
    BlockHandle_t blk = 0;
    void* buf = nullptr;
    EBlockQueueError e = bq_->AcquireWriteOnlyBlock(data_q_, &blk, &buf);
    if (e != BlockQueueError_None || !buf) {
        imu_dropped_++;
        if (e == BlockQueueError_InvalidHandle || e == BlockQueueError_QueueNotFound) {
            Log("%s: data queue went away (err %d)", opt_.tag, int(e));
            data_q_ = 0;  // the setup loop reconnects and re-announces
            connected_ = false;
        }
        return false;
    }
    auto* s = static_cast<ControllerImuBlock*>(buf);
    memset(s, 0, sizeof(*s));
    s->deviceId = device_id_;
    s->sampleTime = t;
    for (int i = 0; i < 3; i++) {
        s->accel[i] = accel[i];
        s->gyro[i] = gyro[i];
    }
    s->flags = flags;
    bq_->ReleaseWriteOnlyBlock(data_q_, blk);
    imu_sent_++;
    return true;
}

}  // namespace cv
}  // namespace tf
