// TouchFrame SteamVR driver: presents Quest 3 Touch Plus controllers to SteamVR on the
// Steam Frame as first-class "oculus_touch" controllers (Touch bindings, Quest 3 render
// models, haptics). State comes from an ITouchSource, chosen by driver_touchframe.mode:
//   relay         the Quest bridge over UDP (UdpSource), poses calibrated into SteamVR's space;
//   radio_camera  the Touch Plus radio dongle (RadioBackend) with XRService tracking the LEDs;
//   radio_3dof    the dongle with IMU orientation only (no camera tracking).
#include <sys/stat.h>

#include <atomic>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>

#include <openvr_driver.h>

#include "cv_clone.h"
#include "log.h"
#include "protocol.h"
#include "radio_backend.h"
#include "skeleton.h"
#include "source.h"

using namespace vr;

namespace tf {

static const char* kSection = "driver_touchframe";

static_assert(sizeof(Bone) == sizeof(VRBoneTransform_t), "Bone layout");

struct Quat { double w, x, y, z; };
struct Vec3 { double x, y, z; };

static Quat QuatFromEulerXYZDeg(double rx, double ry, double rz) {
    // SteamVR render model rotate_xyz: rotations about X, then Y, then Z (intrinsic).
    auto axis = [](double deg, int a) {
        double h = deg * M_PI / 360.0;
        Quat q{std::cos(h), 0, 0, 0};
        (a == 0 ? q.x : a == 1 ? q.y : q.z) = std::sin(h);
        return q;
    };
    auto mul = [](Quat a, Quat b) {
        return Quat{a.w * b.w - a.x * b.x - a.y * b.y - a.z * b.z,
                    a.w * b.x + a.x * b.w + a.y * b.z - a.z * b.y,
                    a.w * b.y - a.x * b.z + a.y * b.w + a.z * b.x,
                    a.w * b.z + a.x * b.y - a.y * b.x + a.z * b.w};
    };
    return mul(mul(axis(rx, 0), axis(ry, 1)), axis(rz, 2));
}

static Vec3 Rotate(Quat q, Vec3 v) {
    // v' = q v q*
    Vec3 u{q.x, q.y, q.z};
    Vec3 t{2 * (u.y * v.z - u.z * v.y), 2 * (u.z * v.x - u.x * v.z), 2 * (u.x * v.y - u.y * v.x)};
    return Vec3{v.x + q.w * t.x + (u.y * t.z - u.z * t.y),
                v.y + q.w * t.y + (u.z * t.x - u.x * t.z),
                v.z + q.w * t.z + (u.x * t.y - u.y * t.x)};
}

class TouchController : public ITrackedDeviceServerDriver {
public:
    TouchController(int hand, const CurlAnimation* anim) : hand_(hand), anim_(anim), poser_(hand) {
        // The source reports the OpenXR grip pose. SteamVR wants the raw controller pose that
        // the oculus_quest_plus render model components are relative to, so the device pose is
        // grip * inverse(openxr_grip component_local) (values from the Frame's render model json).
        Quat r = QuatFromEulerXYZDeg(20.6, 0.0, 0.0);
        Vec3 t{hand == 0 ? 0.007 : -0.007, -0.00182941, 0.1019482};
        Quat r_inv{r.w, -r.x, -r.y, -r.z};
        Vec3 t_inv = Rotate(r_inv, Vec3{-t.x, -t.y, -t.z});
        head_from_grip_rot_ = r_inv;
        head_from_grip_pos_ = t_inv;
    }

    const char* Serial() const { return hand_ == 0 ? "TouchFrame_Left" : "TouchFrame_Right"; }

    EVRInitError Activate(uint32_t id) override {
        auto* p = VRProperties();
        PropertyContainerHandle_t c = p->TrackedDeviceToPropertyContainer(id);
        bool left = hand_ == 0;
        p->SetStringProperty(c, Prop_TrackingSystemName_String, "touchframe");
        p->SetStringProperty(c, Prop_ManufacturerName_String, "Meta");
        p->SetStringProperty(c, Prop_ModelNumber_String,
                             left ? "Meta Quest 3 (Left Controller)" : "Meta Quest 3 (Right Controller)");
        p->SetStringProperty(c, Prop_SerialNumber_String, Serial());
        p->SetStringProperty(c, Prop_RenderModelName_String,
                             left ? "oculus_quest_plus_controller_left" : "oculus_quest_plus_controller_right");
        p->SetStringProperty(c, Prop_ControllerType_String, "oculus_touch");
        p->SetStringProperty(c, Prop_InputProfilePath_String, "{touchframe}/input/touchframe_profile.json");
        p->SetStringProperty(c, Prop_RegisteredDeviceType_String,
                             left ? "touchframe/TouchFrame_Left" : "touchframe/TouchFrame_Right");
        p->SetInt32Property(c, Prop_ControllerRoleHint_Int32,
                            left ? TrackedControllerRole_LeftHand : TrackedControllerRole_RightHand);
        p->SetInt32Property(c, Prop_DeviceClass_Int32, TrackedDeviceClass_Controller);
        // Win the hand roles over idle Frame controllers while Touch Plus is in use.
        p->SetInt32Property(c, Prop_ControllerHandSelectionPriority_Int32,
                            VRSettings()->GetInt32(kSection, "hand_priority"));
        // Battery is advertised once a source reports it (the OpenXR relay can't).
        p->SetBoolProperty(c, Prop_DeviceProvidesBatteryStatus_Bool, false);
        p->SetBoolProperty(c, Prop_WillDriftInYaw_Bool, false);

        auto* in = VRDriverInput();
        const char* lower = left ? "/input/x" : "/input/a";
        const char* upper = left ? "/input/y" : "/input/b";
        in->CreateBooleanComponent(c, (std::string(lower) + "/click").c_str(), &h_lower_click_);
        in->CreateBooleanComponent(c, (std::string(lower) + "/touch").c_str(), &h_lower_touch_);
        in->CreateBooleanComponent(c, (std::string(upper) + "/click").c_str(), &h_upper_click_);
        in->CreateBooleanComponent(c, (std::string(upper) + "/touch").c_str(), &h_upper_touch_);
        in->CreateBooleanComponent(c, "/input/system/click", &h_system_click_);
        in->CreateBooleanComponent(c, "/input/system/touch", &h_system_touch_);
        in->CreateBooleanComponent(c, "/input/joystick/click", &h_stick_click_);
        in->CreateBooleanComponent(c, "/input/joystick/touch", &h_stick_touch_);
        in->CreateScalarComponent(c, "/input/joystick/x", &h_stick_x_, VRScalarType_Absolute, VRScalarUnits_NormalizedTwoSided);
        in->CreateScalarComponent(c, "/input/joystick/y", &h_stick_y_, VRScalarType_Absolute, VRScalarUnits_NormalizedTwoSided);
        in->CreateScalarComponent(c, "/input/trigger/value", &h_trigger_, VRScalarType_Absolute, VRScalarUnits_NormalizedOneSided);
        in->CreateBooleanComponent(c, "/input/trigger/touch", &h_trigger_touch_);
        in->CreateBooleanComponent(c, "/input/trigger/click", &h_trigger_click_);
        in->CreateScalarComponent(c, "/input/grip/value", &h_grip_, VRScalarType_Absolute, VRScalarUnits_NormalizedOneSided);
        in->CreateBooleanComponent(c, "/input/grip/touch", &h_grip_touch_);
        in->CreateBooleanComponent(c, "/input/grip/click", &h_grip_click_);
        in->CreateBooleanComponent(c, "/input/thumbrest/touch", &h_thumbrest_touch_);
        in->CreateHapticComponent(c, "/output/haptic", &h_haptic_);
        if (anim_) {
            EVRInputError e = in->CreateSkeletonComponent(
                c, left ? "/input/skeleton/left" : "/input/skeleton/right",
                left ? "/skeleton/hand/left" : "/skeleton/hand/right", "/pose/raw",
                VRSkeletalTracking_Estimated, nullptr, 0, &h_skeleton_);
            if (e != VRInputError_None) Log("CreateSkeletonComponent %s failed: %d", Serial(), int(e));
        }
        container_ = c;
        id_ = id;  // last: the UDP thread starts updating once the handles exist
        Log("controller %s activated as device %u", Serial(), id);
        return VRInitError_None;
    }

    void Deactivate() override { id_ = k_unTrackedDeviceIndexInvalid; }
    void EnterStandby() override {}
    void* GetComponent(const char*) override { return nullptr; }
    void DebugRequest(const char*, char* resp, uint32_t size) override { if (size) resp[0] = 0; }
    DriverPose_t GetPose() override {
        std::lock_guard<std::mutex> lk(mu_);
        return pose_;
    }

    uint32_t Id() const { return id_; }
    VRInputComponentHandle_t HapticHandle() const { return h_haptic_; }

    void SetCalibration(Quat q, Vec3 t) {
        std::lock_guard<std::mutex> lk(mu_);
        world_rot_ = q;
        world_pos_ = t;
    }

    void Update(const HandState& s, double age_s) {
        if (id_ == k_unTrackedDeviceIndexInvalid) return;
        DriverPose_t p{};
        {
            std::lock_guard<std::mutex> lk(mu_);
            p.qWorldFromDriverRotation = {world_rot_.w, world_rot_.x, world_rot_.y, world_rot_.z};
            p.vecWorldFromDriverTranslation[0] = world_pos_.x;
            p.vecWorldFromDriverTranslation[1] = world_pos_.y;
            p.vecWorldFromDriverTranslation[2] = world_pos_.z;
        }
        p.qDriverFromHeadRotation = {head_from_grip_rot_.w, head_from_grip_rot_.x, head_from_grip_rot_.y, head_from_grip_rot_.z};
        p.vecDriverFromHeadTranslation[0] = head_from_grip_pos_.x;
        p.vecDriverFromHeadTranslation[1] = head_from_grip_pos_.y;
        p.vecDriverFromHeadTranslation[2] = head_from_grip_pos_.z;
        for (int i = 0; i < 3; i++) {
            p.vecPosition[i] = s.pos[i];
            p.vecVelocity[i] = s.lin_vel[i];
            p.vecAngularVelocity[i] = s.ang_vel[i];
        }
        p.qRotation = {s.rot[3], s.rot[0], s.rot[1], s.rot[2]};
        p.poseTimeOffset = -age_s;
        p.deviceIsConnected = (s.flags & kConnected) != 0;
        p.poseIsValid = (s.flags & kOrientationValid) != 0;
        bool tracked = (s.flags & kPositionTracked) && (s.flags & kOrientationTracked);
        p.result = !p.poseIsValid ? TrackingResult_Running_OutOfRange
                 : tracked ? TrackingResult_Running_OK : TrackingResult_Fallback_RotationOnly;
        p.willDriftInYaw = false;
        p.shouldApplyHeadModel = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            pose_ = p;
        }
        VRServerDriverHost()->TrackedDevicePoseUpdated(id_, p, sizeof(p));

        auto* in = VRDriverInput();
        uint16_t b = s.buttons;
        in->UpdateBooleanComponent(h_lower_click_, b & kBtnLowerClick, -age_s);
        in->UpdateBooleanComponent(h_lower_touch_, b & kBtnLowerTouch, -age_s);
        in->UpdateBooleanComponent(h_upper_click_, b & kBtnUpperClick, -age_s);
        in->UpdateBooleanComponent(h_upper_touch_, b & kBtnUpperTouch, -age_s);
        in->UpdateBooleanComponent(h_system_click_, b & kBtnSystemClick, -age_s);
        in->UpdateBooleanComponent(h_system_touch_, b & kBtnSystemClick, -age_s);
        in->UpdateBooleanComponent(h_stick_click_, b & kBtnStickClick, -age_s);
        in->UpdateBooleanComponent(h_stick_touch_, b & kBtnStickTouch, -age_s);
        in->UpdateScalarComponent(h_stick_x_, s.stick_x, -age_s);
        in->UpdateScalarComponent(h_stick_y_, s.stick_y, -age_s);
        in->UpdateScalarComponent(h_trigger_, s.trigger, -age_s);
        in->UpdateBooleanComponent(h_trigger_touch_, (b & kBtnTriggerTouch) || s.trigger > 0.05f, -age_s);
        in->UpdateBooleanComponent(h_trigger_click_, s.trigger > 0.9f, -age_s);
        in->UpdateScalarComponent(h_grip_, s.grip, -age_s);
        in->UpdateBooleanComponent(h_grip_touch_, (b & kBtnGripTouch) || s.grip > 0.05f, -age_s);
        in->UpdateBooleanComponent(h_grip_click_, s.grip > 0.9f, -age_s);
        in->UpdateBooleanComponent(h_thumbrest_touch_, b & kBtnThumbrestTouch, -age_s);
        if (h_skeleton_ != k_ulInvalidInputComponentHandle) UpdateSkeleton(s);

        if (s.battery <= 100 && s.battery != last_battery_) {
            if (last_battery_ > 100) VRProperties()->SetBoolProperty(container_, Prop_DeviceProvidesBatteryStatus_Bool, true);
            last_battery_ = s.battery;
            VRProperties()->SetFloatProperty(container_, Prop_DeviceBatteryPercentage_Float, s.battery / 100.0f);
        }
    }

    void MarkStale() {
        if (id_ == k_unTrackedDeviceIndexInvalid) return;
        DriverPose_t p;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!pose_.poseIsValid) return;
            pose_.poseIsValid = false;
            pose_.result = TrackingResult_Running_OutOfRange;
            p = pose_;
        }
        VRServerDriverHost()->TrackedDevicePoseUpdated(id_, p, sizeof(p));
    }

private:
    // Finger curl from buttons/touches (skeleton.cpp), both motion ranges.
    void UpdateSkeleton(const HandState& s) {
        uint64_t now = MonotonicNs();
        poser_.Update(*anim_, s, last_skeleton_ns_ ? (now - last_skeleton_ns_) * 1e-9 : 0.0);
        last_skeleton_ns_ = now;
        auto* in = VRDriverInput();
        in->UpdateSkeletonComponent(h_skeleton_, VRSkeletalMotionRange_WithController,
                                    reinterpret_cast<const VRBoneTransform_t*>(poser_.WithController()), kBoneCount);
        in->UpdateSkeletonComponent(h_skeleton_, VRSkeletalMotionRange_WithoutController,
                                    reinterpret_cast<const VRBoneTransform_t*>(poser_.WithoutController()), kBoneCount);
    }

    int hand_;
    const CurlAnimation* anim_;  // null: no skeleton
    HandPoser poser_;
    VRInputComponentHandle_t h_skeleton_ = k_ulInvalidInputComponentHandle;
    uint64_t last_skeleton_ns_ = 0;
    std::atomic<uint32_t> id_{k_unTrackedDeviceIndexInvalid};
    PropertyContainerHandle_t container_ = k_ulInvalidPropertyContainer;
    std::mutex mu_;
    DriverPose_t pose_{};
    Quat world_rot_{1, 0, 0, 0};
    Vec3 world_pos_{0, 0, 0};
    Quat head_from_grip_rot_{1, 0, 0, 0};
    Vec3 head_from_grip_pos_{0, 0, 0};
    uint8_t last_battery_ = 255;
    VRInputComponentHandle_t h_lower_click_, h_lower_touch_, h_upper_click_, h_upper_touch_,
        h_system_click_, h_system_touch_, h_stick_click_, h_stick_touch_, h_stick_x_, h_stick_y_,
        h_trigger_, h_trigger_touch_, h_trigger_click_, h_grip_, h_grip_touch_, h_grip_click_,
        h_thumbrest_touch_, h_haptic_;
};

static std::string GetStringSetting(const char* key, const char* def) {
    char buf[1024] = {};
    EVRSettingsError e = VRSettingsError_None;
    VRSettings()->GetString(kSection, key, buf, sizeof(buf), &e);
    return e == VRSettingsError_None ? std::string(buf) : std::string(def);
}
static int32_t GetIntSetting(const char* key, int32_t def) {
    EVRSettingsError e = VRSettingsError_None;
    int32_t v = VRSettings()->GetInt32(kSection, key, &e);
    return e == VRSettingsError_None ? v : def;
}
static bool GetBoolSetting(const char* key, bool def) {
    EVRSettingsError e = VRSettingsError_None;
    bool v = VRSettings()->GetBool(kSection, key, &e);
    return e == VRSettingsError_None ? v : def;
}
static float GetFloatSetting(const char* key, float def) {
    EVRSettingsError e = VRSettingsError_None;
    float v = VRSettings()->GetFloat(kSection, key, &e);
    return e == VRSettingsError_None ? v : def;
}
static std::string ExpandHome(const std::string& p) {
    if (p.compare(0, 2, "~/") != 0) return p;
    const char* home = getenv("HOME");
    return std::string(home ? home : "") + p.substr(1);
}
static bool ReadFile(const std::string& path, std::string* out) {
    std::ifstream f(path);
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    *out = ss.str();
    return true;
}
static bool FileExists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

class Provider : public IServerTrackedDeviceProvider {
public:
    EVRInitError Init(IVRDriverContext* ctx) override {
        VR_INIT_SERVER_DRIVER_CONTEXT(ctx);
        if (!VRSettings()->GetBool(kSection, "enable")) {
            Log("disabled by %s.enable", kSection);
            return VRInitError_Driver_Unknown;
        }
        std::string err;
        bool skeleton = VRSettings()->GetBool(kSection, "skeleton") && anim_.Load("", &err);
        Log(skeleton ? "skeleton: finger curl from %s" : "skeleton: off (%s)",
            skeleton ? anim_.Path().c_str() : err.empty() ? "driver_touchframe.skeleton=false" : err.c_str());
        for (int h = 0; h < 2; h++) hands_[h] = std::make_unique<TouchController>(h, skeleton ? &anim_ : nullptr);

        std::string mode = GetStringSetting("mode", "relay");
        if (mode == "radio_camera") mode_ = kRadioCamera;
        else if (mode == "radio_3dof") mode_ = kRadio3Dof;
        else if (mode != "relay") Log("unknown %s.mode '%s' (relay, radio_camera, radio_3dof); using relay", kSection, mode.c_str());
        Log("mode: %s", mode_ == kRelay ? "relay (Quest bridge over UDP)"
                        : mode_ == kRadioCamera ? "radio_camera (Touch Plus dongle, XRService camera tracking)"
                                                : "radio_3dof (Touch Plus dongle, IMU orientation only)");
        if (mode_ == kRelay) {
            calib_version_ = VRSettings()->GetInt32(kSection, "calib_version");
            LoadCalibration();
            auto port = uint16_t(VRSettings()->GetInt32(kSection, "port"));
            source_ = std::make_unique<UdpSource>(port, [this](const StatePacket& pkt, uint64_t now) { OnState(pkt, now); });
        } else {
            // Radio poses are in SteamVR's space already (camera) or built there (3dof): no relay calibration.
            Log("calibration: none (radio poses are in SteamVR's tracking space)");
            source_ = MakeRadio();
        }
        if (!source_ || !source_->Start()) return VRInitError_Driver_Failed;
        cv_clone_ = CvClone::CreateFromSettings();  // camera-tracker test; off unless cv_clone_serial is set
        return VRInitError_None;
    }

    void Cleanup() override {
        if (cv_clone_) cv_clone_->Stop();
        cv_clone_.reset();
        if (source_) source_->Stop();
        source_.reset();
        radio_ = nullptr;
        VR_CLEANUP_SERVER_DRIVER_CONTEXT();
    }

    const char* const* GetInterfaceVersions() override { return k_InterfaceVersions; }

    void RunFrame() override {
        VREvent_t ev;
        while (VRServerDriverHost()->PollNextEvent(&ev, sizeof(ev))) {
            if (ev.eventType == VREvent_Input_HapticVibration) {
                const auto& hv = ev.data.hapticVibration;
                for (int h = 0; h < 2; h++) {
                    if (added_[h] && hv.componentHandle == hands_[h]->HapticHandle())
                        source_->SendHaptic(h, hv.fAmplitude, hv.fFrequency, hv.fDurationSeconds);
                }
            }
        }
        uint64_t now = MonotonicNs();
        if (mode_ == kRadio3Dof) CacheHeadPose();
        if (now - last_settings_check_ns_ > 1000000000ull) {
            last_settings_check_ns_ = now;
            if (mode_ == kRelay) {
                // tools: tf_calibrate writes new calib_* values and bumps calib_version; pick them up live.
                int32_t v = VRSettings()->GetInt32(kSection, "calib_version");
                if (v != calib_version_) {
                    calib_version_ = v;
                    LoadCalibration();
                }
            } else {
                PollRadioSettings();
                if (mode_ == kRadioCamera && reannounce_) ScanCompetitors(now);
            }
        }
        // A source that went quiet (Quest asleep, Wi-Fi drop, radio out of range) should not leave frozen hands.
        for (int h = 0; h < 2; h++) {
            uint64_t last = mode_ == kRelay ? last_packet_ns_.load() : last_hand_ns_[h].load();
            if (added_[h] && last && now - last > 250000000ull) hands_[h]->MarkStale();
        }
    }

    bool ShouldBlockStandbyMode() override { return false; }
    void EnterStandby() override {}
    void LeaveStandby() override {}

private:
    enum Mode { kRelay, kRadioCamera, kRadio3Dof };

    std::unique_ptr<ITouchSource> MakeRadio() {
        RadioBackend::Options o;
        o.mode = mode_ == kRadioCamera ? RadioBackend::Mode::kCamera : RadioBackend::Mode::k3Dof;
        std::string dir = ExpandHome("~/.config/touchframe");
        mkdir(ExpandHome("~/.config").c_str(), 0755);
        mkdir(dir.c_str(), 0755);
        o.radio.transport = GetStringSetting("radio_transport", "hidraw");
        o.radio.identity_path = ExpandHome(GetStringSetting("radio_state", "~/.config/touchframe/radio_state.json"));
        o.radio.identity_mode = GetStringSetting("radio_identity_mode", "auto");
        o.radio.led_loop = GetBoolSetting("radio_led_loop", true);
        o.radio.led.frame_period_us = GetFloatSetting("radio_led_period_us", float(1e6 / 30));
        o.radio.led.window_us = GetFloatSetting("radio_led_window_us", 65.0f);
        o.radio.led.seed_offset_us = GetFloatSetting("radio_led_seed_offset_us", 0.0f);
        o.radio.led.dwell_s = GetFloatSetting("radio_led_dwell_s", 1.5f);
        o.radio.led.settle_s = GetFloatSetting("radio_led_settle_s", 0.5f);
        o.cv.create_shared_queues = GetBoolSetting("radio_create_queues", true);
        o.cv.create_after_s = GetFloatSetting("radio_create_queues_after_s", 20.0f);
        o.xr_logs_dir = ExpandHome(GetStringSetting("radio_xrservice_logs", ""));
        reannounce_ = GetBoolSetting("radio_reannounce", true);
        for (int h = 0; h < 2; h++) {
            const char* hn = h ? "right" : "left";
            std::string key = std::string("radio_config_") + hn;
            std::string path = ExpandHome(GetStringSetting(key.c_str(), (std::string("~/.config/touchframe/touchplus_") + hn + ".json").c_str()));
            if (mode_ == kRadioCamera && !ReadFile(path, &o.config_text[h]))
                Log("radio: no XRService config for the %s hand at %s (%s.%s): it can't be camera-tracked; "
                    "generate it with tools/touchplus_config.py", hn, path.c_str(), kSection, key.c_str());
            key = std::string("radio_imu_cal_") + hn;
            path = ExpandHome(GetStringSetting(key.c_str(), (std::string("~/.config/touchframe/touchplus_") + hn + "_meta_cal.json").c_str()));
            if (FileExists(path)) o.radio.imu_cal[h] = path;
            key = std::string("radio_device_id_") + hn;
            o.device_id[h] = uint32_t(GetIntSetting(key.c_str(), 0));
        }
        o.log = [](const std::string& s) { Log("%s", s.c_str()); };
        radio_pair_version_ = GetIntSetting("radio_pair_version", 0);
        radio_recenter_version_ = GetIntSetting("radio_recenter_version", 0);
        auto b = std::make_unique<RadioBackend>(
            o, [this](int h, const HandState& s, double age) { OnHand(h, s, age); },
            [this](cv::Pose* p) {
                std::lock_guard<std::mutex> lk(head_mu_);
                if (!have_head_) return false;
                *p = head_;
                return true;
            });
        radio_ = b.get();
        return b;
    }

    // tools: bump radio_pair_version (with radio_pair_hand) to pair a controller, and
    // radio_recenter_version to re-align 3dof yaw with the headset.
    void PollRadioSettings() {
        int32_t v = GetIntSetting("radio_pair_version", 0);
        if (v != radio_pair_version_) {
            radio_pair_version_ = v;
            std::string hand = GetStringSetting("radio_pair_hand", "right");
            int h = hand == "left" ? 0 : 1;
            Log("radio: pairing requested for the %s hand (%s.radio_pair_version %d)", h ? "right" : "left", kSection, v);
            radio_->RequestPair(h);
        }
        v = GetIntSetting("radio_recenter_version", 0);
        if (v != radio_recenter_version_) {
            radio_recenter_version_ = v;
            for (int h = 0; h < 2; h++) radio_->Recenter(h);
        }
    }

    void CacheHeadPose() {
        TrackedDevicePose_t p{};
        VRServerDriverHost()->GetRawTrackedDevicePoses(0, &p, 1);
        if (!p.bPoseIsValid) return;
        std::lock_guard<std::mutex> lk(head_mu_);
        head_ = cv::FromMatrix(p.mDeviceToAbsoluteTracking);
        have_head_ = true;
    }

    // XRService tracks one controller per hand. A Touch Plus announced while a Steam Frame
    // controller holds that hand's slot doesn't get the slot when it frees (FRAME-TRACKER §9.3),
    // so when the competitor goes away, announce again under a fresh deviceId.
    void ScanCompetitors(uint64_t now) {
        static TrackedDevicePose_t poses[k_unMaxTrackedDeviceCount];
        VRServerDriverHost()->GetRawTrackedDevicePoses(0, poses, k_unMaxTrackedDeviceCount);
        bool comp[2] = {false, false};
        for (uint32_t i = 1; i < k_unMaxTrackedDeviceCount; i++) {
            if (i == hands_[0]->Id() || i == hands_[1]->Id() || !poses[i].bDeviceIsConnected) continue;
            PropertyContainerHandle_t c = VRProperties()->TrackedDeviceToPropertyContainer(i);
            if (c == k_ulInvalidPropertyContainer) continue;
            ETrackedPropertyError e = TrackedProp_Success;
            int32_t cls = VRProperties()->GetInt32Property(c, Prop_DeviceClass_Int32, &e);
            if (e != TrackedProp_Success || cls != TrackedDeviceClass_Controller) continue;
            int32_t role = VRProperties()->GetInt32Property(c, Prop_ControllerRoleHint_Int32, &e);
            if (e != TrackedProp_Success) continue;
            if (role == TrackedControllerRole_LeftHand) comp[0] = true;
            if (role == TrackedControllerRole_RightHand) comp[1] = true;
        }
        for (int h = 0; h < 2; h++) {
            const char* hn = h ? "right" : "left";
            if (comp[h] && !competitor_[h])
                Log("radio: another %s controller is on. While it holds XRService's %s tracker the Touch Plus %s "
                    "gets no camera pose; when it turns off, the Touch Plus is announced again", hn, hn, hn);
            if (!comp[h] && competitor_[h] && radio_->connected(h)) {
                if (now - last_reannounce_ns_[h] > 5000000000ull) {
                    last_reannounce_ns_[h] = now;
                    Log("radio: the other %s controller turned off; re-announcing the Touch Plus %s", hn, hn);
                    radio_->Reannounce(h);
                }
            }
            competitor_[h] = comp[h];
        }
    }

    void LoadCalibration() {
        auto* s = VRSettings();
        Quat q{s->GetFloat(kSection, "calib_qw"), s->GetFloat(kSection, "calib_qx"),
               s->GetFloat(kSection, "calib_qy"), s->GetFloat(kSection, "calib_qz")};
        double n = std::sqrt(q.w * q.w + q.x * q.x + q.y * q.y + q.z * q.z);
        if (n < 1e-6) q = {1, 0, 0, 0}; else q = {q.w / n, q.x / n, q.y / n, q.z / n};
        Vec3 t{s->GetFloat(kSection, "calib_tx"), s->GetFloat(kSection, "calib_ty"), s->GetFloat(kSection, "calib_tz")};
        for (auto& h : hands_) h->SetCalibration(q, t);
        Log("calibration q=(%.4f %.4f %.4f %.4f) t=(%.3f %.3f %.3f)", q.w, q.x, q.y, q.z, t.x, t.y, t.z);
    }

    void OnState(const StatePacket& pkt, uint64_t recv_ns) {
        last_packet_ns_ = recv_ns;
        for (int h = 0; h < 2; h++) {
            const HandState& s = pkt.hand[h];
            if (!added_[h]) {
                if (!(s.flags & kConnected)) continue;
                AddHand(h);
                continue;
            }
            // Relay latency is unknown to the driver until clocks are aligned; use a fixed estimate.
            hands_[h]->Update(s, latency_s_);
        }
    }

    // Radio: one hand's state, with the pose's age (XRService's own timestamps, or the IMU's).
    void OnHand(int h, const HandState& s, double age_s) {
        last_hand_ns_[h] = MonotonicNs();
        if (!added_[h]) {
            if (!(s.flags & kConnected)) return;
            AddHand(h);
            return;
        }
        hands_[h]->Update(s, age_s);
    }

    void AddHand(int h) {
        // Add lazily so unused Touch Plus never take roles from the Frame controllers.
        added_[h] = VRServerDriverHost()->TrackedDeviceAdded(hands_[h]->Serial(), TrackedDeviceClass_Controller, hands_[h].get());
        Log("TrackedDeviceAdded %s -> %d", hands_[h]->Serial(), int(added_[h]));
    }

    CurlAnimation anim_;
    std::unique_ptr<TouchController> hands_[2];
    std::atomic<bool> added_[2] = {false, false};
    Mode mode_ = kRelay;
    std::unique_ptr<ITouchSource> source_;
    RadioBackend* radio_ = nullptr;  // source_ in the radio modes
    std::unique_ptr<CvClone> cv_clone_;
    std::atomic<uint64_t> last_packet_ns_{0};
    std::atomic<uint64_t> last_hand_ns_[2] = {{0}, {0}};
    double latency_s_ = 0.015;
    uint64_t last_settings_check_ns_ = 0;
    int32_t calib_version_ = 0;
    int32_t radio_pair_version_ = 0, radio_recenter_version_ = 0;
    bool reannounce_ = true;
    bool competitor_[2] = {false, false};
    uint64_t last_reannounce_ns_[2] = {0, 0};
    std::mutex head_mu_;
    cv::Pose head_;
    bool have_head_ = false;
};

}  // namespace tf

static tf::Provider g_provider;

extern "C" __attribute__((visibility("default"))) void* HmdDriverFactory(const char* name, int* ret) {
    if (std::strcmp(name, vr::IServerTrackedDeviceProvider_Version) == 0) return &g_provider;
    if (ret) *ret = vr::VRInitError_Init_InterfaceNotFound;
    return nullptr;
}
