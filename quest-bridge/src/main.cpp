// TouchFrame Quest bridge: a headless-ish OpenXR app for the Quest 3 headset (sitting on a
// shelf as the controllers' radio and tracker). Every frame it reads both Touch Plus
// controllers (grip pose + velocities, buttons, touches, analogs) and sends a
// tf::StatePacket over UDP to the Frame driver; haptic packets coming back are played.
//
// Target: `adb shell setprop debug.touchframe.target 192.168.0.195:28430`
// (read at start and every 2 s, so it can change while running).
//
// Runs unattended: the driver's heartbeat says whether the Frame is listening, a status line
// goes to logcat every 5 s (`adb logcat -s TouchBridge`), socket errors (Wi-Fi drops) are
// retried, and a lost OpenXR session is rebuilt. Keeping the unworn headset awake is
// tools/quest.sh's job (the prox_close broadcast needs the shell user).
#include <android/log.h>
#include <android/window.h>
#include <android_native_app_glue.h>
#include <arpa/inet.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <jni.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define XR_USE_PLATFORM_ANDROID
#define XR_USE_GRAPHICS_API_OPENGL_ES
#include <openxr/openxr.h>
#include <openxr/openxr_platform.h>

#include "../../driver/src/protocol.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "TouchBridge", __VA_ARGS__)
#define CHECK(x)                                                         \
    do {                                                                 \
        XrResult r_ = (x);                                               \
        if (XR_FAILED(r_)) { LOG("%s failed: %d", #x, r_); return false; } \
    } while (0)

namespace {

uint64_t NowNs() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ull + ts.tv_nsec;
}

struct Net {
    int fd = -1;
    sockaddr_in target{};
    bool have_target = false;
    std::string target_str;
    uint64_t last_check = 0;

    uint64_t sent = 0, send_errors = 0, haptics = 0, heartbeats = 0;
    int last_errno = 0;
    uint64_t last_heartbeat = 0;
    float rtt_ms = 0;
    bool linked = false;

    void Init() {
        if (fd >= 0) close(fd);
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { LOG("socket: %s", strerror(errno)); return; }
        fcntl(fd, F_SETFL, O_NONBLOCK);
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(tf::kDefaultPort);  // haptics come back to this port
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) LOG("bind: %s", strerror(errno));
    }

    void RefreshTarget() {
        uint64_t now = NowNs();
        if (now - last_check < 2000000000ull && last_check) return;
        last_check = now;
        char v[PROP_VALUE_MAX] = {};
        __system_property_get("debug.touchframe.target", v);
        if (target_str == v) return;
        target_str = v;
        std::string s(v);
        size_t colon = s.find(':');
        std::string ip = s.substr(0, colon);
        int port = colon == std::string::npos ? tf::kDefaultPort : atoi(s.c_str() + colon + 1);
        sockaddr_in t{};
        t.sin_family = AF_INET;
        t.sin_port = htons(uint16_t(port));
        have_target = inet_pton(AF_INET, ip.c_str(), &t.sin_addr) == 1;
        target = t;
        LOG("target '%s' -> %s", v, have_target ? "ok" : "unset/invalid");
    }

    void Send(const tf::StatePacket& p) {
        if (!have_target) return;
        if (fd < 0) Init();
        if (sendto(fd, &p, sizeof(p), 0, reinterpret_cast<sockaddr*>(&target), sizeof(target)) < 0) {
            // ENETUNREACH etc. while Wi-Fi is down: keep trying, log each new error once.
            if (errno != last_errno) LOG("send to %s: %s", target_str.c_str(), strerror(errno));
            last_errno = errno;
            send_errors++;
            if (errno == EBADF || errno == ENOTSOCK) Init();
            return;
        }
        if (last_errno) LOG("send to %s ok again", target_str.c_str());
        last_errno = 0;
        sent++;
    }

    // Drains the socket: heartbeats update the link state, haptics go to on_haptic.
    template <class F>
    void Receive(F on_haptic) {
        uint8_t buf[64];
        ssize_t n;
        while (fd >= 0 && (n = recv(fd, buf, sizeof(buf), 0)) >= 4) {
            uint32_t magic;
            memcpy(&magic, buf, 4);
            if (n == sizeof(tf::HapticPacket) && magic == tf::kHapticMagic) {
                tf::HapticPacket h;
                memcpy(&h, buf, sizeof(h));
                if (h.hand < 2) { haptics++; on_haptic(h); }
            } else if (n == sizeof(tf::HeartbeatPacket) && magic == tf::kHeartbeatMagic) {
                tf::HeartbeatPacket hb;
                memcpy(&hb, buf, sizeof(hb));
                last_heartbeat = NowNs();
                rtt_ms = float(last_heartbeat - hb.source_time_ns) / 1e6f;
                heartbeats++;
                if (!linked) LOG("driver linked: %s, rtt %.1f ms", target_str.c_str(), rtt_ms);
                linked = true;
            }
        }
        if (linked && NowNs() - last_heartbeat > 3000000000ull) {
            linked = false;
            LOG("driver not answering for 3 s (Frame asleep, SteamVR restarting, Wi-Fi?); still sending");
        }
    }
};

const char* StateName(XrSessionState s) {
    static const char* names[] = {"unknown", "idle", "ready", "synchronized", "visible",
                                  "focused", "stopping", "loss_pending", "exiting"};
    return unsigned(s) < 9 ? names[s] : "?";
}

const char* HandStatus(uint8_t f) {
    if (!(f & tf::kConnected)) return "off";
    if ((f & tf::kPositionTracked) && (f & tf::kOrientationTracked)) return "tracked";
    if (f & tf::kOrientationValid) return "rot-only";
    return "lost";
}

struct Bridge {
    android_app* app = nullptr;
    bool resumed = false;

    EGLDisplay egl_display = EGL_NO_DISPLAY;
    EGLContext egl_context = EGL_NO_CONTEXT;
    EGLConfig egl_config = nullptr;
    EGLSurface egl_surface = EGL_NO_SURFACE;

    XrInstance instance = XR_NULL_HANDLE;
    XrSystemId system = XR_NULL_SYSTEM_ID;
    XrSession session = XR_NULL_HANDLE;
    XrSpace space = XR_NULL_HANDLE;
    XrSessionState state = XR_SESSION_STATE_UNKNOWN;
    bool running = false;

    XrActionSet set = XR_NULL_HANDLE;
    XrPath hand_path[2];
    XrAction a_grip_pose, a_trigger, a_trigger_touch, a_squeeze, a_stick, a_stick_click, a_stick_touch,
        a_lower_click, a_lower_touch, a_upper_click, a_upper_touch, a_menu, a_thumbrest, a_haptic;
    XrSpace grip_space[2] = {XR_NULL_HANDLE, XR_NULL_HANDLE};

    Net net;
    uint32_t seq = 0;
    bool loader_ready = false;
    bool session_lost = false;
    uint8_t last_flags[2] = {0, 0};
    uint64_t last_status = 0, sent_at_status = 0;

    bool InitEgl() {
        egl_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        eglInitialize(egl_display, nullptr, nullptr);
        const EGLint cfg_attr[] = {EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT, EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
                                   EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_NONE};
        EGLint n = 0;
        if (!eglChooseConfig(egl_display, cfg_attr, &egl_config, 1, &n) || n < 1) return false;
        const EGLint ctx_attr[] = {EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE};
        egl_context = eglCreateContext(egl_display, egl_config, EGL_NO_CONTEXT, ctx_attr);
        const EGLint pb_attr[] = {EGL_WIDTH, 16, EGL_HEIGHT, 16, EGL_NONE};
        egl_surface = eglCreatePbufferSurface(egl_display, egl_config, pb_attr);
        return eglMakeCurrent(egl_display, egl_surface, egl_surface, egl_context);
    }

    XrAction MakeAction(const char* name, XrActionType type, bool per_hand = true) {
        XrActionCreateInfo ci{XR_TYPE_ACTION_CREATE_INFO};
        strncpy(ci.actionName, name, sizeof(ci.actionName) - 1);
        strncpy(ci.localizedActionName, name, sizeof(ci.localizedActionName) - 1);
        ci.actionType = type;
        ci.countSubactionPaths = per_hand ? 2 : 0;
        ci.subactionPaths = per_hand ? hand_path : nullptr;
        XrAction a = XR_NULL_HANDLE;
        xrCreateAction(set, &ci, &a);
        return a;
    }

    XrPath P(const char* s) {
        XrPath p;
        xrStringToPath(instance, s, &p);
        return p;
    }

    bool InitXr() {
        if (!loader_ready) {
            PFN_xrInitializeLoaderKHR init_loader = nullptr;
            xrGetInstanceProcAddr(XR_NULL_HANDLE, "xrInitializeLoaderKHR", (PFN_xrVoidFunction*)&init_loader);
            XrLoaderInitInfoAndroidKHR li{XR_TYPE_LOADER_INIT_INFO_ANDROID_KHR};
            li.applicationVM = app->activity->vm;
            li.applicationContext = app->activity->clazz;
            CHECK(init_loader((XrLoaderInitInfoBaseHeaderKHR*)&li));
            loader_ready = true;
        }

        const char* exts[] = {XR_KHR_OPENGL_ES_ENABLE_EXTENSION_NAME, XR_KHR_ANDROID_CREATE_INSTANCE_EXTENSION_NAME};
        XrInstanceCreateInfoAndroidKHR aci{XR_TYPE_INSTANCE_CREATE_INFO_ANDROID_KHR};
        aci.applicationVM = app->activity->vm;
        aci.applicationActivity = app->activity->clazz;
        XrInstanceCreateInfo ici{XR_TYPE_INSTANCE_CREATE_INFO};
        ici.next = &aci;
        strcpy(ici.applicationInfo.applicationName, "TouchFrame Bridge");
        ici.applicationInfo.apiVersion = XR_MAKE_VERSION(1, 0, 34);
        ici.enabledExtensionCount = 2;
        ici.enabledExtensionNames = exts;
        CHECK(xrCreateInstance(&ici, &instance));

        XrSystemGetInfo sgi{XR_TYPE_SYSTEM_GET_INFO};
        sgi.formFactor = XR_FORM_FACTOR_HEAD_MOUNTED_DISPLAY;
        CHECK(xrGetSystem(instance, &sgi, &system));

        PFN_xrGetOpenGLESGraphicsRequirementsKHR gles_req = nullptr;
        xrGetInstanceProcAddr(instance, "xrGetOpenGLESGraphicsRequirementsKHR", (PFN_xrVoidFunction*)&gles_req);
        XrGraphicsRequirementsOpenGLESKHR req{XR_TYPE_GRAPHICS_REQUIREMENTS_OPENGL_ES_KHR};
        CHECK(gles_req(instance, system, &req));

        if (egl_context == EGL_NO_CONTEXT && !InitEgl()) { LOG("EGL init failed"); return false; }
        XrGraphicsBindingOpenGLESAndroidKHR gb{XR_TYPE_GRAPHICS_BINDING_OPENGL_ES_ANDROID_KHR};
        gb.display = egl_display;
        gb.config = egl_config;
        gb.context = egl_context;
        XrSessionCreateInfo sci{XR_TYPE_SESSION_CREATE_INFO};
        sci.next = &gb;
        sci.systemId = system;
        CHECK(xrCreateSession(instance, &sci, &session));

        // STAGE stays fixed to the room while the shelf headset keeps tracking; LOCAL as fallback.
        XrReferenceSpaceCreateInfo rs{XR_TYPE_REFERENCE_SPACE_CREATE_INFO};
        rs.poseInReferenceSpace.orientation.w = 1;
        rs.referenceSpaceType = XR_REFERENCE_SPACE_TYPE_STAGE;
        if (XR_FAILED(xrCreateReferenceSpace(session, &rs, &space))) {
            rs.referenceSpaceType = XR_REFERENCE_SPACE_TYPE_LOCAL;
            CHECK(xrCreateReferenceSpace(session, &rs, &space));
        }

        XrActionSetCreateInfo asci{XR_TYPE_ACTION_SET_CREATE_INFO};
        strcpy(asci.actionSetName, "touchframe");
        strcpy(asci.localizedActionSetName, "TouchFrame");
        CHECK(xrCreateActionSet(instance, &asci, &set));
        hand_path[0] = P("/user/hand/left");
        hand_path[1] = P("/user/hand/right");
        a_grip_pose = MakeAction("grip_pose", XR_ACTION_TYPE_POSE_INPUT);
        a_trigger = MakeAction("trigger", XR_ACTION_TYPE_FLOAT_INPUT);
        a_trigger_touch = MakeAction("trigger_touch", XR_ACTION_TYPE_BOOLEAN_INPUT);
        a_squeeze = MakeAction("squeeze", XR_ACTION_TYPE_FLOAT_INPUT);
        a_stick = MakeAction("stick", XR_ACTION_TYPE_VECTOR2F_INPUT);
        a_stick_click = MakeAction("stick_click", XR_ACTION_TYPE_BOOLEAN_INPUT);
        a_stick_touch = MakeAction("stick_touch", XR_ACTION_TYPE_BOOLEAN_INPUT);
        a_lower_click = MakeAction("lower_click", XR_ACTION_TYPE_BOOLEAN_INPUT);
        a_lower_touch = MakeAction("lower_touch", XR_ACTION_TYPE_BOOLEAN_INPUT);
        a_upper_click = MakeAction("upper_click", XR_ACTION_TYPE_BOOLEAN_INPUT);
        a_upper_touch = MakeAction("upper_touch", XR_ACTION_TYPE_BOOLEAN_INPUT);
        a_menu = MakeAction("menu", XR_ACTION_TYPE_BOOLEAN_INPUT);
        a_thumbrest = MakeAction("thumbrest", XR_ACTION_TYPE_BOOLEAN_INPUT);
        a_haptic = MakeAction("haptic", XR_ACTION_TYPE_VIBRATION_OUTPUT);

        std::vector<XrActionSuggestedBinding> b;
        auto both = [&](XrAction a, const char* suffix) {
            b.push_back({a, P((std::string("/user/hand/left") + suffix).c_str())});
            b.push_back({a, P((std::string("/user/hand/right") + suffix).c_str())});
        };
        both(a_grip_pose, "/input/grip/pose");
        both(a_trigger, "/input/trigger/value");
        both(a_trigger_touch, "/input/trigger/touch");
        both(a_squeeze, "/input/squeeze/value");
        both(a_stick, "/input/thumbstick");
        both(a_stick_click, "/input/thumbstick/click");
        both(a_stick_touch, "/input/thumbstick/touch");
        both(a_thumbrest, "/input/thumbrest/touch");
        both(a_haptic, "/output/haptic");
        b.push_back({a_lower_click, P("/user/hand/left/input/x/click")});
        b.push_back({a_lower_click, P("/user/hand/right/input/a/click")});
        b.push_back({a_lower_touch, P("/user/hand/left/input/x/touch")});
        b.push_back({a_lower_touch, P("/user/hand/right/input/a/touch")});
        b.push_back({a_upper_click, P("/user/hand/left/input/y/click")});
        b.push_back({a_upper_click, P("/user/hand/right/input/b/click")});
        b.push_back({a_upper_touch, P("/user/hand/left/input/y/touch")});
        b.push_back({a_upper_touch, P("/user/hand/right/input/b/touch")});
        b.push_back({a_menu, P("/user/hand/left/input/menu/click")});
        XrInteractionProfileSuggestedBinding sb{XR_TYPE_INTERACTION_PROFILE_SUGGESTED_BINDING};
        sb.interactionProfile = P("/interaction_profiles/oculus/touch_controller");
        sb.suggestedBindings = b.data();
        sb.countSuggestedBindings = uint32_t(b.size());
        CHECK(xrSuggestInteractionProfileBindings(instance, &sb));

        XrSessionActionSetsAttachInfo at{XR_TYPE_SESSION_ACTION_SETS_ATTACH_INFO};
        at.countActionSets = 1;
        at.actionSets = &set;
        CHECK(xrAttachSessionActionSets(session, &at));

        for (int h = 0; h < 2; h++) {
            XrActionSpaceCreateInfo sp{XR_TYPE_ACTION_SPACE_CREATE_INFO};
            sp.action = a_grip_pose;
            sp.subactionPath = hand_path[h];
            sp.poseInActionSpace.orientation.w = 1;
            CHECK(xrCreateActionSpace(session, &sp, &grip_space[h]));
        }
        if (net.fd < 0) net.Init();
        LOG("OpenXR ready (space type %d)", rs.referenceSpaceType);
        return true;
    }

    // Destroying the instance destroys the session, spaces and actions with it.
    void DestroyXr() {
        if (instance != XR_NULL_HANDLE) xrDestroyInstance(instance);
        instance = XR_NULL_HANDLE;
        session = XR_NULL_HANDLE;
        space = grip_space[0] = grip_space[1] = XR_NULL_HANDLE;
        set = XR_NULL_HANDLE;
        system = XR_NULL_SYSTEM_ID;
        state = XR_SESSION_STATE_UNKNOWN;
        running = false;
        session_lost = false;
    }

    void Status() {
        uint64_t now = NowNs();
        if (last_status && now - last_status < 5000000000ull) return;
        float rate = last_status ? float(net.sent - sent_at_status) * 1e9f / float(now - last_status) : 0.f;
        last_status = now;
        sent_at_status = net.sent;
        char link[64];
        if (net.linked) snprintf(link, sizeof(link), "linked rtt %.1f ms", net.rtt_ms);
        else snprintf(link, sizeof(link), "%s", net.heartbeats ? "lost" : "waiting");
        LOG("status: session %s, target %s, sent %llu (%.0f/s), L %s, R %s, driver %s, haptics %llu, send errors %llu",
            instance == XR_NULL_HANDLE ? "none" : StateName(state),
            net.have_target ? net.target_str.c_str() : "unset", (unsigned long long)net.sent, rate,
            HandStatus(last_flags[0]), HandStatus(last_flags[1]), link,
            (unsigned long long)net.haptics, (unsigned long long)net.send_errors);
    }

    void ApplyHaptic(const tf::HapticPacket& hp) {
        if (state != XR_SESSION_STATE_FOCUSED) return;
        XrHapticVibration vib{XR_TYPE_HAPTIC_VIBRATION};
        vib.amplitude = hp.amplitude;
        vib.frequency = hp.frequency > 0 ? hp.frequency : XR_FREQUENCY_UNSPECIFIED;
        vib.duration = hp.duration_s > 0 ? XrDuration(hp.duration_s * 1e9) : XR_MIN_HAPTIC_DURATION;
        XrHapticActionInfo hi{XR_TYPE_HAPTIC_ACTION_INFO};
        hi.action = a_haptic;
        hi.subactionPath = hand_path[hp.hand];
        xrApplyHapticFeedback(session, &hi, reinterpret_cast<XrHapticBaseHeader*>(&vib));
    }

    void PollEvents() {
        XrEventDataBuffer ev{XR_TYPE_EVENT_DATA_BUFFER};
        while (xrPollEvent(instance, &ev) == XR_SUCCESS) {
            if (ev.type == XR_TYPE_EVENT_DATA_SESSION_STATE_CHANGED) {
                auto* e = reinterpret_cast<XrEventDataSessionStateChanged*>(&ev);
                state = e->state;
                LOG("session state %d", state);
                if (state == XR_SESSION_STATE_READY) {
                    XrSessionBeginInfo bi{XR_TYPE_SESSION_BEGIN_INFO};
                    bi.primaryViewConfigurationType = XR_VIEW_CONFIGURATION_TYPE_PRIMARY_STEREO;
                    running = XR_SUCCEEDED(xrBeginSession(session, &bi));
                } else if (state == XR_SESSION_STATE_STOPPING) {
                    xrEndSession(session);
                    running = false;
                } else if (state == XR_SESSION_STATE_LOSS_PENDING) {
                    session_lost = true;  // rebuilt from the main loop
                } else if (state == XR_SESSION_STATE_EXITING) {
                    ANativeActivity_finish(app->activity);
                }
            } else if (ev.type == XR_TYPE_EVENT_DATA_INTERACTION_PROFILE_CHANGED) {
                // "none" while the runtime has switched to hand tracking (controllers set down).
                for (int h = 0; h < 2; h++) {
                    XrInteractionProfileState ip{XR_TYPE_INTERACTION_PROFILE_STATE};
                    xrGetCurrentInteractionProfile(session, hand_path[h], &ip);
                    char name[XR_MAX_PATH_LENGTH] = "none";
                    uint32_t n = 0;
                    if (ip.interactionProfile != XR_NULL_PATH)
                        xrPathToString(instance, ip.interactionProfile, sizeof(name), &n, name);
                    LOG("%s hand profile: %s", h ? "right" : "left", name);
                }
            }
            ev = {XR_TYPE_EVENT_DATA_BUFFER};
        }
    }

    bool GetBool(XrAction a, int h) {
        XrActionStateGetInfo gi{XR_TYPE_ACTION_STATE_GET_INFO};
        gi.action = a;
        gi.subactionPath = hand_path[h];
        XrActionStateBoolean s{XR_TYPE_ACTION_STATE_BOOLEAN};
        xrGetActionStateBoolean(session, &gi, &s);
        return s.isActive && s.currentState;
    }

    float GetFloat(XrAction a, int h) {
        XrActionStateGetInfo gi{XR_TYPE_ACTION_STATE_GET_INFO};
        gi.action = a;
        gi.subactionPath = hand_path[h];
        XrActionStateFloat s{XR_TYPE_ACTION_STATE_FLOAT};
        xrGetActionStateFloat(session, &gi, &s);
        return s.isActive ? s.currentState : 0.f;
    }

    void Sample(XrTime t) {
        XrActiveActionSet aas{set, XR_NULL_PATH};
        XrActionsSyncInfo si{XR_TYPE_ACTIONS_SYNC_INFO};
        si.countActiveActionSets = 1;
        si.activeActionSets = &aas;
        xrSyncActions(session, &si);

        tf::StatePacket pkt{};
        pkt.magic = tf::kStateMagic;
        pkt.seq = ++seq;
        pkt.source_time_ns = NowNs();
        for (int h = 0; h < 2; h++) {
            tf::HandState& s = pkt.hand[h];
            s.battery = 255;
            XrActionStateGetInfo gi{XR_TYPE_ACTION_STATE_GET_INFO};
            gi.action = a_grip_pose;
            gi.subactionPath = hand_path[h];
            XrActionStatePose ps{XR_TYPE_ACTION_STATE_POSE};
            xrGetActionStatePose(session, &gi, &ps);
            if (ps.isActive) s.flags |= tf::kConnected;

            XrSpaceVelocity vel{XR_TYPE_SPACE_VELOCITY};
            XrSpaceLocation loc{XR_TYPE_SPACE_LOCATION};
            loc.next = &vel;
            if (ps.isActive && XR_SUCCEEDED(xrLocateSpace(grip_space[h], space, t, &loc))) {
                auto f = loc.locationFlags;
                if (f & XR_SPACE_LOCATION_ORIENTATION_VALID_BIT) s.flags |= tf::kOrientationValid;
                if (f & XR_SPACE_LOCATION_POSITION_VALID_BIT) s.flags |= tf::kPositionValid;
                if (f & XR_SPACE_LOCATION_ORIENTATION_TRACKED_BIT) s.flags |= tf::kOrientationTracked;
                if (f & XR_SPACE_LOCATION_POSITION_TRACKED_BIT) s.flags |= tf::kPositionTracked;
                const auto& p = loc.pose;
                s.pos[0] = p.position.x; s.pos[1] = p.position.y; s.pos[2] = p.position.z;
                s.rot[0] = p.orientation.x; s.rot[1] = p.orientation.y;
                s.rot[2] = p.orientation.z; s.rot[3] = p.orientation.w;
                if (vel.velocityFlags & XR_SPACE_VELOCITY_LINEAR_VALID_BIT) {
                    s.lin_vel[0] = vel.linearVelocity.x; s.lin_vel[1] = vel.linearVelocity.y; s.lin_vel[2] = vel.linearVelocity.z;
                }
                if (vel.velocityFlags & XR_SPACE_VELOCITY_ANGULAR_VALID_BIT) {
                    s.ang_vel[0] = vel.angularVelocity.x; s.ang_vel[1] = vel.angularVelocity.y; s.ang_vel[2] = vel.angularVelocity.z;
                }
            }

            s.trigger = GetFloat(a_trigger, h);
            s.grip = GetFloat(a_squeeze, h);
            XrActionStateGetInfo vi{XR_TYPE_ACTION_STATE_GET_INFO};
            vi.action = a_stick;
            vi.subactionPath = hand_path[h];
            XrActionStateVector2f v{XR_TYPE_ACTION_STATE_VECTOR2F};
            xrGetActionStateVector2f(session, &vi, &v);
            if (v.isActive) { s.stick_x = v.currentState.x; s.stick_y = v.currentState.y; }

            uint16_t b = 0;
            if (GetBool(a_lower_click, h)) b |= tf::kBtnLowerClick;
            if (GetBool(a_upper_click, h)) b |= tf::kBtnUpperClick;
            if (h == 0 && GetBool(a_menu, h)) b |= tf::kBtnSystemClick;
            if (GetBool(a_stick_click, h)) b |= tf::kBtnStickClick;
            if (GetBool(a_lower_touch, h)) b |= tf::kBtnLowerTouch;
            if (GetBool(a_upper_touch, h)) b |= tf::kBtnUpperTouch;
            if (GetBool(a_stick_touch, h)) b |= tf::kBtnStickTouch;
            if (GetBool(a_thumbrest, h)) b |= tf::kBtnThumbrestTouch;
            if (GetBool(a_trigger_touch, h)) b |= tf::kBtnTriggerTouch;
            if (s.grip > 0.05f) b |= tf::kBtnGripTouch;
            s.buttons = b;
            last_flags[h] = s.flags;
        }
        net.Send(pkt);
    }

    void Frame() {
        XrFrameWaitInfo wi{XR_TYPE_FRAME_WAIT_INFO};
        XrFrameState fs{XR_TYPE_FRAME_STATE};
        if (XR_FAILED(xrWaitFrame(session, &wi, &fs))) return;
        XrFrameBeginInfo bi{XR_TYPE_FRAME_BEGIN_INFO};
        xrBeginFrame(session, &bi);
        if (state == XR_SESSION_STATE_FOCUSED) Sample(fs.predictedDisplayTime);
        // No layers: nothing to show; the headset is on a shelf.
        XrFrameEndInfo ei{XR_TYPE_FRAME_END_INFO};
        ei.displayTime = fs.predictedDisplayTime;
        ei.environmentBlendMode = XR_ENVIRONMENT_BLEND_MODE_OPAQUE;
        xrEndFrame(session, &ei);
    }
};

void OnCmd(android_app* app, int32_t cmd) {
    auto* b = static_cast<Bridge*>(app->userData);
    if (cmd == APP_CMD_RESUME) b->resumed = true;
    if (cmd == APP_CMD_PAUSE) b->resumed = false;
}

}  // namespace

void android_main(android_app* app) {
    Bridge b;
    b.app = app;
    app->userData = &b;
    app->onAppCmd = OnCmd;
    JNIEnv* env;
    app->activity->vm->AttachCurrentThread(&env, nullptr);
    ANativeActivity_setWindowFlags(app->activity, AWINDOW_FLAG_KEEP_SCREEN_ON, 0);

    uint64_t next_init = 0;
    while (!app->destroyRequested) {
        int events;
        android_poll_source* src;
        int timeout = (b.running || b.resumed) ? 0 : 100;
        while (ALooper_pollOnce(timeout, nullptr, &events, (void**)&src) >= 0) {
            if (src) src->process(app, src);
            if (app->destroyRequested) break;
            timeout = 0;
        }
        if (b.session_lost) {
            LOG("session lost; rebuilding OpenXR in 2 s");
            b.DestroyXr();
            next_init = NowNs() + 2000000000ull;
        }
        // (Re)start OpenXR: at launch, after a session loss, or until the runtime is up.
        if (b.instance == XR_NULL_HANDLE && NowNs() >= next_init) {
            if (!b.InitXr()) {
                LOG("OpenXR init failed; retrying in 2 s");
                b.DestroyXr();
                next_init = NowNs() + 2000000000ull;
            }
        }
        b.net.RefreshTarget();
        b.net.Receive([&](const tf::HapticPacket& h) { b.ApplyHaptic(h); });
        b.Status();
        if (b.instance == XR_NULL_HANDLE) continue;
        b.PollEvents();
        if (b.running) b.Frame();
    }
    b.DestroyXr();
    app->activity->vm->DetachCurrentThread();
}
