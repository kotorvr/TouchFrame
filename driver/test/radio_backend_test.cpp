// RadioBackend pieces: the XRService log parser and watcher, the 3dof orientation filter, and (with
// a transport argument) the backend end to end against fake_dongle in 3dof and camera mode. Camera
// mode outside vrserver has no block queues: inputs must still reach the Provider.
//   radio_backend_test SCRATCH_DIR [TRANSPORT STATE_FILE]
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#define MKDIR(p) mkdir(p, 0755)
#endif

#include "radio_backend.h"
#include "xr_log.h"

using namespace tf;
using namespace tf::cv;

static int g_fail = 0;
#define CHECKF(c, ...)                                          \
    do {                                                        \
        if (!(c)) {                                             \
            printf("FAIL %s:%d: %s: ", __FILE__, __LINE__, #c); \
            printf(__VA_ARGS__);                                \
            printf("\n");                                       \
            g_fail++;                                           \
        }                                                       \
    } while (0)
#define CHECK(c) CHECKF(c, "%s", "")

static double Now() { return radio::HostNowNs() * 1e-9; }
static void Sleep(double s) { std::this_thread::sleep_for(std::chrono::milliseconds(int(s * 1000))); }

static void TestParse() {
    XrLogLine l;
    // Lines as XRService writes them (docs/re/DEV-1.md, FRAME-MODEL.md §4).
    CHECK(ParseXrLogLine("10:41:09.091 [ControllerTracking]: initializing controller 0, serial number: tfclone_tftouchplus_left", &l) &&
          l.kind == XrLogLine::kTrackerInit && l.tracker == 0 && l.serial == "tfclone_tftouchplus_left");
    CHECK(ParseXrLogLine("XRService: Received controller Connection event for device 2 ... initializing controller 1, serial number: 8d59320477d2\r", &l) &&
          l.kind == XrLogLine::kTrackerInit && l.tracker == 1 && l.serial == "8d59320477d2");
    CHECK(ParseXrLogLine("10:41:12.000 [ContrLedsStats 1]: Observed LED 3 reproj 0.07", &l) && l.kind == XrLogLine::kLedStats &&
          l.tracker == 1);
    CHECK(ParseXrLogLine("10:41:11.366 [ControllerTracking 0]: Trying to track first LED frame with timestamp: 13897.229567", &l) &&
          l.kind == XrLogLine::kFrameStamp && std::fabs(l.frame_t - 13897.229567) < 1e-9 && l.tracker == 0);
    CHECK(ParseXrLogLine("[ControllerTracking 1]: Not having enough IMU data for controller frame, skipping processing it. "
                         "Current timestamp: 13901.262900, got state timestamp: 13901.250000",
                         &l) &&
          l.kind == XrLogLine::kFrameStamp && std::fabs(l.frame_t - 13901.2629) < 1e-9 && l.tracker == 1);
    CHECK(!ParseXrLogLine("10:41:07.141 setControllerTrackingStreamingMode() streamingMode: 4", &l));
    CHECK(!ParseXrLogLine("initializing controller x, serial number: ", &l));
}

static void Append(const std::string& path, const std::string& text) {
    std::ofstream f(path, std::ios::app | std::ios::binary);
    f << text;
}

static void TestWatcher(const std::string& scratch) {
    std::string dir = scratch + "/xrlogs";
    MKDIR(dir.c_str());
    std::string sub = dir + "/XRService-2026-10-04";
    MKDIR(sub.c_str());
    std::string log1 = sub + "/XRService-1.log";
    remove(log1.c_str());
    // Before the driver looks: our left controller was already initialised as tracker 1, and an old
    // LED-stats line must not count.
    Append(log1, "a [ControllerTracking]: initializing controller 1, serial number: tftouchplus_left\n"
                 "b [ContrLedsStats 1]: Observed LED 2\n");
    std::vector<int> hits;
    std::vector<double> stamps;
    XrLogWatcher::Callbacks cb;
    cb.serial_of_hand = [](int h) { return std::string(h ? "tftouchplus_right" : "tftouchplus_left"); };
    cb.led_hit = [&](int h, double) { hits.push_back(h); };
    cb.frame_stamp = [&](double, double t) { stamps.push_back(t); };
    cb.log = [](const std::string& s) { printf("  | %s\n", s.c_str()); };
    XrLogWatcher w(dir, cb);
    double t = 100;
    w.Poll(t);
    CHECKF(hits.empty(), "old LED lines counted (%zu)", hits.size());
    Append(log1, "c [ContrLedsStats 1]: Observed LED 4\n[ContrLedsStats 0]: Observed LED 1 (a Frame controller)\n");
    w.Poll(t += 0.1);
    CHECKF(hits.size() == 1 && hits[0] == 0, "tracker 1 -> left: %zu hits", hits.size());
    // A partial line waits for its newline.
    Append(log1, "[ControllerTracking 1]: Not having enough IMU data for controller frame, skipping processing it. Current timestamp: 5");
    w.Poll(t += 0.1);
    CHECK(stamps.empty());
    Append(log1, "0.25, got state timestamp: 49.9\n");
    w.Poll(t += 0.1);
    CHECKF(stamps.size() == 1 && std::fabs(stamps[0] - 50.25) < 1e-9, "%zu stamps", stamps.size());
    // Our right controller turns up as tracker 0 (re-announced, say): its LED lines count for right.
    Append(log1, "[ControllerTracking]: initializing controller 0, serial number: tftouchplus_right\n[ContrLedsStats 0]: x\n");
    w.Poll(t += 0.1);
    CHECKF(hits.size() == 2 && hits[1] == 1, "tracker 0 -> right: %zu hits", hits.size());
    // Two lines within 20 ms count once.
    Append(log1, "[ContrLedsStats 0]: y\n");
    w.Poll(t += 0.001);
    CHECK(hits.size() == 2);
    // XRService restarted: a newer log, read from its start, with a fresh mapping.
    Sleep(1.1);  // mtime resolution
    std::string log2 = sub + "/XRService-2.log";
    remove(log2.c_str());
    Append(log2, "[ControllerTracking]: initializing controller 0, serial number: tftouchplus_left\n[ContrLedsStats 0]: z\n");
    w.Poll(t += 6);
    CHECKF(hits.size() == 3 && hits[2] == 0, "after the switch: %zu hits", hits.size());
    CHECK(XrLogWatcher::FindNewestLog(dir) == log2);
}

static void TestWatcherCatchUp(const std::string& scratch) {
    // A long XRService log that was there before we looked (DEV-1 saw ~300 error lines/s): read a
    // few MB per Poll, not all in the first one. The mapping at its end still counts; its LED lines
    // don't.
    std::string dir = scratch + "/xrlogs_big";
    MKDIR(dir.c_str());
    std::string log = dir + "/XRService-big.log";
    remove(log.c_str());
    {
        std::ofstream f(log, std::ios::binary);
        std::string filler = "12:00:00.000 [ControllerTracking 0]: Couldn't find any neighbor for blob, skipping it\n";
        for (size_t n = 0; n < (20u << 20); n += filler.size()) f << filler;
        f << "[ControllerTracking]: initializing controller 2, serial number: tftouchplus_right\n[ContrLedsStats 2]: old\n";
    }
    std::vector<int> hits;
    XrLogWatcher::Callbacks cb;
    cb.serial_of_hand = [](int h) { return std::string(h ? "tftouchplus_right" : "tftouchplus_left"); };
    cb.led_hit = [&](int h, double) { hits.push_back(h); };
    cb.log = [](const std::string& s) { printf("  | %s\n", s.c_str()); };
    XrLogWatcher w(dir, cb);
    double t = 100;
    w.Poll(t);
    CHECKF(w.catching_up(), "20 MB read in one Poll");
    int polls = 1;
    while (w.catching_up() && polls < 20) w.Poll(t += 0.1), polls++;
    printf("catch-up: 20 MB in %d polls\n", polls);
    CHECKF(!w.catching_up() && polls >= 5, "%d polls", polls);
    CHECKF(hits.empty(), "old LED line counted");
    Append(log, "[ContrLedsStats 2]: new\n");
    w.Poll(t += 0.1);
    CHECKF(hits.size() == 1 && hits[0] == 1, "mapping from the end of the old log lost: %zu hits", hits.size());
}

static void TestOrientation() {
    // At rest with the controller's +Z up (fake_dongle's accel (0, 0, 1 g)): +Z must come out as world +Y.
    ImuOrientation o;
    float a[3] = {0, 0, 9.80665f}, g0[3] = {0, 0, 0};
    double t = 0;
    for (; t < 2; t += 0.002) o.Update(t, a, g0);
    V3 z = Rot(o.q(), V3{0, 0, 1});
    CHECKF(z.y > 0.9998, "body +Z -> (%f %f %f)", z.x, z.y, z.z);
    // Tilted 30° about body X: the filter follows the accelerometer.
    float at[3] = {0, float(9.80665 * std::sin(M_PI / 6)), float(9.80665 * std::cos(M_PI / 6))};
    for (double end = t + 10; t < end; t += 0.002) o.Update(t, at, g0);
    V3 up = Rot(Conj(o.q()), V3{0, 1, 0});
    CHECKF(std::fabs(up.y - at[1] / 9.80665) < 0.01 && std::fabs(up.z - at[2] / 9.80665) < 0.01, "tilt: up in body (%f %f %f)",
           up.x, up.y, up.z);
    // Yaw from the gyro: held level (+Y up, so -Z is a horizontal forward), 1 rad/s about up.
    ImuOrientation y;
    float ay[3] = {0, 9.80665f, 0};
    for (t = 0; t < 1; t += 0.002) y.Update(t, ay, g0);
    V3 f0 = Rot(y.q(), V3{0, 0, -1});
    float gz[3] = {0, 1.0f, 0};
    for (double end = t + 1.0; t < end - 1e-9; t += 0.002) y.Update(t, ay, gz);
    V3 f1 = Rot(y.q(), V3{0, 0, -1});
    double ang = std::atan2(Cross(f0, f1).y, Dot(f0, f1));
    CHECKF(std::fabs(std::fabs(ang) - 1.0) < 0.02, "yaw by gyro: %f rad", ang);
    // AlignYaw: forward along the headset's.
    y.AlignYaw(V3{1, 0, 0});
    V3 f2 = Rot(y.q(), V3{0, 0, -1});
    f2.y = 0;
    CHECKF(f2.x / Len(f2) > 0.9999, "aligned forward (%f %f %f)", f2.x, f2.y, f2.z);
}

static void WriteText(const std::string& path, const std::string& text) {
    std::ofstream f(path, std::ios::trunc | std::ios::binary);
    f << text;
}

static void TestFindHidraw(const std::string& scratch) {
    // A fake /sys/class/hidraw: a mouse, then our dongle as hidraw2 and hidraw10 (two interfaces
    // can't both match on a real Frame, but the lower number must win either way).
    std::string sys = scratch + "/sysfs";
    MKDIR(sys.c_str());
    const char* nodes[][2] = {{"hidraw0", "HID_ID=0003:0000046D:0000C52B"},
                              {"hidraw10", "HID_ID=0003:00001209:00000001"},
                              {"hidraw2", "HID_ID=0003:00001209:00000001"}};
    for (auto& n : nodes) {
        std::string d = sys + "/" + n[0];
        MKDIR(d.c_str());
        MKDIR((d + "/device").c_str());
        WriteText(d + "/device/uevent", std::string("DRIVER=hid-generic\n") + n[1] + "\nHID_NAME=x\n");
    }
    std::string why;
    std::string got = radio::FindHidraw(0x1209, 0x0001, &why, sys, "/dev");
    CHECKF(got == "/dev/hidraw2", "found '%s' (%s)", got.c_str(), why.c_str());
    got = radio::FindHidraw(0x1209, 0x0002, &why, sys, "/dev");
    CHECKF(got.empty() && why.find("046d:c52b") != std::string::npos, "no match: '%s' (%s)", got.c_str(), why.c_str());
}

static void TestIdentityJson() {
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = uint8_t(i * 17);
    std::map<uint64_t, int> paired{{0x1122334455667701ull, 0}, {0xAABBCCDDEEFF0011ull, 0xFF}}, hands{{0x1122334455667701ull, 1}};
    std::string j = radio::IdentityJson(0x12345678, key, paired, hands);
    uint32_t na = 0;
    uint8_t k2[16] = {};
    std::map<uint64_t, int> p2, h2;
    CHECKF(radio::ParseIdentityJson(j, &na, k2, &p2, &h2) && na == 0x12345678 && !memcmp(key, k2, 16) && p2 == paired &&
               h2 == hands,
           "round trip: %s", j.c_str());
}

struct Seen {
    std::mutex mu;
    HandState last[2] = {};
    std::atomic<uint64_t> n[2] = {{0}, {0}};
    double age_max = 0;
};

static void TestBackend3Dof(const std::string& transport, const std::string& state) {
    remove(state.c_str());
    Seen seen;
    RadioBackend::Options o;
    o.mode = RadioBackend::Mode::k3Dof;
    o.radio.transport = transport;
    o.radio.identity_path = state;
    o.radio.placeholder = true;
    o.log = [](const std::string& s) { printf("  | %s\n", s.c_str()); };
    o.status_every_s = 0;
    Pose head;
    head.p = {0.1, 1.7, 0.2};
    head.q = FromRotVec(V3{0, M_PI / 2, 0});  // facing world -X
    RadioBackend b(
        o,
        [&](int h, const HandState& s, double age) {
            std::lock_guard<std::mutex> lk(seen.mu);
            seen.last[h] = s;
            seen.n[h]++;
            seen.age_max = std::max(seen.age_max, age);
        },
        [&](Pose* p) {
            *p = head;
            return true;
        });
    b.Start();
    Sleep(1.5);
    b.RequestPair(1);
    double end = Now() + 6;
    while (Now() < end && seen.n[1] < 200) Sleep(0.05);
    uint64_t n0 = seen.n[1];
    Sleep(2.0);
    double hz = (seen.n[1] - n0) / 2.0;
    printf("3dof right: %.0f Hz\n", hz);
    CHECKF(hz > 150 && hz < 300, "3dof rate %.0f Hz (250 expected; the fake's stamps are uneven)", hz);
    {
        std::lock_guard<std::mutex> lk(seen.mu);
        const HandState& s = seen.last[1];
        CHECKF((s.flags & (kConnected | kOrientationValid | kOrientationTracked)) == (kConnected | kOrientationValid | kOrientationTracked) &&
                   !(s.flags & kPositionTracked),
               "flags %x", s.flags);
        Q q{s.rot[3], s.rot[0], s.rot[1], s.rot[2]};
        // The fake's gyro swings ±500 dps about body X (its accelerometer, inconsistently, stays at
        // +Z up), so the orientation really rolls by > 100°; what must hold is that it is a roll
        // about X only: body X stays horizontal and the quaternion unit length.
        V3 x = Rot(q, V3{1, 0, 0});
        double qn = std::sqrt(q.w * q.w + q.x * q.x + q.y * q.y + q.z * q.z);
        CHECKF(std::fabs(x.y) < 0.02 && std::fabs(qn - 1) < 1e-4, "body X (%f %f %f), |q| %f", x.x, x.y, x.z, qn);
        // Arm offset (0.18, -0.4, -0.3) in the headset's yaw frame (facing -X): right = -Z, forward = -X.
        V3 want{head.p.x - 0.30, head.p.y - 0.40, head.p.z - 0.18};
        CHECKF(std::fabs(s.pos[0] - want.x) < 1e-3 && std::fabs(s.pos[1] - want.y) < 1e-3 && std::fabs(s.pos[2] - want.z) < 1e-3,
               "pos (%f %f %f) want (%f %f %f)", s.pos[0], s.pos[1], s.pos[2], want.x, want.y, want.z);
        CHECKF(s.battery == 87, "battery %u", s.battery);
        printf("3dof max pose age %.1f ms\n", seen.age_max * 1e3);
        CHECKF(seen.age_max < 0.05, "pose age up to %.1f ms", seen.age_max * 1e3);
    }
    b.SendHaptic(1, 0.5f, 160, 0.1f);
    b.Stop();
}

static void TestBackendCamera(const std::string& transport, const std::string& state) {
    // State from the 3dof run: the right controller is paired and comes straight back.
    Seen seen;
    RadioBackend::Options o;
    o.mode = RadioBackend::Mode::kCamera;
    o.radio.transport = transport;
    o.radio.identity_path = state;
    o.radio.placeholder = true;
    o.radio.led_loop = true;
    o.xr_logs_dir = "-";
    o.config_text[1] = R"({"device_serial_number":"tftouchplus_right","model_number":"TouchFrame_TouchPlus_Right_Roy_EV1.5",
        "tracked_controller_role":"right_hand","imu":{"plus_x":[1,0,0],"plus_z":[0,0,1],"position":[0,0,0]},
        "head":{"plus_x":[1,0,0],"plus_z":[0,0,1],"position":[0,0,0]},
        "lighthouse_config":{"modelPoints":[[0,0,0],[0.01,0,0],[0,0.01,0],[0,0,0.01]],
        "modelNormals":[[0,0,1],[0,0,1],[0,0,1],[0,0,1]]}})";
    o.log = [](const std::string& s) { printf("  | %s\n", s.c_str()); };
    o.status_every_s = 0;
    RadioBackend b(o, [&](int h, const HandState& s, double) {
        std::lock_guard<std::mutex> lk(seen.mu);
        seen.last[h] = s;
        seen.n[h]++;
    });
    b.Start();
    double end = Now() + 8;
    while (Now() < end && seen.n[1] < 20) Sleep(0.05);
    uint64_t n0 = seen.n[1];
    Sleep(2.0);
    double hz = (seen.n[1] - n0) / 2.0;
    printf("camera mode without XRService: inputs at %.0f Hz\n", hz);
    CHECKF(hz > 50 && hz < 100, "input-only rate %.0f Hz (≤ 90 expected)", hz);
    {
        std::lock_guard<std::mutex> lk(seen.mu);
        CHECKF(seen.last[1].flags == kConnected && seen.last[1].battery == 87, "flags %x battery %u", seen.last[1].flags,
               seen.last[1].battery);
    }
    b.Stop();
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) {
        printf("usage: radio_backend_test SCRATCH_DIR [TRANSPORT STATE_FILE]\n");
        return 2;
    }
    TestParse();
    TestWatcher(argv[1]);
    TestWatcherCatchUp(argv[1]);
    TestOrientation();
    TestFindHidraw(argv[1]);
    TestIdentityJson();
    if (argc >= 4) {
        TestBackend3Dof(argv[2], argv[3]);
        TestBackendCamera(argv[2], argv[3]);
    }
    printf(g_fail ? "radio_backend_test: %d failure(s)\n" : "radio_backend_test passed\n", g_fail);
    return g_fail ? 1 : 0;
}
