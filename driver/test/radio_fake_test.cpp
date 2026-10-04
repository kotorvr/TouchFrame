// RadioSource end to end against tools/fake_dongle.py (served by driver/test/fake_dongle_server.py):
// link session, pairing through the driver, both hands streaming, time sync, IMU scale from cmd
// 0x32, haptics and LED commands accepted, adopt-on-restart, and recovery from a dongle reboot.
//   radio_fake_test TRANSPORT SCENARIO EXPECTED_DRIFT_PPM STATE_FILE
// SCENARIO: basic | reboot. driver/test/run.sh starts the server and runs both.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "radio_source.h"

using namespace tf;
using namespace tf::radio;

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

static double Now() { return HostNowNs() * 1e-9; }
static void Sleep(double s) { std::this_thread::sleep_for(std::chrono::milliseconds(int(s * 1000))); }

struct Probe {
    std::mutex mu;
    std::vector<std::string> log;
    std::atomic<int> connected[2] = {{0}, {0}}, connects[2] = {{0}, {0}}, disconnects[2] = {{0}, {0}};
    std::atomic<uint64_t> imu[2] = {{0}, {0}}, inputs[2] = {{0}, {0}};
    std::atomic<int> backwards{0};
    double last_t[2] = {0, 0};
    std::vector<double> latency;
    float accel[2][3] = {};
    HandState in[2] = {};

    bool Logged(const char* needle) {
        std::lock_guard<std::mutex> lk(mu);
        for (auto& l : log)
            if (l.find(needle) != std::string::npos) return true;
        return false;
    }
    std::vector<std::string> Errors() {
        std::lock_guard<std::mutex> lk(mu);
        std::vector<std::string> out;
        for (auto& l : log)
            if (l.find(" -> ") != std::string::npos && l.find("LED loop") == std::string::npos) out.push_back(l);
        return out;
    }
};

static RadioSource::Options MakeOptions(const std::string& transport, const std::string& state, Probe* p) {
    RadioSource::Options o;
    o.transport = transport;
    o.identity_path = state;
    o.placeholder = true;  // fake controllers speak the placeholder connected-link formats
    o.led_loop = true;
    o.led_min_sync_span_s = 1.0;
    o.led.dwell_s = 0.3;
    o.led.settle_s = 0.1;
    o.log = [p](const std::string& l) {
        printf("  | %s\n", l.c_str());
        std::lock_guard<std::mutex> lk(p->mu);
        p->log.push_back(l);
    };
    return o;
}

static RadioSource::Callbacks MakeCallbacks(Probe* p) {
    RadioSource::Callbacks cb;
    cb.imu = [p](int h, double t, const float a[3], const float g[3]) {
        double now = Now();
        std::lock_guard<std::mutex> lk(p->mu);
        if (t <= p->last_t[h]) p->backwards++;
        p->last_t[h] = t;
        p->imu[h]++;
        if (p->latency.size() < 20000) p->latency.push_back(now - t);
        memcpy(p->accel[h], a, sizeof(p->accel[h]));
    };
    cb.inputs = [p](int h, const HandState& s, double) {
        std::lock_guard<std::mutex> lk(p->mu);
        p->inputs[h]++;
        p->in[h] = s;
    };
    cb.connection = [p](int h, bool c) {
        p->connected[h] = c;
        (c ? p->connects[h] : p->disconnects[h])++;
    };
    return cb;
}

static bool WaitFor(double timeout, const std::function<bool()>& f) {
    double end = Now() + timeout;
    while (Now() < end) {
        if (f()) return true;
        Sleep(0.02);
    }
    return f();
}

static void Basic(const std::string& transport, double drift, const std::string& state) {
    remove(state.c_str());
    Probe p;
    {
        RadioSource rs(MakeOptions(transport, state, &p), MakeCallbacks(&p));
        rs.Start();
        CHECKF(WaitFor(5, [&] { return rs.link_status().hosting; }), "not hosting after 5 s");
        rs.RequestPair(1);
        CHECKF(WaitFor(5, [&] { return p.connected[1].load(); }), "right hand not connected after pairing");
        rs.RequestPair(0);
        CHECKF(WaitFor(5, [&] { return p.connected[0].load(); }), "left hand not connected after pairing");
        rs.SendHaptic(1, 0.5f, 200.0f, 3.0f);
        rs.SendHaptic(0, 1.0f, 0.0f, 0.0f);
        // Stream for a while, feeding the LED loop "no pose yet" observations like CvTouchSource would.
        uint64_t imu0[2] = {p.imu[0], p.imu[1]}, in0[2] = {p.inputs[0], p.inputs[1]};
        double t0 = Now();
        while (Now() - t0 < 4.0) {
            for (int h = 0; h < 2; h++) rs.ObservePose(h, Now(), false);
            Sleep(0.01);
        }
        double dt = Now() - t0;
        for (int h = 0; h < 2; h++) {
            double imu_hz = (p.imu[h] - imu0[h]) / dt, in_hz = (p.inputs[h] - in0[h]) / dt;
            printf("hand %d: imu %.0f Hz, inputs %.0f Hz\n", h, imu_hz, in_hz);
            CHECKF(imu_hz > 350 && imu_hz < 650, "hand %d IMU %.0f Hz (fake streams 500)", h, imu_hz);
            CHECKF(in_hz > 350 && in_hz < 650, "hand %d inputs %.0f Hz", h, in_hz);
            RadioSource::HandStatus hs = rs.hand_status(h);
            CHECKF(hs.scale.source == ImuScale::Controller, "hand %d IMU scale not from cmd 0x32", h);
            CHECKF(hs.led_state >= 0, "hand %d LED loop not running", h);
            std::lock_guard<std::mutex> lk(p.mu);
            // fake: accel (0, 0, 1024) counts = 1 g on z.
            CHECKF(std::fabs(p.accel[h][2] - 9.80665f) < 0.01f && std::fabs(p.accel[h][0]) < 1e-4f,
                   "hand %d accel (%f %f %f)", h, p.accel[h][0], p.accel[h][1], p.accel[h][2]);
            CHECKF(p.in[h].battery == 87 && (p.in[h].buttons & kBtnLowerTouch), "hand %d inputs: battery %u buttons %x",
                   h, p.in[h].battery, p.in[h].buttons);
        }
        CHECKF(p.backwards == 0, "%d IMU timestamps went backwards", p.backwards.load());
        {
            std::lock_guard<std::mutex> lk(p.mu);
            std::vector<double> l = p.latency;
            std::sort(l.begin(), l.end());
            double med = l.empty() ? -1 : l[l.size() / 2], lo = l.empty() ? -1 : l[l.size() / 20];
            printf("IMU stamp age: p5 %.2f ms, median %.2f ms\n", lo * 1e3, med * 1e3);
            CHECKF(lo >= 0 && med < 0.030, "IMU stamp age p5 %.2f ms, median %.2f ms", lo * 1e3, med * 1e3);
        }
        RadioSource::LinkStatus ls = rs.link_status();
        printf("sync: drift %+.2f ppm (fake %+.2f), best rtt %.0f us, band %.0f us, %.0f s span\n", ls.drift_ppm, drift,
               ls.best_rtt_us, ls.sync_band_us, ls.sync_span_s);
        CHECKF(std::fabs(ls.drift_ppm - drift) < 25, "drift %+.1f ppm vs %+.1f", ls.drift_ppm, drift);
        auto errs = p.Errors();
        for (auto& e : errs) printf("unexpected: %s\n", e.c_str());
        CHECKF(errs.empty(), "%zu command error(s)", errs.size());
        rs.Stop();
    }
    // The state file knows both hands.
    std::ifstream f(state);
    std::stringstream ss;
    ss << f.rdbuf();
    uint32_t na;
    uint8_t key[16];
    std::map<uint64_t, int> paired, hands;
    CHECKF(ParseIdentityJson(ss.str(), &na, key, &paired, &hands) && hands.size() == 2, "state file: %s",
           ss.str().c_str());

    // A driver restart adopts the running host: no pairing, controllers are back at once.
    Probe q;
    RadioSource rs2(MakeOptions(transport, state, &q), MakeCallbacks(&q));
    rs2.Start();
    CHECKF(WaitFor(5, [&] { return q.connected[0] && q.connected[1]; }), "restart: hands not back");
    CHECKF(q.Logged("already hosting as us"), "restart: did not adopt the running host");
    rs2.Stop();
}

static void Reboot(const std::string& transport, const std::string& state) {
    remove(state.c_str());
    Probe p;
    RadioSource rs(MakeOptions(transport, state, &p), MakeCallbacks(&p));
    rs.Start();
    CHECKF(WaitFor(5, [&] { return rs.link_status().hosting; }), "not hosting");
    rs.RequestPair(0);
    CHECKF(WaitFor(5, [&] { return p.connected[0].load(); }), "left not connected");
    // The server reboots the dongle a few seconds after host start: we must notice, restart the
    // session, and get the stored pairing back without help.
    CHECKF(WaitFor(12, [&] { return p.disconnects[0] > 0; }), "reboot not noticed");
    CHECKF(WaitFor(8, [&] { return p.connected[0].load(); }), "left not back after the reboot");
    CHECKF(p.Logged("clock restarted"), "reboot not detected via the clock");
    uint64_t n = p.imu[0];
    Sleep(1.0);
    CHECKF(p.imu[0] > n + 300, "IMU not flowing after the reboot");
    CHECKF(p.backwards == 0, "%d IMU timestamps went backwards across the reboot", p.backwards.load());
    rs.Stop();
}

int main(int argc, char** argv) {
    if (argc < 5) {
        printf("usage: radio_fake_test TRANSPORT basic|reboot DRIFT_PPM STATE_FILE\n");
        return 2;
    }
    std::string transport = argv[1], scenario = argv[2], state = argv[4];
    double drift = atof(argv[3]);
    printf("== %s over %s\n", scenario.c_str(), transport.c_str());
    if (scenario == "basic") Basic(transport, drift, state);
    else if (scenario == "reboot") Reboot(transport, state);
    else return 2;
    printf(g_fail ? "radio_fake_test %s: %d failure(s)\n" : "radio_fake_test %s passed\n", scenario.c_str(), g_fail);
    return g_fail ? 1 : 0;
}
