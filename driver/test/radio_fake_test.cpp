// RadioSource end to end against tools/fake_dongle.py (served by driver/test/fake_dongle_server.py):
// link session, pairing through the driver, both hands streaming, time sync, IMU scale from cmd
// 0x32, haptics and LED commands accepted, adopt-on-restart, and recovery from a dongle reboot.
//   radio_fake_test TRANSPORT SCENARIO EXPECTED_DRIFT_PPM STATE_FILE
// hands / swap: handedness from cmd 1 (REVIEW-RE R11), hand collisions, disconnects by slot.
// SCENARIO: basic | reboot | hands | swap. driver/test/run.sh starts a server for each.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <fstream>
#include <map>
#include <memory>
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

    bool Logged(const std::string& needle) { return Count(needle) > 0; }
    int Count(const std::string& needle) {
        std::lock_guard<std::mutex> lk(mu);
        int n = 0;
        for (auto& l : log) n += l.find(needle) != std::string::npos;
        return n;
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
    rs.RequestPair(0, 0x1122334455667702ull);  // the fake's left controller (cmd 1 says so)
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

// fake_dongle_server.py --control: one command line, one reply line.
struct Control {
    std::unique_ptr<Transport> t;
    std::string buf;
    explicit Control(const std::string& port) {
        std::string err;
        t = MakeTransport("tcp:127.0.0.1:" + port, &err);
        if (!t || !t->Open(&err)) {
            printf("FAIL: control port %s: %s\n", port.c_str(), err.c_str());
            t.reset();
            g_fail++;
        }
    }
    std::string operator()(const std::string& cmd) {
        if (!t) return "err no control";
        std::string line = cmd + "\n";
        t->Write(reinterpret_cast<const uint8_t*>(line.data()), line.size());
        double end = Now() + 2;
        while (buf.find('\n') == std::string::npos && Now() < end) {
            uint8_t b[256];
            int n = t->Read(b, sizeof(b), 50);
            if (n < 0) break;
            buf.append(reinterpret_cast<char*>(b), size_t(std::max(n, 0)));
        }
        size_t nl = buf.find('\n');
        std::string r = nl == std::string::npos ? "err no reply" : buf.substr(0, nl);
        buf.erase(0, nl == std::string::npos ? buf.size() : nl + 1);
        return r;
    }
};

static std::string Hex(uint64_t v) {
    char b[17];
    snprintf(b, sizeof(b), "%016" PRIx64, v);
    return b;
}

static const uint64_t kC[6] = {0, 0x1122334455667701ull, 0x1122334455667702ull, 0x1122334455667703ull,
                               0x1122334455667704ull, 0x1122334455667705ull};

static void WriteState(const std::string& state, const std::map<uint64_t, int>& hands) {
    uint8_t key[16] = {};
    std::ofstream f(state, std::ios::trunc);
    f << IdentityJson(0x12345679, key, {}, hands);
}

static int HandInFile(const std::string& state, uint64_t dev) {
    std::ifstream f(state);
    std::stringstream ss;
    ss << f.rdbuf();
    uint32_t na;
    uint8_t key[16];
    std::map<uint64_t, int> paired, hands;
    if (!ParseIdentityJson(ss.str(), &na, key, &paired, &hands) || !hands.count(dev)) return -1;
    return hands[dev];
}

static RadioSource::Options RealOptions(const std::string& transport, const std::string& state, Probe* p) {
    RadioSource::Options o = MakeOptions(transport, state, p);
    o.placeholder = false;  // real formats: the dongle reads cmd 1 itself and sends the second EVT_PAIR(DONE)
    o.led_loop = false;
    return o;
}

static bool On(RadioSource& rs, int h, uint64_t dev) {
    RadioSource::HandStatus s = rs.hand_status(h);
    return s.connected && s.device_id == dev;
}

static std::string DoneLine(uint64_t dev) { return "pairing done (controller " + Hex(dev) + ")"; }

// Handedness from cmd 1 (REVIEW-RE R11), with real formats and the dongle's flash store. The server
// runs --hands left,right,right,unconf,unconf --stored 4 --control: C1 says left, C2 and C3 right,
// C4 and C5 "unconf", and C4 is already paired in the dongle's flash (hand unknown).
static void Hands(const std::string& transport, const std::string& state, const std::string& control_port) {
    const uint64_t kStale = 0xDEADBEEF00000001ull;  // forgotten long ago, still in the state file as right
    WriteState(state, {{kStale, 1}});
    Control ctl(control_port);
    Probe p;
    RadioSource rs(RealOptions(transport, state, &p), MakeCallbacks(&p));
    auto flash_hand = [&](uint64_t dev) {  // the dongle's stored link_hand, -1 if not paired there
        std::string r = ctl("pairs"), id = Hex(dev);
        size_t at = r.find(id);
        if (at == std::string::npos) return -1;
        size_t colon = r.find(':', at + id.size() + 1);
        return colon == std::string::npos ? -2 : atoi(r.c_str() + colon + 1);
    };
    rs.Start();
    CHECKF(WaitFor(5, [&] { return rs.link_status().hosting; }), "not hosting");

    // C4 has no hand anywhere: the first free hand, right first. The stale right entry (not paired
    // on the dongle) must not take it. C4 says "unconf": it stays right, and nothing is stored.
    CHECKF(WaitFor(5, [&] { return On(rs, 1, kC[4]); }), "C4 not on the right hand (did a forgotten controller block it?)");
    CHECKF(WaitFor(3, [&] { return p.Logged("says it is unconf"); }), "C4's cmd 1 not read");
    Sleep(0.5);
    CHECKF(On(rs, 1, kC[4]) && HandInFile(state, kC[4]) == 1, "unconf moved C4 (file hand %d)", HandInFile(state, kC[4]));
    CHECKF(flash_hand(kC[4]) == 0, "unconf stored hand %d", flash_hand(kC[4]));

    // C1 paired as right replaces C4. Its cmd 1 says left, so it moves there (our own read, and the
    // dongle's second EVT_PAIR(DONE), which carries the hand); the dongle stores left.
    rs.RequestPair(1, kC[1]);
    CHECKF(WaitFor(5, [&] { return On(rs, 0, kC[1]); }), "C1 not moved to the left hand after cmd 1");
    CHECKF(WaitFor(3, [&] { return p.Count(DoneLine(kC[1])) == 2; }), "%d EVT_PAIR(DONE) for C1, want 2",
           p.Count(DoneLine(kC[1])));
    CHECKF(flash_hand(kC[4]) == -1 && !rs.hand_status(1).connected, "C4 not replaced: pairs %s", ctl("pairs").c_str());
    CHECKF(HandInFile(state, kC[1]) == 0, "file: C1 hand %d", HandInFile(state, kC[1]));
    CHECKF(WaitFor(2, [&] { return flash_hand(kC[1]) == 1; }), "flash: C1 hand %d", flash_hand(kC[1]));

    // C2 (right) paired as right.
    rs.RequestPair(1, kC[2]);
    CHECKF(WaitFor(5, [&] { return On(rs, 1, kC[2]); }), "C2 not on the right hand");
    CHECKF(On(rs, 0, kC[1]), "C1 lost the left hand");

    // C3 paired as left (replacing C1), but it says right like C2: it borrows the free left hand.
    // Its second EVT_PAIR(DONE) says right: that updates its hand only, and must not replace C2.
    const int right_drops = p.disconnects[1];
    rs.RequestPair(0, kC[3]);
    CHECKF(WaitFor(5, [&] { return On(rs, 0, kC[3]); }), "C3 not on the left hand");
    CHECKF(WaitFor(3, [&] { return HandInFile(state, kC[3]) == 1; }), "file: C3 hand %d", HandInFile(state, kC[3]));
    CHECKF(WaitFor(3, [&] { return p.Count(DoneLine(kC[3])) == 2; }), "no second EVT_PAIR(DONE) for C3");
    Sleep(0.5);
    CHECKF(On(rs, 1, kC[2]) && p.disconnects[1] == right_drops && flash_hand(kC[2]) == 2,
           "C3's hand took the right hand from C2 (pairs %s)", ctl("pairs").c_str());
    CHECKF(flash_hand(kC[1]) == -1, "C1 not replaced on the left hand");

    // Disconnects go by slot: C3 (a right controller on the left hand) drops; left goes, not right.
    const int left_drops = p.disconnects[0];
    CHECKF(ctl("drop " + Hex(kC[3])).rfind("ok", 0) == 0, "drop C3");
    CHECKF(WaitFor(2, [&] { return p.disconnects[0] > left_drops; }), "left not disconnected when C3 dropped");
    CHECKF(On(rs, 1, kC[2]) && p.disconnects[1] == right_drops, "dropping C3 disconnected the right hand");
    CHECKF(WaitFor(3, [&] { return On(rs, 0, kC[3]); }), "C3 not back on the left hand");

    // C5 ("unconf") paired as left: no left controller is in the file, so nothing is replaced, but
    // C3 only borrowed the left hand: it gives way. Both hands are in use, so C3 waits.
    rs.RequestPair(0, kC[5]);
    CHECKF(WaitFor(5, [&] { return On(rs, 0, kC[5]); }), "C5 not on the left hand (C3 didn't give way?)");
    CHECKF(p.Logged("it waits for a free hand"), "C3 not waiting");
    Sleep(0.5);
    CHECKF(On(rs, 0, kC[5]) && On(rs, 1, kC[2]) && HandInFile(state, kC[5]) == 0, "after C5: file hand %d",
           HandInFile(state, kC[5]));
    CHECKF(flash_hand(kC[3]) == 2 && flash_hand(kC[5]) == 0, "flash: C3 %d C5 %d", flash_hand(kC[3]), flash_hand(kC[5]));
    CHECKF(p.Count(DoneLine(kC[5])) == 1, "unconf C5 got a second EVT_PAIR(DONE)");

    // C2 drops: the waiting C3 (a right controller) takes the right hand at once. C2 comes back to
    // both hands held by their own controllers, and waits.
    CHECKF(ctl("drop " + Hex(kC[2])).rfind("ok", 0) == 0, "drop C2");
    CHECKF(WaitFor(2, [&] { return On(rs, 1, kC[3]); }), "the waiting C3 didn't take the free right hand");
    CHECKF(WaitFor(2, [&] { return p.Count("it waits for a free hand") >= 2; }), "C2 not waiting after it came back");
    CHECKF(On(rs, 1, kC[3]) && On(rs, 0, kC[5]), "C2's return disturbed the hands");

    auto errs = p.Errors();
    for (auto& e : errs) printf("unexpected: %s\n", e.c_str());
    CHECKF(errs.empty(), "%zu command error(s)", errs.size());
    rs.Stop();
}

// Two stored controllers on each other's hand in the state file (as if paired without a hand and
// given right first): cmd 1 swaps them, and neither may stay stuck on the wrong hand. The server
// runs --hands left,right --stored 1,2.
static void Swap(const std::string& transport, const std::string& state) {
    WriteState(state, {{kC[1], 1}, {kC[2], 0}});
    Probe p;
    RadioSource rs(RealOptions(transport, state, &p), MakeCallbacks(&p));
    rs.Start();
    CHECKF(WaitFor(6, [&] { return On(rs, 0, kC[1]) && On(rs, 1, kC[2]); }),
           "swapped controllers stuck: left %016" PRIx64 ", right %016" PRIx64, rs.hand_status(0).device_id,
           rs.hand_status(1).device_id);
    Sleep(3.0);  // the pairings re-read (2.5 s after a connect) must agree
    CHECKF(On(rs, 0, kC[1]) && On(rs, 1, kC[2]), "hands changed after the pairings re-read");
    CHECKF(HandInFile(state, kC[1]) == 0 && HandInFile(state, kC[2]) == 1, "file: C1 %d C2 %d", HandInFile(state, kC[1]),
           HandInFile(state, kC[2]));
    rs.Stop();
}

int main(int argc, char** argv) {
    if (argc < 5) {
        printf("usage: radio_fake_test TRANSPORT basic|reboot|hands|swap DRIFT_PPM STATE_FILE [CONTROL_PORT]\n");
        return 2;
    }
    std::string transport = argv[1], scenario = argv[2], state = argv[4];
    double drift = atof(argv[3]);
    printf("== %s over %s\n", scenario.c_str(), transport.c_str());
    if (scenario == "basic") Basic(transport, drift, state);
    else if (scenario == "reboot") Reboot(transport, state);
    else if (scenario == "hands" && argc > 5) Hands(transport, state, argv[5]);
    else if (scenario == "swap") Swap(transport, state);
    else return 2;
    printf(g_fail ? "radio_fake_test %s: %d failure(s)\n" : "radio_fake_test %s passed\n", scenario.c_str(), g_fail);
    return g_fail ? 1 : 0;
}
