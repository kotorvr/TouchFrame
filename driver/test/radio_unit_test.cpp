// Host unit tests for the radio backend's portable parts: COBS/HID framing, time sync, IMU and
// input decoding, haptics scheduling and the LED phase closed loop (against a camera + tracker
// model). No SteamVR, no dongle. Build/run: driver/test/run.sh
#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "led_phase.h"
#include "radio_decode.h"
#include "radio_link.h"
#include "time_sync.h"

using namespace tf;
using namespace tf::radio;

static int g_fail = 0;
static bool g_trace = false;  // phase_dbg: print every probe
#define CHECK(c)                                                         \
    do {                                                                 \
        if (!(c)) {                                                      \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);          \
            g_fail++;                                                    \
        }                                                                \
    } while (0)
#define CHECKF(c, ...)                                                   \
    do {                                                                 \
        if (!(c)) {                                                      \
            printf("FAIL %s:%d: %s: ", __FILE__, __LINE__, #c);          \
            printf(__VA_ARGS__);                                         \
            printf("\n");                                                \
            g_fail++;                                                    \
        }                                                                \
    } while (0)

// ------------------------------------------------------------------------------- framing

static void TestCobsAndHid() {
    std::mt19937 rng(7);
    std::vector<std::vector<uint8_t>> frames;
    for (int len : {1, 2, 10, 253, 254, 255, 256, 299}) {
        for (int zeros : {0, 1, 3}) {
            std::vector<uint8_t> f(len);
            for (auto& b : f) b = uint8_t(1 + rng() % 255);
            for (int z = 0; z < zeros && len > 1; z++) f[rng() % len] = 0;
            f[0] = 0x8C;  // a type byte is never 0
            frames.push_back(f);
        }
    }
    std::vector<uint8_t> stream;
    for (auto& f : frames) CobsEncode(f.data(), f.size(), &stream);
    for (size_t i = 0; i + 1 < stream.size(); i++) {
        // the only zeros are frame ends
        if (stream[i] == 0) CHECK(i + 1 < stream.size());
    }
    // Through HID reports, fed back in odd-sized chunks.
    std::vector<uint8_t> reports;
    HidPack(stream.data(), stream.size(), &reports);
    CHECK(reports.size() % kHidReport == 0);
    std::vector<uint8_t> back;
    for (size_t off = 0; off < reports.size(); off += kHidReport) {
        const uint8_t* p;
        size_t n;
        CHECK(HidUnpack(reports.data() + off, kHidReport, &p, &n));
        back.insert(back.end(), p, p + n);
    }
    CHECK(back == stream);
    uint8_t bad[64] = {64};
    const uint8_t* p;
    size_t n;
    CHECK(!HidUnpack(bad, 64, &p, &n));
    bad[0] = 0;  // keepalive
    CHECK(HidUnpack(bad, 64, &p, &n) && n == 0);

    FrameDecoder dec;
    size_t got = 0;
    bool same = true;
    for (size_t off = 0; off < back.size(); off += 7) {
        size_t k = std::min<size_t>(7, back.size() - off);
        dec.Feed(back.data() + off, k, [&](const uint8_t* f, size_t fn) {
            if (got < frames.size()) same &= std::vector<uint8_t>(f, f + fn) == frames[got];
            got++;
        });
    }
    CHECK(got == frames.size() && same);
    CHECK(dec.bad_frames() == 0);
    // Garbage then a good frame: the garbage is dropped, the frame survives.
    uint8_t junk[] = {0x05, 0x01, 0x00};
    std::vector<uint8_t> one = EncodeCommand(CMD_HELLO, "\x07", 1);
    got = 0;
    dec.Feed(junk, sizeof(junk), [&](const uint8_t*, size_t) { got++; });
    dec.Feed(one.data(), one.size(), [&](const uint8_t* f, size_t fn) {
        got += 10;
        CHECK(fn == 2 && f[0] == CMD_HELLO && f[1] == 7);
    });
    CHECK(got == 10 && dec.bad_frames() == 1);
}

// ------------------------------------------------------------------------------- time sync

struct DongleClock {
    double offset_us, ppm;
    uint64_t at(double host_us) const { return uint64_t(offset_us + host_us * (1 + ppm * 1e-6)); }
};

static void TestTimeSync() {
    for (double ppm : {-19.0, 0.0, 17.0}) {
        std::mt19937 rng(int(ppm * 10) + 100);
        std::uniform_real_distribution<double> usb(125, 1000);  // one-way USB latency, µs
        DongleClock dc{3.7e9, ppm};
        TimeSync ts;
        double host0 = 5e9;  // µs, arbitrary host clock origin
        double worst = 0;
        for (int i = 0; i < 400; i++) {  // 40 s at 10 Hz
            double send = host0 + i * 1e5;
            double rx = send + usb(rng);
            double tx = rx + 30;
            double recv = tx + usb(rng);
            ts.AddPing(int64_t(send * 1000), int64_t(recv * 1000), dc.at(rx), dc.at(tx));
            if (i > 250) {  // the LED loop waits for a 20 s span; IMU stamps tolerate more
                double t = send + 50000;
                double err = ts.ToHostNs(dc.at(t)) / 1000.0 - t;
                worst = std::max(worst, std::fabs(err));
                uint64_t d = ts.ToDongleUs(int64_t(t * 1000));
                CHECKF(std::fabs(double(int64_t(d - dc.at(t)))) < 200, "ToDongleUs off by %lld us",
                       (long long)int64_t(d - dc.at(t)));
            }
        }
        CHECKF(worst < 40, "ppm %.0f: worst mapping error %.1f us", ppm, worst);
        CHECKF(std::fabs(ts.DriftPpm() - ppm) < 1.5, "drift %.2f ppm vs %.0f", ts.DriftPpm(), ppm);
        printf("ok   timesync %+5.0f ppm: worst %.1f us, drift est %+.2f ppm, best rtt %.0f us, band %.1f us\n",
               ppm, worst, ts.DriftPpm(), ts.best_rtt_us(), ts.uncertainty_us());
    }
    // Dongle reboot: its clock restarts near 0. The filter must start over, not average it in.
    TimeSync ts;
    DongleClock a{9e9, 5}, b{1000, -3};
    for (int i = 0; i < 50; i++) {
        double s = 1e6 + i * 1e5;
        ts.AddPing(int64_t(s * 1000), int64_t((s + 400) * 1000), a.at(s + 200), a.at(s + 210));
    }
    for (int i = 50; i < 100; i++) {
        double s = 1e6 + i * 1e5;
        ts.AddPing(int64_t(s * 1000), int64_t((s + 400) * 1000), b.at(s + 200), b.at(s + 210));
    }
    double t = 1e6 + 99 * 1e5;
    CHECK(ts.resets() == 1);
    CHECKF(std::fabs(ts.ToHostNs(b.at(t)) / 1000.0 - t) < 300, "after reset: %.0f us off",
           ts.ToHostNs(b.at(t)) / 1000.0 - t);
}

// ------------------------------------------------------------------------------- decoding

static void TestDecode() {
    uint8_t cfg[16];
    uint16_t h[4] = {32000, 4000, 500, 500};
    float f[2] = {1.0f / 1024, 1.0f / 8.192f};
    memcpy(cfg, h, 8);
    memcpy(cfg + 8, f, 8);
    ImuScale s;
    CHECK(ParseImuConfig(cfg, 16, &s) && s.source == ImuScale::Controller && s.accel_hz == 500);
    CHECK(!ParseImuConfig(cfg, 12, &s));
    ImuEvt e{};
    e.bits = 16, e.accel_fs_g = 32, e.gyro_fs_dps = 4000;
    ImuScale es;
    CHECK(ScaleFromImuEvent(e, &es) && std::fabs(es.g_per_lsb - 1.0f / 1024) < 1e-9 &&
          std::fabs(es.dps_per_lsb - 1.0f / 8.192f) < 1e-7);

    // 1024 counts = 1 g; 8192 counts = 1000 dps.
    Rectifier id;
    int32_t ra[3] = {0, 1024, -2048}, rg[3] = {8192, 0, 0};
    float acc[3], gyr[3];
    ImuToSI(s, id, ra, rg, acc, gyr);
    CHECK(std::fabs(acc[1] - 9.80665f) < 1e-4 && std::fabs(acc[2] + 2 * 9.80665f) < 1e-4);
    CHECK(std::fabs(gyr[0] - 1000 * M_PI / 180) < 1e-3);

    // A Meta calibration: model y = -raw z, model z = raw y, with an accel offset.
    std::string cal =
        "[{\"TrackedObject\":{\"AccCalibration\":[1,0,0, 0,0,-1, 0,1,0, 0.1,0.2,0.3],"
        "\"GyroCalibration\":[1,0,0, 0,0,-1, 0,1,0, 0,0,0]}},"
        " {\"TrackedObject\":{\"AccCalibration\":[1,0,0, 0,0,-1, 0,1,0, 0.3,0.2,0.1],"
        "\"GyroCalibration\":[1,0,0, 0,0,-1, 0,1,0, 0,0,0]}}]";
    Rectifier r;
    std::string err;
    CHECK(ParseMetaCalibration(cal, &r, &err) && r.units == 2);
    ImuToSI(s, r, ra, rg, acc, gyr);
    // si = (0, g, -2g) - (0.2, 0.2, 0.2) -> model = (si.x, -si.z, si.y)
    double g = 9.80665;
    CHECKF(std::fabs(acc[0] - (0 - 0.2)) < 1e-4 && std::fabs(acc[1] - (2 * g + 0.2)) < 1e-4 &&
               std::fabs(acc[2] - (g - 0.2)) < 1e-4,
           "acc %f %f %f", acc[0], acc[1], acc[2]);
    CHECK(!ParseMetaCalibration("{\"x\":1}", &r, &err));

    InputEvt in{};
    in.buttons = 0x0B;  // A/X, B/Y, system
    in.touch = 0x011 | 0x020;  // touch A/X + touch trigger + prox A/X
    in.stick[0] = 32767, in.stick[1] = -32768;
    in.trigger = 4095, in.grip = 0x7ff;
    in.battery_pct = 87;
    HandState hs = MapInputs(in);
    CHECK(hs.buttons == (kBtnLowerClick | kBtnUpperClick | kBtnSystemClick | kBtnLowerTouch | kBtnTriggerTouch));
    CHECK(hs.stick_x == 1.0f && hs.stick_y == -1.0f && hs.trigger == 1.0f && std::fabs(hs.grip - 0.5f) < 0.001f);
    CHECK(hs.battery == 87);
    in.battery_pct = 0xFF;
    CHECK(MapInputs(in).battery == 255);

    HapticScheduler hap;
    Haptic c = hap.Request(10.0, 0.5f, 1000.0f, 5.0f);
    CHECK(c.mode == HAPTIC_SIMPLE && c.amplitude == 128 && c.freq_hz == 561 && c.duration_ms == 5000);
    Haptic r2;
    CHECK(!hap.Poll(11.0, &r2));
    CHECK(hap.Poll(11.6, &r2) && r2.mode == HAPTIC_SIMPLE && r2.duration_ms == 3400);
    CHECK(hap.Poll(13.2, &r2) && r2.duration_ms == 1800);
    CHECK(!hap.Poll(14.8, &r2));  // < 2 s left at the last send: the dongle stops it
    CHECK(!hap.Poll(15.1, &r2) && !hap.active());
    c = hap.Request(20.0, 1.0f, 0.0f, 0.0f);
    CHECK(c.freq_hz == HapticScheduler::kDefaultHz && c.duration_ms == 20 && c.amplitude == 255);
    c = hap.Request(20.01, 0.0f, 100.0f, 1.0f);
    CHECK(c.mode == HAPTIC_STOP && !hap.active());
}

// ------------------------------------------------------------------------------- LED phase loop

// Camera + tracker model. Controller frames expose for `exp_us` around theta + n·P_true on the host
// clock (P_true drifts `cam_ppm` from nominal). The controller strobes per the last CMD_LED on the
// dongle clock (which drifts `dongle_ppm`). A frame "sees" the LEDs if a pulse overlaps its
// exposure. XRService-ish tracker: bootstraps after 3 consecutive seen frames, coasts on IMU for
// `hold_s` after the last seen frame, then loses the pose.
struct PhaseSim {
    double P = 1e6 / 30, cam_ppm = 0, theta_us = 12345, exp_us = 40, hold_s = 0.3;
    double dongle_ppm = 0, dongle_off_us = 2.5e9;
    bool log_hits = false;  // also report LED-stats hits (one per seen frame, 1 in 10 logged)
    uint32_t seed = 1;

    struct Result {
        double first_track_s = -1, valid_frac_tail = 0, centre_err_us = 1e9;
        int state_at_end = 0, sweeps = 0;
        double drift_est = 0;
    };

    Result Run(LedPhaseLoop::Options lo, double seconds, double tail_s) {
        std::mt19937 rng(seed);
        std::uniform_real_distribution<double> usb(125, 1000);
        DongleClock dc{dongle_off_us, dongle_ppm};
        TimeSync ts;
        LedPhaseLoop loop(lo);
        const double t0 = 1000.0;  // host seconds
        double P_true = P * (1 + cam_ppm * 1e-6);
        Led cmd{};
        bool have_cmd = false;
        int consec = 0;
        double last_seen = -1e9;
        bool tracking = false;
        long n_frame = long(std::ceil((t0 * 1e6 - theta_us) / P_true));
        double next_ping = t0, next_pose = t0;
        long tail_obs = 0, tail_valid = 0;
        int hitlog = 0;
        Result res;
        // Prime the time sync for 25 s: RadioSource starts the loop once the pings span 20 s.
        for (double t = t0 - 25; t < t0; t += 0.1) {
            double s = t * 1e6, rx = s + usb(rng), tx = rx + 30, rv = tx + usb(rng);
            ts.AddPing(int64_t(s * 1000), int64_t(rv * 1000), dc.at(rx), dc.at(tx));
        }
        loop.Start(t0);
        for (double t = t0; t < t0 + seconds; t += 0.001) {
            if (t >= next_ping) {
                next_ping += 0.1;
                double s = t * 1e6, rx = s + usb(rng), tx = rx + 30, rv = tx + usb(rng);
                ts.AddPing(int64_t(s * 1000), int64_t(rv * 1000), dc.at(rx), dc.at(tx));
            }
            int probes_before = loop.probes();
            if (loop.Update(t)) {
                if (g_trace && loop.probes() != probes_before) {
                    double truth = std::fmod(theta_us + std::ceil((t * 1e6 - theta_us) / P_true) * P_true, P);
                    printf("%7.1f %-6s probe %9.1f / %8.1f  truth %8.1f  width %.0f drift %+.2f track %d\n", t - t0,
                           LedPhaseLoop::StateName(loop.state()), loop.probe_phase_us(), loop.probe_period_us(),
                           std::fmod(truth, loop.probe_period_us()), loop.width_us(), loop.drift_us_per_s(), int(tracking));
                }
                cmd = LedCommandFor(loop.schedule(t), ts, 0);
                have_cmd = true;
            }
            // camera frames due by t
            for (;;) {
                double E = theta_us + n_frame * P_true;  // host µs
                if (E > t * 1e6) break;
                n_frame++;
                bool seen = false;
                if (have_cmd) {
                    double dE = double(dc.at(E));
                    double k = std::round((dE - cmd.phase_us) / cmd.period_us);
                    double centre = cmd.phase_us + k * cmd.period_us;
                    double off_host = std::fabs(centre - dE) / (1 + dongle_ppm * 1e-6);
                    seen = off_host <= (exp_us + std::min<uint32_t>(cmd.on_us, 75)) / 2;
                }
                if (seen) {
                    consec++;
                    last_seen = E * 1e-6;
                    if (consec >= 3) tracking = true;
                    if (log_hits && tracking && ++hitlog % 10 == 0) loop.LedHit(E * 1e-6 + 0.01);
                } else {
                    consec = 0;
                }
            }
            if (tracking && t - last_seen > hold_s) tracking = false;
            if (t >= next_pose) {
                next_pose += 1.0 / 240;
                loop.Observe(t, tracking);
                if (t > t0 + seconds - tail_s) tail_obs++, tail_valid += tracking;
            }
            if (res.first_track_s < 0 && loop.state() == LedPhaseLoop::kTrack) res.first_track_s = t - t0;
        }
        double tend = t0 + seconds;
        res.valid_frac_tail = tail_obs ? double(tail_valid) / tail_obs : 0;
        res.state_at_end = loop.state();
        res.sweeps = loop.sweeps();
        res.drift_est = loop.drift_us_per_s();
        // Where the loop thinks the centre is vs the true exposure centre, both mod P at tend.
        LedPhaseLoop::Schedule s = loop.schedule(tend);
        double truth = std::fmod(theta_us + std::ceil((s.anchor_s * 1e6 - theta_us) / P_true) * P_true, P);
        double est = std::fmod(s.anchor_s * 1e6, P);
        double d = std::fmod(est - truth + 1.5 * P, P) - P / 2;
        res.centre_err_us = std::fabs(d);
        return res;
    }
};

static void TestPhaseLoop() {
    struct Case {
        const char* name;
        double exp_us, cam_ppm, dongle_ppm, theta;
        bool log_hits;
    } cases[] = {
        {"short exposure, still clocks", 40, 0, 0, 12345, false},
        {"short exposure, dongle +18 ppm", 40, 0, 18, 30111, false},
        {"camera +3 ppm, dongle -15 ppm", 40, 3, -15, 777, false},
        {"long exposure 600 us", 600, 0, 10, 20000, false},
        {"camera -6 ppm, LED-stats hits", 40, -6, 5, 16000, true},
    };
    for (auto& c : cases) {
        PhaseSim sim;
        sim.exp_us = c.exp_us, sim.cam_ppm = c.cam_ppm, sim.dongle_ppm = c.dongle_ppm, sim.theta_us = c.theta;
        sim.log_hits = c.log_hits;
        LedPhaseLoop::Options o;
        PhaseSim::Result r = sim.Run(o, 420, 120);
        printf("     phase loop [%s]: track at %.0f s, sweeps %d, tail valid %.3f, centre err %.0f us, drift est %+.2f us/s, state %s\n",
               c.name, r.first_track_s, r.sweeps, r.valid_frac_tail, r.centre_err_us, r.drift_est,
               LedPhaseLoop::StateName(LedPhaseLoop::State(r.state_at_end)));
        CHECKF(r.first_track_s > 0 && r.first_track_s < 180, "[%s] reached TRACK at %.0f s", c.name, r.first_track_s);
        CHECKF(r.valid_frac_tail > 0.95, "[%s] tail valid fraction %.3f", c.name, r.valid_frac_tail);
        CHECKF(r.state_at_end == LedPhaseLoop::kTrack, "[%s] ended in %d", c.name, r.state_at_end);
        CHECKF(r.centre_err_us < (c.exp_us + 75) / 2, "[%s] centre error %.0f us", c.name, r.centre_err_us);
    }
    // The command the dongle gets: period ≥ 800 µs while searching, P (±drift) when tracking,
    // centre phase on the dongle clock.
    TimeSync ts;
    DongleClock dc{1e6, 0};
    for (int i = 0; i < 40; i++) {
        double s = 1e9 + i * 1e5;
        ts.AddPing(int64_t(s * 1000), int64_t((s + 200) * 1000), dc.at(s + 100), dc.at(s + 100));
    }
    LedPhaseLoop loop;
    loop.Start(1004.0);
    CHECK(loop.Update(1004.0));
    Led l = LedCommandFor(loop.schedule(1004.0), ts, 3);
    CHECK(l.slot == 3 && l.mode == LED_STROBE && l.on_us == 75 && l.period_us >= 800 && l.period_us < 33334);
    CHECK(!loop.Update(1004.1));  // nothing new, refresh not due
    CHECK(loop.Update(1004.3));   // refresh
}

int main() {
    TestCobsAndHid();
    TestTimeSync();
    TestDecode();
    TestPhaseLoop();
    if (g_fail) {
        printf("radio_unit_test: %d failure(s)\n", g_fail);
        return 1;
    }
    printf("radio_unit_test passed\n");
    return 0;
}
