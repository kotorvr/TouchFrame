// LED phase closed loop: finds and then holds the Touch Plus LED pulse inside the Steam Frame's
// controller-camera exposures, without knowing the exposure schedule.
//
// Why: the controller can't hold its IR LEDs on. It strobes ≤ 75 µs pulses whose CENTRE sits at
// d (mod p) on the host's (= our dongle's) clock (docs/re/PERIPHERALS.md §0, §2). XRService only
// sees them if a pulse lands inside a short controller-frame exposure (~30 Hz). The exposure
// schedule goes from XRService to driver_cv and we have no tap on it (RE-3 blocked), so the
// driver searches for the phase and tracks it by watching what XRService gives back:
//   * pose validity on our pose queue (valid poses ⇒ LEDs are being matched), and
//   * optionally "[ContrLedsStats N]" lines from XRService's log for our tracker (LedHit()).
//
// Window (docs/re/FRAME-MODEL.md §3.3): mode 4 exposes 10 µs, so a 75 µs pulse lights it fully
// only within ±32.5 µs of the exposure (window_us = 65). The camera clock may drift against ours
// by tens of ppm (= µs/s): out of the window within a few probes. So the loop learns the drift
// while it still sees the LEDs, and re-phases continuously. The controller's period is whole µs:
// P = 33333.3 slips 0.33 µs/frame, and P/16 = 2083.3 slips 0.33 µs per PULSE (5 µs/frame), so
// the schedule is re-sent (anchored mid-interval) often enough to keep that smear ≤ max_smear_us.
//
// The loop works on the host clock (CLOCK_MONOTONIC_RAW, the camera timestamps' clock). The radio
// side turns a Schedule into a CMD_LED in dongle time with the time sync (LedCommandFor), which
// takes the dongle crystal's drift out. What remains, camera clock vs MONOTONIC_RAW, is rate_.
//
// States (P = frame period, k = coarse_divisor, a power of two):
//   SEARCH  strobe at P/k so each probe covers k phases of the frame at once, at phases in a
//           golden-ratio order across P/k: with no drift it covers P/k in steps ≤ step_us within
//           ~P/(k·step_us) probes, and unlike a linear sweep it can't crawl along with a drift. A
//           probe "hits" when its score (valid-pose fraction after a settle time, or 1 with an
//           LED-stats hit) ≥ hit_threshold. With a phase guess (a seed, the other hand, the last
//           connection, or a TRACK just lost) it first probes at P around it (±seed_span_us,
//           nearest first).
//   TRACK   centre and sentinel probes at centre ± window/4, inside the window, so the LEDs stay
//           seen while probing. A sentinel miss moves the centre away from that side (doubling the
//           step while misses keep coming from the same side) and feeds the drift-rate estimate.
//           lost_misses misses in a row → SEARCH. A sweep hit tracks "coarse" (still at P/k, k
//           pulses per frame) for coarse_track_s to learn the drift, then LOCATEs.
//   LOCATE  binary search for which of the k phases is the frame's: double the period each level
//           (log2 k levels, ≤ 2 probes each) until it is P, then TRACK at P. Both halves missing
//           → back to coarse TRACK.
// A probe ends after dwell_s, or decide_s after settling when the score is already clear, so the
// drift per probe stays small. A probe with no pose observations at all (XRService not tracking us, headset off the head) is
// repeated, not scored: the loop pauses rather than sweeping blind.
//
// Seeding (FRAME-MODEL §4): XRService logs some controller-frame timestamps ("Trying to track
// first LED frame with timestamp", "Not having enough IMU data for controller frame … Current
// timestamp"). Seed() turns one into a phase guess, and two seeds ≥ 10 s apart give the camera
// period, i.e. the drift, before any tracking. After a seeded search fails the loop ignores seeds
// until a blind sweep's worth of probes has run. Which exposure point the timestamp marks is
// UNKNOWN: seed_offset_us() reports the found centre minus the seed so a hardware day can pin
// Options::seed_offset_us.
//
// Pure logic (time is passed in); unit-tested against a camera + tracker model in
// driver/test/radio_unit_test.cpp. Not thread-safe.
#pragma once
#include <cstdint>

#include "radio_link.h"
#include "time_sync.h"

namespace tf {
namespace radio {

class LedPhaseLoop {
public:
    struct Options {
        double frame_period_us = 1e6 / 30.0;  // controller-frame period (XRService mode 4, 30 Hz)
        uint32_t on_us = 75;                  // pulse width; the controller clamps to 75
        double window_us = 65;                // phases that light the exposure fully (on − exposure)
        int coarse_divisor = 16;              // k, power of two; P/k must stay ≥ 800 µs
        double step_us = 40;                  // SEARCH step (< window, less the drift per probe)
        double track_step_us = 15;            // TRACK's first correction step
        double settle_s = 0.5;                // ignore observations this long after a change
        double dwell_s = 1.5;                 // probe length, settle included
        double decide_s = 0.3;                // ... or end it this long after settling once the
                                              // score is clear (≥ 0.9 hit; ≤ 0.1 miss, in TRACK)
        double hit_threshold = 0.5;
        double freq_gain = 0.4;               // drift-rate learning gain
        double max_drift_us_per_s = 100;      // ±100 ppm between camera and host clocks
        int lost_misses = 3;
        double coarse_track_s = 12;           // coarse TRACK this long before LOCATE
        double refresh_s = 0.5;               // re-send the schedule at least this often (re-anchors it)
        double min_refresh_s = 0.05;          // ... and at most this often
        double max_smear_us = 10;             // whole-µs period rounding allowed per refresh
        double seed_offset_us = 0;            // pulse centre − logged frame timestamp (UNKNOWN; HW day)
        double seed_span_us = 300;            // local search: ± this around a phase guess
        double seed_max_age_s = 5;            // ignore older frame timestamps
    };
    enum State { kSearch, kLocate, kTrack };
    // Pulse centres at anchor_s + n·period_us on the host clock.
    struct Schedule {
        double period_us = 0;
        double anchor_s = 0;
        uint32_t on_us = 0;
    };

    LedPhaseLoop() : LedPhaseLoop(Options()) {}
    explicit LedPhaseLoop(Options o);

    void Start(double now);
    // One pose block from XRService for this controller (t = when we read it).
    void Observe(double t, bool valid);
    // XRService logged an LED match for this controller.
    void LedHit(double t);
    // XRService logged a controller-frame timestamp (host clock seconds) that we read at `now`.
    void Seed(double now, double frame_t);
    // A frame phase found elsewhere (the other hand, or this hand's last connection): phase mod P
    // at `now`, drifting at rate µs/s. Used while searching.
    void SeedPhase(double now, double phase_us, double rate);
    // Advances the state machine. True when the schedule changed or is due for a refresh: send
    // schedule(now) to the controller.
    bool Update(double now);
    Schedule schedule(double now) const;

    State state() const { return state_; }
    bool coarse() const { return coarse_; }  // TRACK at P/k, before LOCATE
    bool fine_track() const { return state_ == kTrack && !coarse_; }
    static const char* StateName(State s);
    double centre_us() const { return phase_; }  // pulse-centre phase mod the track period (host clock)
    double centre_at(double now) const { return Wrap(phase_ + rate_ * (now - phase_t_), TrackPeriod()); }
    double width_us() const { return opt_.window_us; }
    double drift_us_per_s() const { return rate_; }
    bool seed_rate_known() const { return seed_rate_known_; }
    int sweeps() const { return sweeps_; }
    int probes() const { return probes_; }
    // The probe in flight (for logs): phase mod its period, and the period (host µs).
    double probe_phase_us() const { return probe_phase_; }
    double probe_period_us() const { return probe_period_; }
    const Options& options() const { return opt_; }
    // Found centre minus the latest seed's phase, in (−P/2, P/2]; 0 unless in TRACK at P with a seed.
    double seed_offset_us(double now) const;

private:
    enum Probe { kSweep, kLocal, kHalfA, kHalfB, kSentinelPlus, kSentinelMinus, kCentre };
    void Begin(double now, Probe kind, double phase, double period);
    void Finish(double now, double score);
    void FinishTrack(double now, bool hit);
    void EnterSearch(double now, double start_phase);
    void EnterTrack(double now, double centre, bool coarse);
    void EnterLocalSearch(double now, double centre);
    bool NextLocalProbe(double now);
    void Correct(double now, int dir, bool learn);
    double RefreshFor() const;  // re-send interval for the probe in flight
    double TrackPeriod() const { return coarse_ ? opt_.frame_period_us / opt_.coarse_divisor : opt_.frame_period_us; }
    double Wrap(double phase, double period) const;

    Options opt_;
    State state_ = kSearch;
    Probe probe_ = kSweep;
    double probe_phase_ = 0, probe_period_ = 0, probe_start_ = 0;
    int obs_ = 0, obs_valid_ = 0, led_hits_ = 0;
    bool changed_ = true;
    double last_emit_ = -1e9;
    bool coarse_ = false;
    // search
    double search_start_ = 0;
    int search_n_ = 0;
    double local_phase_ = 0, local_t_ = 0;  // local search centre (at P) at local_t_
    int local_idx_ = 0;
    // locate
    double base_ = 0, base_t_ = 0, level_period_ = 0;  // base_ = phase at time base_t_
    // track: centre phase at time phase_t_, drifting at rate_ µs/s
    double phase_ = 0, phase_t_ = 0, rate_ = 0, last_corr_t_ = -1e9, track_start_ = 0, step_ = 0;
    int last_dir_ = 0;
    bool plus_next_ = true;
    int misses_ = 0;
    int sweeps_ = 0, probes_ = 0;
    // seeding: the latest seed's phase at seed_t_; the first frame time of the drift baseline
    double seed_phase_ = 0, seed_t_ = 0, seed_base_frame_ = 0;
    int seed_blocked_sweep_ = -1;
    bool seed_rate_known_ = false;
};

// The CMD_LED (strobe) that puts the schedule's pulse centres on the dongle clock: the anchor
// through the time sync, the period scaled by the dongle's measured drift and rounded to µs. The
// rounding error grows from the anchor, so re-send it as often as Update() says.
Led LedCommandFor(const LedPhaseLoop::Schedule& s, const TimeSync& sync, uint8_t slot);

}  // namespace radio
}  // namespace tf
