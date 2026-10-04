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
// The loop works on the host clock (CLOCK_MONOTONIC_RAW, the camera timestamps' clock). The radio
// side turns a Schedule into a CMD_LED in dongle time with the time sync (LedCommandFor), which
// takes the dongle crystal's drift out. What remains, the camera clock vs MONOTONIC_RAW, is learnt
// as a phase drift rate in TRACK.
//
// States:
//   SEARCH  strobe at P/k (k = coarse_divisor, a power of two) so each probe covers k phases of
//           the frame at once; step the phase by step_us across P/k. A probe "hits" when its score
//           (valid-pose fraction after a settle time, or 1 with an LED-stats hit) ≥ hit_threshold.
//   LOCATE  binary search for which of the k phases hit: double the period each level (log2 k
//           levels, ≤ 2 probes each) until the period is P.
//   REFINE  at period P, walk down and up in refine_step_us until a probe misses: the plateau
//           [lo, hi] is where pulse and exposure overlap. Centre = (lo + hi) / 2.
//   TRACK   alternate sentinel probes at centre ± width/4, both inside the
//           plateau, so tracking is kept while probing. A sentinel miss moves the centre one
//           refine step away from that side and feeds the drift-rate estimate; then a centre
//           probe confirms. lost_misses misses in a row → SEARCH near the last centre.
// A probe with no pose observations at all (XRService not tracking us, headset off the head) is
// repeated, not scored: the loop pauses rather than sweeping blind.
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
        double frame_period_us = 1e6 / 30.0;  // controller-frame period (XRService: "Controller (30Hz ...)")
        uint32_t on_us = 75;                  // pulse width; the controller clamps to 75
        int coarse_divisor = 16;              // k, power of two; P/k must stay ≥ 800 µs
        double step_us = 60;                  // SEARCH step (≤ on_us + exposure, or pulses slip through)
        double refine_step_us = 20;           // REFINE / TRACK step
        double settle_s = 0.5;                // ignore observations this long after a change
        double dwell_s = 1.5;                 // probe length, settle included
        double hit_threshold = 0.5;
        double freq_gain = 0.2;               // drift-rate learning gain
        double max_drift_us_per_s = 100;      // ±100 ppm between camera and host clocks
        int lost_misses = 3;
        double refresh_s = 0.25;              // re-send the schedule this often (re-anchors it)
    };
    enum State { kSearch, kLocate, kRefine, kTrack };
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
    // Advances the state machine. True when the schedule changed or is due for a refresh: send
    // schedule(now) to the controller.
    bool Update(double now);
    Schedule schedule(double now) const;

    State state() const { return state_; }
    static const char* StateName(State s);
    double centre_us() const { return phase_; }  // pulse-centre phase mod frame period (host clock)
    double width_us() const { return width_; }
    double drift_us_per_s() const { return rate_; }
    int sweeps() const { return sweeps_; }
    int probes() const { return probes_; }
    // The probe in flight (for logs): phase mod its period, and the period (host µs).
    double probe_phase_us() const { return probe_phase_; }
    double probe_period_us() const { return probe_period_; }
    const Options& options() const { return opt_; }

private:
    enum Probe { kSweep, kHalfA, kHalfB, kRefineDown, kRefineUp, kSentinelPlus, kSentinelMinus, kCentre };
    void Begin(double now, Probe kind, double phase, double period);
    void Finish(double now, double score);
    void EnterSearch(double now, double start_phase);
    double Wrap(double phase, double period) const;

    Options opt_;
    State state_ = kSearch;
    Probe probe_ = kSweep;
    double probe_phase_ = 0, probe_period_ = 0, probe_start_ = 0;
    int obs_ = 0, obs_valid_ = 0, led_hits_ = 0;
    bool changed_ = true;
    double last_emit_ = -1e9;
    // search
    double search_start_ = 0, search_offset_ = 0;
    // locate
    double base_ = 0, base_t_ = 0, level_period_ = 0;  // base_ = phase at time base_t_
    // refine
    double lo_ = 0, hi_ = 0, refine_offset_ = 0;
    // track: centre phase at time phase_t_, drifting at rate_ µs/s
    double phase_ = 0, phase_t_ = 0, rate_ = 0, width_ = 0, last_corr_t_ = 0;
    bool plus_next_ = true;
    int misses_ = 0;
    int sweeps_ = 0, probes_ = 0;
};

// The CMD_LED (strobe) that puts the schedule's pulse centres on the dongle clock: the anchor
// through the time sync, the period scaled by the dongle's measured drift and rounded to µs. The
// rounding error grows from the anchor, so re-send it every refresh_s (Update() says when).
Led LedCommandFor(const LedPhaseLoop::Schedule& s, const TimeSync& sync, uint8_t slot);

}  // namespace radio
}  // namespace tf
