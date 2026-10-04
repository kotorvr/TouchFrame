#include "led_phase.h"

#include <algorithm>
#include <cmath>

namespace tf {
namespace radio {

LedPhaseLoop::LedPhaseLoop(Options o) : opt_(o) {
    if (opt_.coarse_divisor < 1) opt_.coarse_divisor = 1;
    // Keep k a power of two (LOCATE halves) and P/k above the controller's ~0.8 ms re-arm floor.
    int k = 1;
    while (k * 2 <= opt_.coarse_divisor && opt_.frame_period_us / (k * 2) >= 800) k *= 2;
    opt_.coarse_divisor = k;
    opt_.window_us = std::max(4.0, opt_.window_us);
    opt_.step_us = std::max(1.0, opt_.step_us);
    opt_.track_step_us = std::max(1.0, opt_.track_step_us);
}

const char* LedPhaseLoop::StateName(State s) {
    switch (s) {
        case kSearch: return "search";
        case kLocate: return "locate";
        case kTrack: return "track";
    }
    return "?";
}

double LedPhaseLoop::Wrap(double phase, double period) const {
    double r = std::fmod(phase, period);
    return r < 0 ? r + period : r;
}

void LedPhaseLoop::Start(double now) {
    if (!seed_rate_known_) rate_ = 0;
    sweeps_ = probes_ = 0;
    EnterSearch(now, 0);
}

void LedPhaseLoop::EnterSearch(double now, double start_phase) {
    state_ = kSearch;
    coarse_ = false;
    search_start_ = start_phase;
    search_n_ = 0;
    Begin(now, kSweep, start_phase, opt_.frame_period_us / opt_.coarse_divisor);
}

void LedPhaseLoop::EnterTrack(double now, double centre, bool coarse) {
    state_ = kTrack;
    coarse_ = coarse;
    phase_ = Wrap(centre, TrackPeriod());
    phase_t_ = track_start_ = now;
    last_corr_t_ = -1e9;
    last_dir_ = 0;
    step_ = opt_.track_step_us;
    misses_ = 0;
    plus_next_ = true;
    Begin(now, kCentre, phase_, TrackPeriod());
}

void LedPhaseLoop::EnterLocalSearch(double now, double centre) {
    local_phase_ = centre;
    local_t_ = now;
    local_idx_ = -1;
    NextLocalProbe(now);
}

bool LedPhaseLoop::NextLocalProbe(double now) {
    local_idx_++;
    int n = (local_idx_ + 1) / 2;  // 0, +1, -1, +2, -2, ...
    double off = (local_idx_ % 2 ? 1 : -1) * n * opt_.step_us;
    if (n * opt_.step_us > opt_.seed_span_us) return false;
    state_ = kSearch;
    coarse_ = false;
    Begin(now, kLocal, local_phase_ + rate_ * (now - local_t_) + off, opt_.frame_period_us);
    return true;
}

void LedPhaseLoop::Begin(double now, Probe kind, double phase, double period) {
    probe_ = kind;
    probe_period_ = period;
    probe_phase_ = Wrap(phase, period);
    probe_start_ = now;
    obs_ = obs_valid_ = led_hits_ = 0;
    changed_ = true;
    probes_++;
}

void LedPhaseLoop::Observe(double t, bool valid) {
    if (t < probe_start_ + opt_.settle_s) return;
    obs_++;
    if (valid) obs_valid_++;
}

void LedPhaseLoop::LedHit(double t) {
    if (t >= probe_start_ + opt_.settle_s) led_hits_++;
}

void LedPhaseLoop::Seed(double now, double frame_t) {
    if (frame_t <= 0 || now - frame_t > opt_.seed_max_age_s || frame_t - now > 1.0) return;
    const double P = opt_.frame_period_us;
    // The camera period from two frame times: whole frames apart, so it holds while the drift
    // over the baseline stays under P/2 (300 s at 50 ppm).
    double span = frame_t - seed_base_frame_;
    if (seed_base_frame_ <= 0 || span > 300 || span < 0) {
        seed_base_frame_ = frame_t;
    } else if (span >= 10) {
        double n = std::round(span * 1e6 / P);
        double r = (span * 1e6 / n - P) / P * 1e6;  // µs of phase per second
        if (std::fabs(r) <= opt_.max_drift_us_per_s) {
            // Before tracking it is all we know; while tracking the loop's own estimate is closer.
            if (state_ == kSearch || !seed_rate_known_) rate_ = r;
            seed_rate_known_ = true;
        }
    }
    // Frame times and our phases share the host clock: the phase is the time mod P.
    seed_phase_ = Wrap(std::fmod(frame_t * 1e6, P) + opt_.seed_offset_us + rate_ * (now - frame_t), P);
    seed_t_ = now;
    if (state_ == kSearch && probe_ == kSweep && sweeps_ != seed_blocked_sweep_)
        EnterLocalSearch(now, seed_phase_);  // blind so far: try around the seed first
}

void LedPhaseLoop::SeedPhase(double now, double phase_us, double rate) {
    // Not again until a sweep's worth of blind probes after a failed local search.
    if (state_ != kSearch || probe_ != kSweep || sweeps_ == seed_blocked_sweep_) return;
    rate_ = std::max(-opt_.max_drift_us_per_s, std::min(opt_.max_drift_us_per_s, rate));
    EnterLocalSearch(now, phase_us);
}

double LedPhaseLoop::seed_offset_us(double now) const {
    if (state_ != kTrack || coarse_ || seed_t_ <= 0) return 0;
    const double P = opt_.frame_period_us;
    double d = Wrap(phase_ + rate_ * (now - phase_t_) - (seed_phase_ + rate_ * (now - seed_t_)), P);
    return d > P / 2 ? d - P : d;
}

bool LedPhaseLoop::Update(double now) {
    bool due = now - probe_start_ >= opt_.dwell_s;
    if (!due && now - probe_start_ >= opt_.settle_s + opt_.decide_s && (obs_ >= 5 || led_hits_)) {
        double score = led_hits_ ? 1.0 : double(obs_valid_) / obs_;
        due = score >= 0.9 || (score <= 0.1 && state_ == kTrack);
    }
    if (due) {
        if (obs_ == 0 && led_hits_ == 0) {
            // Nothing to judge by (XRService isn't tracking us yet): hold this probe.
            probe_start_ = now;
        } else {
            double score = obs_ ? double(obs_valid_) / obs_ : 0.0;
            if (led_hits_ > 0) score = 1.0;
            Finish(now, score);
        }
    }
    if (!changed_ && now - last_emit_ < RefreshFor()) return false;
    changed_ = false;
    last_emit_ = now;
    return true;
}

double LedPhaseLoop::RefreshFor() const {
    double p = probe_period_ * (1.0 + rate_ * 1e-6);
    double smear_per_s = std::fabs(p - std::round(p)) * 1e6 / p;  // rounding error, µs per second
    if (smear_per_s * opt_.refresh_s <= opt_.max_smear_us) return opt_.refresh_s;
    return std::max(opt_.min_refresh_s, opt_.max_smear_us / smear_per_s);
}

LedPhaseLoop::Schedule LedPhaseLoop::schedule(double now) const {
    Schedule s;
    s.on_us = opt_.on_us;
    s.period_us = probe_period_ * (1.0 + rate_ * 1e-6);
    // Anchor on the pulse nearest the middle of the interval until the next re-send, so the
    // whole-µs rounding errs both ways.
    double mid = now + RefreshFor() / 2;
    double phase = Wrap(probe_phase_ + rate_ * (mid - probe_start_), probe_period_);
    double mid_us = mid * 1e6;
    double d = Wrap(phase - std::fmod(mid_us, probe_period_), probe_period_);
    if (d > probe_period_ / 2) d -= probe_period_;
    s.anchor_s = (mid_us + d) * 1e-6;
    return s;
}

void LedPhaseLoop::Finish(double now, double score) {
    const double P = opt_.frame_period_us;
    const bool hit = score >= opt_.hit_threshold;
    switch (probe_) {
        case kSweep: {
            if (hit) {
                // Track at P/k first: the LEDs stay seen while the drift is learnt.
                EnterTrack(now, probe_phase_ + rate_ * (now - probe_start_), probe_period_ < P - 1e-6);
                return;
            }
            search_start_ += rate_ * (now - probe_start_);  // move with the known drift
            // Golden-ratio order; a "sweep" is as many probes as a linear sweep would take.
            int per_sweep = std::max(1, int(std::ceil(probe_period_ / opt_.step_us)));
            if (++search_n_ % per_sweep == 0) sweeps_++;
            const double golden = 0.6180339887498949;
            double f = search_n_ * golden;
            Begin(now, kSweep, search_start_ + (f - std::floor(f)) * probe_period_, probe_period_);
            return;
        }
        case kLocal: {
            if (hit) {
                EnterTrack(now, probe_phase_ + rate_ * (now - probe_start_), false);
                return;
            }
            if (!NextLocalProbe(now)) {
                seed_blocked_sweep_ = sweeps_;  // no more seeded searches until a sweep's worth
                EnterSearch(now, local_phase_ + rate_ * (now - local_t_));
            }
            return;
        }
        case kHalfA:
        case kHalfB: {
            base_ += rate_ * (now - base_t_);  // keep the base moving with the learnt drift
            base_t_ = now;
            if (!hit) {
                if (probe_ == kHalfA) Begin(now, kHalfB, base_ + level_period_ / 2, level_period_);
                else EnterTrack(now, base_, true);  // lost it while locating: coarse track again
                return;
            }
            if (probe_ == kHalfB) base_ += level_period_ / 2;
            if (level_period_ >= P - 1e-6) {
                EnterTrack(now, base_, false);
            } else {
                level_period_ *= 2;
                Begin(now, kHalfA, base_, level_period_);
            }
            return;
        }
        case kSentinelPlus:
        case kSentinelMinus:
        case kCentre:
            FinishTrack(now, hit);
            return;
    }
}

// Moves the centre `dir` (±1) by the current step, doubling it while corrections keep coming
// from the same side, and (for sentinel misses) learns the drift from how often that happens.
void LedPhaseLoop::Correct(double now, int dir, bool learn) {
    const double recent = 4 * opt_.dwell_s;
    double dt = now - last_corr_t_;
    if (dir == last_dir_ && dt < recent) step_ = std::min(2 * step_, opt_.window_us);
    else step_ = opt_.track_step_us;
    double c = dir * step_;
    phase_ = Wrap(phase_ + c, TrackPeriod());
    if (learn && dt < 20) {
        rate_ += opt_.freq_gain * c / std::max(dt, opt_.dwell_s);
        rate_ = std::max(-opt_.max_drift_us_per_s, std::min(opt_.max_drift_us_per_s, rate_));
    }
    last_dir_ = dir;
    last_corr_t_ = now;
}

void LedPhaseLoop::FinishTrack(double now, bool hit) {
    const double T = TrackPeriod();
    phase_ = Wrap(phase_ + rate_ * (now - phase_t_), T);
    phase_t_ = now;
    if (hit) {
        misses_ = 0;
        if (coarse_ && now - track_start_ >= opt_.coarse_track_s) {
            // Drift learnt: find which of the k phases is the frame's.
            state_ = kLocate;
            base_ = phase_;
            base_t_ = now;
            level_period_ = T * 2;
            Begin(now, kHalfA, base_, level_period_);
            return;
        }
        // Sentinels a quarter-window either side, alternating: inside the window with margin.
        double e = opt_.window_us / 4;
        Probe next = plus_next_ ? kSentinelPlus : kSentinelMinus;
        plus_next_ = !plus_next_;
        Begin(now, next, phase_ + (next == kSentinelPlus ? e : -e), T);
        return;
    }
    if (probe_ != kCentre) {
        // The window moved away from this sentinel: step the centre the other way.
        Correct(now, probe_ == kSentinelPlus ? -1 : 1, true);
        misses_ = 1;
        Begin(now, kCentre, phase_, T);
        return;
    }
    if (++misses_ >= opt_.lost_misses) {
        if (coarse_) EnterSearch(now, phase_);
        else EnterLocalSearch(now, phase_);  // the frame phase is known: look near it first
        return;
    }
    // Centre missed too: keep going the way the last correction went (or try both sides).
    int dir = last_dir_ && now - last_corr_t_ < 4 * opt_.dwell_s ? last_dir_ : (misses_ % 2 ? 1 : -1);
    Correct(now, dir, false);
    Begin(now, kCentre, phase_, T);
}

Led LedCommandFor(const LedPhaseLoop::Schedule& s, const TimeSync& sync, uint8_t slot) {
    Led l{};
    l.slot = slot;
    l.mode = LED_STROBE;
    l.intensity = 255;
    l.on_us = s.on_us;
    double rate = 1.0 + sync.DriftPpm() * 1e-6;  // dongle µs per host µs
    uint32_t p = uint32_t(std::max(1L, std::lround(s.period_us * rate)));
    uint64_t anchor = sync.ToDongleUs(int64_t(std::llround(s.anchor_s * 1e9)));
    l.period_us = p;
    l.phase_us = int32_t(anchor % p);
    return l;
}

}  // namespace radio
}  // namespace tf
