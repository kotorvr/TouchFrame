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
    opt_.step_us = std::max(1.0, opt_.step_us);
    opt_.refine_step_us = std::max(1.0, opt_.refine_step_us);
}

const char* LedPhaseLoop::StateName(State s) {
    switch (s) {
        case kSearch: return "search";
        case kLocate: return "locate";
        case kRefine: return "refine";
        case kTrack: return "track";
    }
    return "?";
}

double LedPhaseLoop::Wrap(double phase, double period) const {
    double r = std::fmod(phase, period);
    return r < 0 ? r + period : r;
}

void LedPhaseLoop::Start(double now) {
    rate_ = 0;
    sweeps_ = probes_ = 0;
    width_ = 0;
    EnterSearch(now, 0);
}

void LedPhaseLoop::EnterSearch(double now, double start_phase) {
    state_ = kSearch;
    search_start_ = start_phase;
    search_offset_ = 0;
    Begin(now, kSweep, start_phase, opt_.frame_period_us / opt_.coarse_divisor);
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

bool LedPhaseLoop::Update(double now) {
    if (now - probe_start_ >= opt_.dwell_s) {
        if (obs_ == 0 && led_hits_ == 0) {
            // Nothing to judge by (XRService isn't tracking us yet): hold this probe.
            probe_start_ = now;
        } else {
            double score = obs_ ? double(obs_valid_) / obs_ : 0.0;
            if (led_hits_ > 0) score = 1.0;
            Finish(now, score);
        }
    }
    if (!changed_ && now - last_emit_ < opt_.refresh_s) return false;
    changed_ = false;
    last_emit_ = now;
    return true;
}

LedPhaseLoop::Schedule LedPhaseLoop::schedule(double now) const {
    Schedule s;
    s.on_us = opt_.on_us;
    s.period_us = probe_period_ * (1.0 + rate_ * 1e-6);
    double phase = Wrap(probe_phase_ + rate_ * (now - probe_start_), probe_period_);
    double now_us = now * 1e6;
    s.anchor_s = (now_us + Wrap(phase - std::fmod(now_us, probe_period_), probe_period_)) * 1e-6;
    return s;
}

void LedPhaseLoop::Finish(double now, double score) {
    const double P = opt_.frame_period_us, rs = opt_.refine_step_us;
    const bool hit = score >= opt_.hit_threshold;
    switch (probe_) {
        case kSweep: {
            if (hit) {
                state_ = kLocate;
                base_ = probe_phase_ + rate_ * (now - probe_start_);
                base_t_ = now;
                level_period_ = probe_period_ * 2;
                if (probe_period_ >= P - 1e-6) {  // k == 1: nothing to locate
                    state_ = kRefine;
                    lo_ = hi_ = 0;
                    refine_offset_ = rs;
                    Begin(now, kRefineDown, base_ - rs, P);
                } else {
                    Begin(now, kHalfA, base_, level_period_);
                }
                return;
            }
            search_offset_ += opt_.step_us;
            if (search_offset_ >= probe_period_) {
                search_offset_ = 0;
                sweeps_++;
            }
            Begin(now, kSweep, search_start_ + search_offset_, probe_period_);
            return;
        }
        case kHalfA:
        case kHalfB: {
            base_ += rate_ * (now - base_t_);  // keep the base moving with the learnt drift
            base_t_ = now;
            if (!hit) {
                if (probe_ == kHalfA) Begin(now, kHalfB, base_ + level_period_ / 2, level_period_);
                else EnterSearch(now, base_ - 3 * opt_.step_us);  // false positive: look again nearby
                return;
            }
            if (probe_ == kHalfB) base_ += level_period_ / 2;
            if (level_period_ >= P - 1e-6) {
                state_ = kRefine;
                base_ = Wrap(base_, P);
                lo_ = hi_ = 0;
                refine_offset_ = rs;
                Begin(now, kRefineDown, base_ - rs, P);
            } else {
                level_period_ *= 2;
                Begin(now, kHalfA, base_, level_period_);
            }
            return;
        }
        case kRefineDown:
        case kRefineUp: {
            base_ += rate_ * (now - base_t_);
            base_t_ = now;
            // A plateau wider than a coarse slot means something odd; stop walking there.
            const double cap = P / opt_.coarse_divisor / 2;
            if (hit && refine_offset_ < cap) {
                if (probe_ == kRefineDown) lo_ = -refine_offset_;
                else hi_ = refine_offset_;
                refine_offset_ += rs;
                Begin(now, probe_, base_ + (probe_ == kRefineDown ? -refine_offset_ : refine_offset_), P);
                return;
            }
            if (probe_ == kRefineDown) {
                refine_offset_ = rs;
                Begin(now, kRefineUp, base_ + rs, P);
                return;
            }
            state_ = kTrack;
            width_ = hi_ - lo_ + rs;  // the plateau reaches part-way to each missed probe
            phase_ = Wrap(base_ + (lo_ + hi_) / 2, P);
            phase_t_ = last_corr_t_ = now;
            misses_ = 0;
            plus_next_ = true;
            Begin(now, kCentre, phase_, P);
            return;
        }
        case kSentinelPlus:
        case kSentinelMinus:
        case kCentre: {
            double cur = phase_ + rate_ * (now - phase_t_);
            phase_ = Wrap(cur, P);
            phase_t_ = now;
            if (hit) {
                misses_ = 0;
                // Sentinels a quarter-width either side: inside the plateau with margin even
                // though REFINE overestimates the width (drift during the walk, step rounding).
                double e = std::max(width_ / 4, rs / 2);
                Probe next = plus_next_ ? kSentinelPlus : kSentinelMinus;
                plus_next_ = !plus_next_;
                Begin(now, next, phase_ + (next == kSentinelPlus ? e : -e), P);
                return;
            }
            if (probe_ != kCentre) {
                // The plateau moved away from this sentinel: step the centre the other way and
                // learn the drift rate from how long that took.
                double c = probe_ == kSentinelPlus ? -rs : rs;
                phase_ = Wrap(phase_ + c, P);
                double dt = now - last_corr_t_;
                if (dt > 0.1) {
                    rate_ += opt_.freq_gain * c / dt;
                    rate_ = std::max(-opt_.max_drift_us_per_s, std::min(opt_.max_drift_us_per_s, rate_));
                }
                last_corr_t_ = now;
                misses_ = 1;
                Begin(now, kCentre, phase_, P);
                return;
            }
            if (++misses_ >= opt_.lost_misses) {
                EnterSearch(now, phase_ - 3 * opt_.step_us);
                return;
            }
            Begin(now, kCentre, phase_, P);
            return;
        }
    }
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
