// Dongle microsecond clock -> host clock (CLOCK_MONOTONIC_RAW ns, XRService's clock), from
// CMD_TIME_PING / EVT_TIME round trips (radio-fw/src/link.h link_time_pong_t).
//
// Every ping bounds the mapping from both sides: the dongle received it after the host sent it
// (host(rx) ≥ send) and replied before the host got the reply (host(tx) ≤ recv). USB full speed
// polls every 1 ms, so one ping's bounds are ~1 ms apart. The fit:
//   * slope b (crystal drift, ±20 ppm) over the last 60 s: while the span is short (< 20 s), the
//     slope closest to 0 ppm that every ping's bounds allow (jitter makes any short-span estimate
//     noise); then the maximum-margin slope (widest band between the clouds);
//   * intercept: the middle of the band left between the two bound clouds over the last 15 s at
//     that slope. That uses the fastest ping in each direction rather than the fastest round
//     trip, and slow pings drop out by construction.
// The constant part of any OUT/IN latency asymmetry is an offset error the LED phase loop
// calibrates out; what matters there is that the mapping is stable.
//
// A dongle reset (its clock jumps back) or a sample that contradicts the fit by far restarts it.
// Not thread-safe: the owner serializes calls.
#pragma once
#include <cstdint>
#include <deque>

namespace tf {
namespace radio {

class TimeSync {
public:
    struct Options {
        double window_s = 60;           // slope: fitted over the pings of the last window_s
        double intercept_window_s = 15;  // intercept: band of the last few seconds at that slope
        double margin_span_s = 20;      // switch the slope to max-margin once pings span this
        double max_rtt_us = 20000;      // drop slower samples
        double max_drift_ppm = 300;     // a slope beyond this is ignored
        double reset_jump_us = 50000;   // a sample this far outside the fit restarts it
    };
    TimeSync() : TimeSync(Options()) {}
    explicit TimeSync(Options o) : opt_(o) {}

    // host_* in ns on the host clock; dongle_* in dongle µs. Returns the sample's RTT in µs
    // (negative if the sample was malformed and dropped).
    double AddPing(int64_t host_send_ns, int64_t host_recv_ns, uint64_t dongle_rx_us, uint64_t dongle_tx_us);

    bool Valid() const { return have_fit_; }
    int64_t ToHostNs(uint64_t dongle_us) const;
    uint64_t ToDongleUs(int64_t host_ns) const;
    // Dongle clock rate relative to the host, in ppm (positive: the dongle runs fast).
    double DriftPpm() const { return have_fit_ ? (1.0 / b_ - 1.0) * 1e6 : 0.0; }
    double best_rtt_us() const { return best_rtt_us_; }
    // Width of the feasible band at the fit (µs): how tightly the recent pings pin the mapping.
    double uncertainty_us() const { return gap_us_; }
    int samples() const { return int(win_.size()); }
    // Seconds of pings in the fit window: the LED loop waits for a long span (stable slope).
    double span_s() const { return win_.size() < 2 ? 0 : (win_.back().send_us - win_.front().send_us) * 1e-6; }
    int resets() const { return resets_; }
    void Reset();

private:
    struct Sample {
        double send_us, recv_us;  // host, µs since host_ref_ns_
        double rx_us, tx_us;      // dongle, µs since dongle_ref_us_
        double rtt_us;
    };
    void Fit();
    // Feasible intercept band for slope b over pings sent at or after since_us: [lo, hi].
    void Band(double b, double* lo, double* hi, double since_us = -1e300) const;
    // The slope in [x0, x1] leaving the widest band over the whole window.
    double MaxMarginSlope(double x0, double x1) const;

    Options opt_;
    bool have_ref_ = false, have_fit_ = false;
    int64_t host_ref_ns_ = 0;
    uint64_t dongle_ref_us_ = 0;
    std::deque<Sample> win_;
    double a_ = 0, b_ = 1;  // host_us = a + b * dongle_us (both relative to the refs)
    double best_rtt_us_ = 0, gap_us_ = 0;
    int resets_ = 0;
};

}  // namespace radio
}  // namespace tf
