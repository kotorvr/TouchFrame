#include "time_sync.h"

#include <algorithm>
#include <cmath>

namespace tf {
namespace radio {

void TimeSync::Reset() {
    have_ref_ = have_fit_ = false;
    win_.clear();
    a_ = 0, b_ = 1;
    best_rtt_us_ = gap_us_ = 0;
}

double TimeSync::AddPing(int64_t host_send_ns, int64_t host_recv_ns, uint64_t dongle_rx_us, uint64_t dongle_tx_us) {
    if (host_recv_ns < host_send_ns || dongle_tx_us < dongle_rx_us) return -1;
    double rtt = (host_recv_ns - host_send_ns) / 1000.0 - double(dongle_tx_us - dongle_rx_us);
    if (rtt < 0) rtt = 0;
    if (rtt > opt_.max_rtt_us) return rtt;
    if (!have_ref_) {
        have_ref_ = true;
        host_ref_ns_ = host_send_ns;
        dongle_ref_us_ = dongle_rx_us;
    }
    Sample s;
    s.send_us = (host_send_ns - host_ref_ns_) / 1000.0;
    s.recv_us = (host_recv_ns - host_ref_ns_) / 1000.0;
    s.rx_us = double(int64_t(dongle_rx_us - dongle_ref_us_));
    s.tx_us = s.rx_us + double(dongle_tx_us - dongle_rx_us);
    s.rtt_us = rtt;
    if (have_fit_ && (s.send_us - (a_ + b_ * s.rx_us) > opt_.reset_jump_us ||
                      (a_ + b_ * s.tx_us) - s.recv_us > opt_.reset_jump_us)) {
        // The dongle rebooted (its clock restarted) or a clock jumped: start over.
        Reset();
        resets_++;
        return AddPing(host_send_ns, host_recv_ns, dongle_rx_us, dongle_tx_us);
    }
    win_.push_back(s);
    while (win_.size() > 2 && win_.back().send_us - win_.front().send_us > opt_.window_s * 1e6) win_.pop_front();
    Fit();
    return rtt;
}

void TimeSync::Band(double b, double* lo, double* hi, double since_us) const {
    // Intercept at the window's first dongle stamp, so the products stay small.
    const double d0 = win_.front().rx_us;
    double l = -1e300, h = 1e300;
    for (const Sample& s : win_) {
        if (s.send_us < since_us) continue;
        l = std::max(l, s.send_us - b * (s.rx_us - d0));
        h = std::min(h, s.recv_us - b * (s.tx_us - d0));
    }
    *lo = l, *hi = h;
}

void TimeSync::Fit() {
    best_rtt_us_ = 1e300;
    for (const Sample& s : win_) best_rtt_us_ = std::min(best_rtt_us_, s.rtt_us);
    const double d0 = win_.front().rx_us;
    double b = b_;
    if (win_.size() >= 3 && win_.back().rx_us - d0 > 2e6) {
        // Short span: least squares of the ping midpoints (each good to ~±RTT/2, independent
        // errors). A max-margin slope locks onto 2-3 extreme pings while there are few of them.
        double n = 0, mx = 0, my = 0;
        for (const Sample& s : win_) mx += (s.rx_us + s.tx_us) / 2 - d0, my += (s.send_us + s.recv_us) / 2, n++;
        mx /= n, my /= n;
        double sxx = 0, sxy = 0;
        for (const Sample& s : win_) {
            double x = (s.rx_us + s.tx_us) / 2 - d0 - mx, y = (s.send_us + s.recv_us) / 2 - my;
            sxx += x * x, sxy += x * y;
        }
        double ls = sxx > 0 ? sxy / sxx : b_;
        if (std::fabs(1.0 / ls - 1.0) * 1e6 <= opt_.max_drift_ppm) b = ls;
    }
    if (win_.size() >= 3 && win_.back().rx_us - d0 >= opt_.margin_span_s * 1e6) {
        // Long span: the maximum-margin slope (the one leaving the widest band between the two
        // bound clouds) beats least squares. gap(b) = hi(b) - lo(b) is concave (a min of lines
        // minus a max of lines): ternary search around the least-squares slope.
        double x0 = b * (1 - 50e-6), x1 = b * (1 + 50e-6);
        for (int it = 0; it < 60 && x1 - x0 > 1e-10; it++) {
            double m1 = x0 + (x1 - x0) / 3, m2 = x1 - (x1 - x0) / 3, l1, h1, l2, h2;
            Band(m1, &l1, &h1);
            Band(m2, &l2, &h2);
            if (h1 - l1 < h2 - l2) x0 = m1;
            else x1 = m2;
        }
        b = (x0 + x1) / 2;
    }
    // The intercept from recent pings only: a small slope error then tilts it by little.
    double lo, hi;
    Band(b, &lo, &hi, win_.back().send_us - opt_.intercept_window_s * 1e6);
    gap_us_ = hi - lo;
    b_ = b;
    a_ = (lo + hi) / 2 - b * d0;
    have_fit_ = true;
}

int64_t TimeSync::ToHostNs(uint64_t dongle_us) const {
    double rel = double(int64_t(dongle_us - dongle_ref_us_));
    return host_ref_ns_ + int64_t(std::llround((a_ + b_ * rel) * 1000.0));
}

uint64_t TimeSync::ToDongleUs(int64_t host_ns) const {
    double host_us = (host_ns - host_ref_ns_) / 1000.0;
    return dongle_ref_us_ + uint64_t(int64_t(std::llround((host_us - a_) / b_)));
}

}  // namespace radio
}  // namespace tf
