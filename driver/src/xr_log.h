// Reads XRService's own log for what the LED phase loop can use (docs/re/FRAME-MODEL.md §4,
// docs/re/DEV-1.md):
//   [ControllerTracking]: initializing controller N, serial number: S   tracker N is serial S
//   [ContrLedsStats N]: Observed LED …                                   LEDs matched for tracker N
//   … Trying to track first LED frame with timestamp: T                  a controller-frame time
//   Not having enough IMU data for controller frame … Current timestamp: T, …   (one per frame)
// Tracker indices are XRService's, not deviceIds; the init line maps them to our serials.
// Frame times are seconds on XRService's clock (CLOCK_MONOTONIC_RAW, INFERRED as for the IMU).
//
// The watcher tails the newest XRService log under the Steam logs directory
// (~/.local/share/Steam/logs/…/XRService*), switching when a newer one appears. Reading a log
// that is already there, it only takes the tracker mapping from the old lines.
#pragma once
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <string>

namespace tf {

struct XrLogLine {
    enum Kind { kNone, kTrackerInit, kLedStats, kFrameStamp };
    Kind kind = kNone;
    int tracker = -1;    // kTrackerInit, kLedStats (and kFrameStamp when the line names one)
    std::string serial;  // kTrackerInit
    double frame_t = 0;  // kFrameStamp
};
bool ParseXrLogLine(const std::string& line, XrLogLine* out);

class XrLogWatcher {
public:
    struct Callbacks {
        std::function<std::string(int hand)> serial_of_hand;  // our serial per hand ("" = none)
        std::function<void(int hand, double now)> led_hit;
        std::function<void(double now, double frame_t)> frame_stamp;
        std::function<void(const std::string&)> log;
    };
    // logs_dir: "" = $HOME/.local/share/Steam/logs.
    XrLogWatcher(std::string logs_dir, Callbacks cb);
    ~XrLogWatcher();

    // Reads what was appended since the last call (call ~10 Hz). now: host seconds.
    void Poll(double now);
    // The newest XRService log under dir ("" if none).
    static std::string FindNewestLog(const std::string& dir);

    uint64_t led_hits() const { return led_hits_; }
    uint64_t frame_stamps() const { return frame_stamps_; }

private:
    void Open(const std::string& path, bool from_start);
    void Line(const std::string& line, double now, bool live);

    std::string dir_, path_, partial_;
    Callbacks cb_;
    FILE* f_ = nullptr;
    long offset_ = 0;
    double next_scan_ = 0;
    std::map<int, int> tracker_hand_;  // XRService tracker index -> our hand
    double last_hit_[2] = {0, 0};
    uint64_t led_hits_ = 0, frame_stamps_ = 0;
};

}  // namespace tf
