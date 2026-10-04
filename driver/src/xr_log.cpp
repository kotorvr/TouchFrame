#include "xr_log.h"

#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace tf {

static bool ParseInt(const char* p, int* out) {
    char* end = nullptr;
    long v = strtol(p, &end, 10);
    if (end == p) return false;
    *out = int(v);
    return true;
}

bool ParseXrLogLine(const std::string& line, XrLogLine* out) {
    *out = XrLogLine();
    const char* s = line.c_str();
    if (const char* p = strstr(s, "[ContrLedsStats ")) {
        if (!ParseInt(p + 16, &out->tracker)) return false;
        out->kind = XrLogLine::kLedStats;
        return true;
    }
    if (const char* p = strstr(s, "initializing controller ")) {
        const char* sn = strstr(p, "serial number: ");
        if (!sn || !ParseInt(p + 24, &out->tracker)) return false;
        std::string serial = sn + 15;
        while (!serial.empty() && isspace(uint8_t(serial.back()))) serial.pop_back();
        if (serial.empty()) return false;
        out->serial = serial;
        out->kind = XrLogLine::kTrackerInit;
        return true;
    }
    const char* key = nullptr;
    if (strstr(s, "Not having enough IMU data for controller frame")) key = "Current timestamp: ";
    else if (strstr(s, "Trying to track first LED frame")) key = "with timestamp: ";
    if (key) {
        const char* p = strstr(s, key);
        if (!p) return false;
        char* end = nullptr;
        double t = strtod(p + strlen(key), &end);
        if (end == p + strlen(key) || !(t > 0)) return false;
        out->frame_t = t;
        if (const char* ct = strstr(s, "[ControllerTracking ")) ParseInt(ct + 20, &out->tracker);
        out->kind = XrLogLine::kFrameStamp;
        return true;
    }
    return false;
}

XrLogWatcher::XrLogWatcher(std::string logs_dir, Callbacks cb) : dir_(std::move(logs_dir)), cb_(std::move(cb)) {
    if (dir_.empty()) {
        const char* home = getenv("HOME");
        dir_ = std::string(home ? home : "") + "/.local/share/Steam/logs";
    }
}

XrLogWatcher::~XrLogWatcher() {
    if (f_) fclose(f_);
}

static bool IsXrLogName(const std::string& n) {
    std::string l = n;
    for (auto& c : l) c = char(tolower(uint8_t(c)));
    return l.find("xrservice") != std::string::npos &&
           (l.size() > 4 && (l.compare(l.size() - 4, 4, ".log") == 0 || l.compare(l.size() - 4, 4, ".txt") == 0));
}

std::string XrLogWatcher::FindNewestLog(const std::string& dir) {
    std::string best;
    long long best_t = -1;
    // The logs dir itself and one level of subdirectories (XRService-<date>/).
    std::vector<std::string> dirs{dir};
    if (DIR* d = opendir(dir.c_str())) {
        while (dirent* e = readdir(d)) {
            if (e->d_name[0] == '.') continue;
            std::string p = dir + "/" + e->d_name;
            struct stat st;
            if (stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) dirs.push_back(p);
        }
        closedir(d);
    }
    for (const std::string& dd : dirs) {
        DIR* d = opendir(dd.c_str());
        if (!d) continue;
        while (dirent* e = readdir(d)) {
            if (!IsXrLogName(e->d_name)) continue;
            std::string p = dd + "/" + e->d_name;
            struct stat st;
            if (stat(p.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
            if ((long long)st.st_mtime > best_t || ((long long)st.st_mtime == best_t && p > best)) {
                best_t = st.st_mtime;
                best = p;
            }
        }
        closedir(d);
    }
    return best;
}

void XrLogWatcher::Open(const std::string& path, bool from_start) {
    if (f_) fclose(f_);
    f_ = fopen(path.c_str(), "rb");
    path_ = path;
    offset_ = 0;
    partial_.clear();
    tracker_hand_.clear();
    // Old lines (a log that was there before we looked): only the tracker mapping counts, the
    // stamps and hits are stale. Read in Poll's chunks: the log can be hundreds of MB.
    catching_up_ = !from_start;
    if (f_ && cb_.log) cb_.log("xrlog: reading " + path + (from_start ? "" : " (mapping trackers from what is there)"));
}

void XrLogWatcher::Consume(double now) {
    size_t start = 0, pos;
    while ((pos = partial_.find('\n', start)) != std::string::npos) {
        Line(partial_.substr(start, pos - start), now, !catching_up_);
        start = pos + 1;
    }
    partial_.erase(0, start);
}

void XrLogWatcher::Poll(double now) {
    if (now >= next_scan_) {
        next_scan_ = now + 5;
        std::string newest = FindNewestLog(dir_);
        if (!newest.empty() && newest != path_) Open(newest, !path_.empty());  // a new XRService run: all new
    }
    if (!f_) return;
    struct stat st;
    if (stat(path_.c_str(), &st) == 0 && st.st_size < offset_) {  // truncated / rotated in place
        partial_.clear();
        offset_ = 0;
    }
    fseek(f_, offset_, SEEK_SET);
    char buf[65536];
    size_t n = 0;
    int budget = 64;  // <= 4 MB a poll
    while (budget-- > 0 && (n = fread(buf, 1, sizeof(buf), f_)) > 0) {
        partial_.append(buf, n);
        Consume(now);
        if (partial_.size() > 1 << 20) partial_.clear();  // no newline in 1 MB: not a text log
    }
    if (n == 0 && catching_up_) catching_up_ = false;  // at the end: from here on, lines are live
    offset_ = ftell(f_);
    clearerr(f_);
}

void XrLogWatcher::Line(const std::string& line, double now, bool live) {
    XrLogLine l;
    if (!ParseXrLogLine(line, &l)) return;
    switch (l.kind) {
        case XrLogLine::kTrackerInit: {
            int hand = -1;
            for (int h = 0; h < 2 && cb_.serial_of_hand; h++) {
                std::string s = cb_.serial_of_hand(h);
                if (!s.empty() && s == l.serial) hand = h;
            }
            for (auto it = tracker_hand_.begin(); it != tracker_hand_.end();)
                it = it->second == hand && hand >= 0 ? tracker_hand_.erase(it) : std::next(it);
            if (hand >= 0) tracker_hand_[l.tracker] = hand;
            else tracker_hand_.erase(l.tracker);
            if (live && hand >= 0 && cb_.log)
                cb_.log("xrlog: XRService tracker " + std::to_string(l.tracker) + " is our " + (hand ? "right" : "left") +
                        " controller (" + l.serial + ")");
            return;
        }
        case XrLogLine::kLedStats: {
            auto it = tracker_hand_.find(l.tracker);
            if (!live || it == tracker_hand_.end()) return;
            int hand = it->second;
            if (now - last_hit_[hand] < 0.02) return;  // one per frame is plenty
            last_hit_[hand] = now;
            led_hits_++;
            if (cb_.led_hit) cb_.led_hit(hand, now);
            return;
        }
        case XrLogLine::kFrameStamp:
            if (!live) return;
            frame_stamps_++;
            if (cb_.frame_stamp) cb_.frame_stamp(now, l.frame_t);
            return;
        case XrLogLine::kNone:
            return;
    }
}

}  // namespace tf
