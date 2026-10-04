#include "radio_source.h"

#include <chrono>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <random>
#include <sstream>

#include "small_json.h"

namespace tf {
namespace radio {

namespace {

constexpr int64_t kSec = 1000000000LL;
const char* const kHandName[2] = {"left", "right"};

const char* CmdName(uint8_t c) {
    switch (c) {
        case CMD_STOP: return "STOP";
        case CMD_HELLO: return "HELLO";
        case CMD_HOST_START: return "HOST_START";
        case CMD_HOST_STATUS: return "HOST_STATUS";
        case CMD_PAIR_START: return "PAIR_START";
        case CMD_PAIR_STOP: return "PAIR_STOP";
        case CMD_CONNECT: return "CONNECT";
        case CMD_DISCONNECT: return "DISCONNECT";
        case CMD_REG_READ: return "REG_READ";
        case CMD_REG_WRITE: return "REG_WRITE";
        case CMD_REG_SUBSCRIBE: return "REG_SUBSCRIBE";
        case CMD_LED: return "LED";
        case CMD_HAPTIC: return "HAPTIC";
        case CMD_TIME_PING: return "TIME_PING";
    }
    return "?";
}
const char* SlotStateName(uint8_t s) {
    static const char* const n[] = {"free", "waiting", "negotiating", "connected", "lost"};
    return s < 5 ? n[s] : "?";
}
const char* PairStateName(uint8_t s) {
    static const char* const n[] = {"idle", "scanning", "linking", "key exchange", "provision", "done", "failed", "stopped"};
    return s < 8 ? n[s] : "?";
}
const char* ReasonName(uint8_t r) {
    static const char* const n[] = {"", "requested", "timeout", "rejected", "host restart"};
    return r < 5 ? n[r] : "?";
}

std::string CapsString(uint16_t caps) {
    static const char* const names[16] = {"sniffer", "host", "fake_ctrl", "placeholder", "store", "hid", "", "",
                                          "real_pairing", "real_conn_neg", "real_nonce", "real_hreg",
                                          "real_input", "real_imu", "real_led", "real_haptic"};
    std::string s;
    for (int b = 0; b < 16; b++)
        if (caps >> b & 1) s += (s.empty() ? "" : ",") + std::string(*names[b] ? names[b] : "?");
    return s.empty() ? "none" : s;
}

template <class T>
bool Body(const uint8_t* b, size_t n, T* out) {
    if (n < sizeof(T)) return false;
    memcpy(out, b, sizeof(T));
    return true;
}

std::string Hex16(uint64_t v) {
    char b[20];
    snprintf(b, sizeof(b), "%016" PRIx64, v);
    return b;
}

void SleepFor(double s) { std::this_thread::sleep_for(std::chrono::microseconds(int64_t(s * 1e6))); }

}  // namespace

int64_t HostNowNs() {
    timespec ts;
#ifdef _WIN32
    clock_gettime(CLOCK_MONOTONIC, &ts);  // host tests only (winpthreads has no MONOTONIC_RAW)
#else
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#endif
    return int64_t(ts.tv_sec) * kSec + ts.tv_nsec;
}

// ------------------------------------------------------------------------------- identity file

bool ParseIdentityJson(const std::string& text, uint32_t* netaddr, uint8_t key[16], std::map<uint64_t, int>* paired,
                       std::map<uint64_t, int>* hands) {
    json::Value root;
    json::Parser p(text.data(), text.data() + text.size());
    if (!p.Parse(&root) || root.type != json::Value::Object) return false;
    const json::Value* na = root.Get("netaddr");
    const json::Value* k = root.Get("link_key");
    if (!na || na->type != json::Value::Number || !k || k->type != json::Value::String || k->str.size() != 32)
        return false;
    *netaddr = uint32_t(na->num);
    for (int i = 0; i < 16; i++) key[i] = uint8_t(strtoul(k->str.substr(2 * i, 2).c_str(), nullptr, 16));
    paired->clear();
    hands->clear();
    if (const json::Value* pd = root.Get("paired"))
        for (auto& kv : pd->obj) {
            int slot = kv.second.type == json::Value::Number ? int(kv.second.num) : 0xFF;
            (*paired)[strtoull(kv.first.c_str(), nullptr, 16)] = slot;
        }
    if (const json::Value* hd = root.Get("hands"))
        for (auto& kv : hd->obj) {
            if (kv.second.type != json::Value::String) continue;
            if (kv.second.str == "left") (*hands)[strtoull(kv.first.c_str(), nullptr, 16)] = 0;
            else if (kv.second.str == "right") (*hands)[strtoull(kv.first.c_str(), nullptr, 16)] = 1;
        }
    return true;
}

std::string IdentityJson(uint32_t netaddr, const uint8_t key[16], const std::map<uint64_t, int>& paired,
                         const std::map<uint64_t, int>& hands) {
    std::string k;
    char b[4];
    for (int i = 0; i < 16; i++) snprintf(b, sizeof(b), "%02x", key[i]), k += b;
    std::ostringstream o;
    o << "{\n  \"netaddr\": " << netaddr << ",\n  \"link_key\": \"" << k << "\",\n  \"paired\": {";
    bool first = true;
    for (auto& kv : paired) {
        o << (first ? "\n" : ",\n") << "    \"" << Hex16(kv.first) << "\": " << kv.second;
        first = false;
    }
    o << (first ? "},\n" : "\n  },\n") << "  \"hands\": {";
    first = true;
    for (auto& kv : hands) {
        o << (first ? "\n" : ",\n") << "    \"" << Hex16(kv.first) << "\": \"" << kHandName[kv.second & 1] << "\"";
        first = false;
    }
    o << (first ? "}\n" : "\n  }\n") << "}\n";
    return o.str();
}

void RadioSource::LoadIdentity() {
    std::string text;
    if (!opt_.identity_path.empty()) {
        std::ifstream f(opt_.identity_path);
        std::stringstream ss;
        ss << f.rdbuf();
        text = ss.str();
    }
    if (!text.empty() && ParseIdentityJson(text, &id_.netaddr, id_.key, &id_.paired, &id_.hand)) {
        Logf("radio: host identity %s: netaddr 0x%08x, %zu paired controller(s)", opt_.identity_path.c_str(),
             id_.netaddr, id_.paired.size());
        return;
    }
    if (!text.empty()) Logf("radio: %s is not a host identity file; making a new one", opt_.identity_path.c_str());
    std::random_device rd;
    id_.netaddr = rd() | 1;
    for (auto& b : id_.key) b = uint8_t(rd());
    id_.paired.clear();
    id_.hand.clear();
    SaveIdentity();
    Logf("radio: new host identity (netaddr 0x%08x)%s%s", id_.netaddr,
         opt_.identity_path.empty() ? "; NOT persisted (no identity path)" : " in ", opt_.identity_path.c_str());
}

void RadioSource::SaveIdentity() {
    if (opt_.identity_path.empty()) return;
    std::string tmp = opt_.identity_path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        f << IdentityJson(id_.netaddr, id_.key, id_.paired, id_.hand);
        if (!f) {
            Logf("radio: can't write %s", tmp.c_str());
            return;
        }
    }
#ifdef _WIN32
    std::remove(opt_.identity_path.c_str());  // Windows rename won't replace (host tests only)
#endif
    if (std::rename(tmp.c_str(), opt_.identity_path.c_str()) != 0)
        Logf("radio: can't replace %s", opt_.identity_path.c_str());
}

// ------------------------------------------------------------------------------- lifecycle

RadioSource::RadioSource(Options opt, Callbacks cb) : opt_(std::move(opt)), cb_(std::move(cb)) {}

RadioSource::~RadioSource() { Stop(); }

void RadioSource::Logf(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (opt_.log) opt_.log(buf);
    else fprintf(stderr, "%s\n", buf);
}

bool RadioSource::Start() {
    if (running_) return true;
    LoadIdentity();
    for (int h = 0; h < 2; h++) {
        if (opt_.imu_cal[h].empty()) continue;
        std::ifstream f(opt_.imu_cal[h]);
        std::stringstream ss;
        ss << f.rdbuf();
        std::string err;
        if (ParseMetaCalibration(ss.str(), &hands_[h].rect, &err))
            Logf("radio: %s IMU rectification from %s (%d unit(s))", kHandName[h], opt_.imu_cal[h].c_str(),
                 hands_[h].rect.units);
        else
            Logf("radio: %s IMU rectification: %s: %s; using raw chip axes (XRService needs the model frame!)",
                 kHandName[h], opt_.imu_cal[h].c_str(), err.c_str());
    }
    running_ = true;
    thread_ = std::thread(&RadioSource::Run, this);
    return true;
}

void RadioSource::Stop() {
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
}

void RadioSource::Run() {
    int64_t last_fail_log = -1000 * kSec;
    while (running_) {
        std::string err;
        std::unique_ptr<Transport> t = MakeTransport(opt_.transport, &err);
        if (!t) {
            Logf("radio: %s", err.c_str());
            return;
        }
        if (t->Open(&err)) {
            Logf("radio: opened %s", t->Describe().c_str());
            last_fail_log = HostNowNs();
            Session(t.get());
            t->Close();
            {
                std::lock_guard<std::mutex> lk(mu_);
                link_.open = link_.hosting = false;
            }
        } else if (HostNowNs() - last_fail_log > 30 * kSec) {
            Logf("radio: no dongle (%s); retrying every second", err.c_str());
            last_fail_log = HostNowNs();
        }
        for (int i = 0; i < 10 && running_; i++) SleepFor(0.1);
    }
}

void RadioSource::Send(uint8_t cmd, const void* body, size_t n, const void* tail, size_t tail_n) {
    if (!tr_) return;
    std::vector<uint8_t> f = EncodeCommand(cmd, body, n, tail, tail_n);
    if (!tr_->Write(f.data(), f.size())) Logf("radio: write of %s failed", CmdName(cmd));
}

uint8_t RadioSource::Tag(const Pending& p) {
    uint8_t t = next_tag_;
    next_tag_ = uint8_t(next_tag_ % 255 + 1);
    pending_[t] = p;
    return t;
}

void RadioSource::Session(Transport* t) {
    tr_ = t;
    restart_ = false;
    dec_.Reset();
    sync_.Reset();
    pending_.clear();
    parked_.clear();
    int64_t now = HostNowNs();
    last_pong_ns_ = last_status_ns_ = now;
    state_ = kHello;
    state_since_ns_ = 0;  // send HELLO at once
    {
        std::lock_guard<std::mutex> lk(mu_);
        link_ = LinkStatus();
        link_.open = true;
        link_.transport = t->Describe();
    }
    uint8_t buf[4096];
    while (running_) {
        int n = t->Read(buf, sizeof(buf), 2);
        now = HostNowNs();
        if (n < 0) {
            Logf("radio: %s: read failed (unplugged?)", t->Describe().c_str());
            break;
        }
        if (n > 0) dec_.Feed(buf, size_t(n), [&](const uint8_t* f, size_t fn) { HandleFrame(f, fn, now); });
        if (state_ == kClosed) break;  // fatal (wrong link version)
        if (restart_) {
            Logf("radio: the dongle's clock restarted (it rebooted); starting over");
            break;
        }
        if (state_ != kRunning && now - state_since_ns_ > kSec) {
            static const char* const what[] = {"", "HELLO", "PAIR_LIST", "HOST_STATUS", "HOST_START", ""};
            if (state_ != kHello) Logf("radio: no answer to %s; starting over", what[state_]);
            Pending p;
            p.cmd = CMD_HELLO;
            uint8_t tag = Tag(p);
            Send(CMD_HELLO, &tag, 1);
            state_ = kHello;
            state_since_ns_ = now;
        }
        if (now - last_ping_ns_ >= int64_t(kSec / std::max(1.0, opt_.ping_hz))) {
            TimePing p{};
            p.seq = ++ping_seq_;
            p.host_t = uint64_t(HostNowNs());
            Send(CMD_TIME_PING, &p, sizeof(p));
            last_ping_ns_ = now;
        }
        if (now - last_pong_ns_ > 3 * kSec) {
            Logf("radio: no reply from the dongle for 3 s; reopening");
            break;
        }
        if (state_ == kRunning && now - last_status_ns_ > 60 * kSec) {
            last_status_ns_ = now;
            Pending p;
            p.cmd = CMD_HOST_STATUS;
            uint8_t tag = Tag(p);
            Send(CMD_HOST_STATUS, &tag, 1);
        }
        ServiceHands(now);
    }
    parked_.clear();
    for (int h = 0; h < 2; h++) {
        bool was;
        {
            std::lock_guard<std::mutex> lk(mu_);
            was = hands_[h].connected;
        }
        if (was) Disconnected(h, "dongle link closed");
    }
    bool fatal = state_ == kClosed;
    state_ = kClosed;
    tr_ = nullptr;
    if (fatal)
        for (int i = 0; i < 300 && running_; i++) SleepFor(0.1);  // don't hammer a wrong firmware
}

// ------------------------------------------------------------------------------- events

void RadioSource::HandleFrame(const uint8_t* f, size_t n, int64_t now) {
    const uint8_t type = f[0];
    const uint8_t* b = f + 1;
    const size_t bn = n - 1;
    {
        std::lock_guard<std::mutex> lk(mu_);
        link_.frames++;
        link_.bad_frames = dec_.bad_frames();
    }
    switch (type) {
        case EVT_TIME: {
            TimePong p;
            if (!Body(b, bn, &p)) return;
            if (int64_t(p.host_t) <= now && now - int64_t(p.host_t) < kSec) {
                int resets = sync_.resets();
                sync_.AddPing(int64_t(p.host_t), now, p.dongle_rx_us, p.dongle_tx_us);
                if (sync_.resets() != resets) restart_ = true;  // the dongle's clock restarted: it rebooted
                last_pong_ns_ = now;
                std::lock_guard<std::mutex> lk(mu_);
                link_.drift_ppm = sync_.DriftPpm();
                link_.best_rtt_us = sync_.best_rtt_us();
                link_.sync_band_us = sync_.uncertainty_us();
                link_.sync_span_s = sync_.span_s();
            }
            return;
        }
        case EVT_HELLO: {
            HelloEvt h;
            if (!Body(b, bn, &h) || state_ != kHello) return;
            if (h.version != kLinkVersion) {
                Logf("radio: dongle speaks link v%u, driver v%u: reflash the dongle (radio-fw)", h.version, kLinkVersion);
                state_ = kClosed;
                return;
            }
            {
                std::lock_guard<std::mutex> lk(mu_);
                link_.caps = h.caps;
            }
            Logf("radio: dongle %016" PRIx64 " build %u, mode %u, caps %s", h.dongle_id, h.build, h.mode,
                 CapsString(h.caps).c_str());
            if (!(h.caps & (1u << 1))) {
                Logf("radio: this firmware has no host mode");
                state_ = kClosed;
                return;
            }
            if (!(h.caps & (1u << 12)) && !opt_.placeholder)
                Logf("radio: note: real controller input isn't pinned in this firmware yet (RE-1); "
                     "controllers may not connect");
            hello_mode_ = h.mode;
            stored_ = opt_.identity_mode == "stored" || (opt_.identity_mode != "driver" && (h.caps & CAP_STORE));
            if (stored_) {  // learn the stored identity and pairings first
                Pending p;
                p.cmd = CMD_PAIR_LIST;
                uint8_t tag = Tag(p);
                Send(CMD_PAIR_LIST, &tag, 1);
                state_ = kListing;
                state_since_ns_ = now;
                return;
            }
            StartHost(now);
            return;
        }
        case EVT_PAIRINGS: {
            Pairings ps;
            if (!Body(b, bn, &ps) || bn < sizeof(ps) + ps.count * sizeof(Pairing)) return;
            dongle_netaddr_ = ps.netaddr;
            id_.paired.clear();
            bool changed = false;
            for (int i = 0; i < ps.count; i++) {
                Pairing pr;
                memcpy(&pr, b + sizeof(ps) + i * sizeof(Pairing), sizeof(pr));
                id_.paired[pr.device_id] = pr.slot;
                if (pr.hand == HAND_LEFT || pr.hand == HAND_RIGHT) {
                    int hd = pr.hand == HAND_LEFT ? 0 : 1;
                    if (!id_.hand.count(pr.device_id) || id_.hand[pr.device_id] != hd) id_.hand[pr.device_id] = hd, changed = true;
                }
            }
            if (changed) SaveIdentity();
            Logf("radio: dongle flash: netaddr 0x%08x, %u pairing(s), %u writes left", ps.netaddr, ps.count,
                 ps.writes_left);
            MoveToReportedHands();
            if (state_ == kListing) StartHost(now);
            return;
        }
        case EVT_HOST_STATUS: {
            if (bn < 44 + 5 * 28) return;
            uint8_t mode = b[1], flags = b[2];
            uint32_t netaddr, beacons, uplinks, crc, late, dropped;
            memcpy(&netaddr, b + 12, 4);
            memcpy(&beacons, b + 16, 4);
            memcpy(&uplinks, b + 24, 4);
            memcpy(&crc, b + 28, 4);
            memcpy(&late, b + 32, 4);
            memcpy(&dropped, b + 36, 4);
            std::string slots;
            for (int s = 0; s < kMaxSlots; s++) slots += std::string(s ? " " : "") + SlotStateName(b[44 + 28 * s]);
            if (state_ == kAdopting) {
                uint8_t want = HostFlags();
                uint32_t ours = stored_ ? dongle_netaddr_ : id_.netaddr;
                const uint8_t mask = HOST_COMPACT | HOST_PLACEHOLDER | HOST_STORED;
                if (mode == 2 && ours && netaddr == ours && (flags & mask) == (want & mask)) {
                    Logf("radio: dongle already hosting as us (netaddr 0x%08x); keeping its connections [%s]", netaddr,
                         slots.c_str());
                    state_ = kRunning;
                    {
                        std::lock_guard<std::mutex> lk(mu_);
                        link_.hosting = true;
                    }
                    for (int s = 0; s < kMaxSlots; s++) {
                        const uint8_t* st = b + 44 + 28 * s;
                        if (st[0] != SLOT_CONNECTED) continue;
                        ConnEvt c{};
                        c.slot = uint8_t(s);
                        c.state = SLOT_CONNECTED;
                        c.rssi = int8_t(st[1]);
                        memcpy(&c.pulsar_version, st + 2, 2);
                        memcpy(&c.device_id, st + 4, 8);
                        OnConn(c);
                    }
                    if (!stored_) ConnectPaired();
                } else {
                    Logf("radio: dongle is hosting another identity or mode; restarting host mode");
                    hello_mode_ = 0;
                    StartHost(now);
                }
                return;
            }
            Logf("radio: host status: beacons %u, uplinks %u, crc errors %u, late beacons %u, events dropped %u, "
                 "sync drift %+.1f ppm rtt %.0f us band %.0f us | slots %s",
                 beacons, uplinks, crc, late, dropped, sync_.DriftPpm(), sync_.best_rtt_us(), sync_.uncertainty_us(),
                 slots.c_str());
            return;
        }
        case EVT_RESULT: {
            ResultEvt r;
            if (Body(b, bn, &r)) OnResult(r);
            return;
        }
        case EVT_CONN: {
            ConnEvt c;
            if (Body(b, bn, &c)) OnConn(c);
            return;
        }
        case EVT_PAIR: {
            PairEvt p;
            if (!Body(b, bn, &p)) return;
            Logf("radio: pairing %s%s (controller %016" PRIx64 ")", PairStateName(p.state),
                 p.status ? (std::string(", ") + StatusName(p.status)).c_str() : "", p.device_id);
            if (p.state == PAIR_DONE) {
                int hand;
                bool ours;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    hand = pair_.hand;
                    ours = pair_.active;
                    pair_.active = false;
                }
                const bool told = p.hand == HAND_LEFT || p.hand == HAND_RIGHT;
                if (told) hand = p.hand == HAND_LEFT ? 0 : 1;  // the controller knows
                if (!ours && id_.paired.count(p.device_id)) {
                    // The dongle's follow-up once it has read the controller's cmd 1: only its hand.
                    // (Replacing the other controller on that hand is for a new pairing only.)
                    if (told && (!id_.hand.count(p.device_id) || id_.hand[p.device_id] != hand)) {
                        id_.hand[p.device_id] = hand;
                        SaveIdentity();
                        MoveToReportedHands();
                    }
                    return;
                }
                std::vector<uint64_t> replaced;
                for (auto& kv : id_.hand)
                    if (kv.second == hand && kv.first != p.device_id) replaced.push_back(kv.first);
                for (uint64_t old : replaced) {
                    Logf("radio: %s hand: %016" PRIx64 " replaced by %016" PRIx64, kHandName[hand], old, p.device_id);
                    ForgetOrDrop(old, hand);
                }
                id_.paired[p.device_id] = 0xFF;
                id_.hand[p.device_id] = hand;
                SaveIdentity();
                if (!stored_) {  // a stored pairing is let in by the dongle itself
                    Connect c{};
                    c.tag = Tag(Pending{CMD_CONNECT, hand, p.device_id, 0});
                    c.slot = 0xFF;
                    c.device_id = p.device_id;
                    Send(CMD_CONNECT, &c, sizeof(c));
                }
            } else if (p.state == PAIR_FAILED || p.state == PAIR_STOPPED) {
                std::lock_guard<std::mutex> lk(mu_);
                pair_.active = false;
            }
            return;
        }
        case EVT_ADVERT: {
            uint64_t dev;
            if (bn >= 17) {
                memcpy(&dev, b + 8, 8);
                Logf("radio: controller %016" PRIx64 " advertising (rssi %d)", dev, int(int8_t(b[16])));
            }
            return;
        }
        case EVT_REG: {
            RegEvt r;
            if (!Body(b, bn, &r) || bn < sizeof(RegEvt) + r.len) return;
            if (r.kind != REG_READ) return;
            int hand = HandOfSlot(r.slot);
            if (hand < 0) return;
            if (r.reg == kRegDeviceDesc) {
                // Handedness from the controller itself (REVIEW-RE R11); "unconf" keeps our choice.
                std::string s;
                if (r.status == LINK_OK && r.len >= kDeviceDescLen) {
                    const char* p = reinterpret_cast<const char*>(b + sizeof(RegEvt) + 16);
                    s.assign(p, strnlen(p, 8));
                }
                int said = s == "left" ? 0 : s == "right" ? 1 : -1;
                uint64_t dev = hands_[hand].device_id;
                Logf("radio: %s controller %016" PRIx64 " says it is %s", kHandName[hand], dev,
                     r.status != LINK_OK ? ("unknown (" + std::string(StatusName(r.status)) + ")").c_str()
                     : s.empty() ? "unknown" : s.c_str());
                if (said >= 0 && said != hand) {
                    id_.hand[dev] = said;
                    SaveIdentity();
                    MoveToReportedHands();
                }
                return;
            }
            if (r.reg != kRegImuConfig) return;
            ImuScale s;
            std::lock_guard<std::mutex> lk(mu_);
            if (r.status == LINK_OK && ParseImuConfig(b + sizeof(RegEvt), r.len, &s)) {
                hands_[hand].scale = s;
                hands_[hand].scale_from_controller = true;
                Logf("radio: %s IMU config: %.6g g/LSB, %.6g dps/LSB, %u/%u Hz", kHandName[hand], s.g_per_lsb,
                     s.dps_per_lsb, s.accel_hz, s.gyro_hz);
            } else {
                Logf("radio: %s IMU config (cmd 0x32) unreadable (%s); using the sample's scale fields or the "
                     "ICM-42686 default", kHandName[hand], StatusName(r.status));
            }
            return;
        }
        case EVT_INPUT: {
            InputEvt in;
            if (Body(b, bn, &in)) OnSample(in, nullptr, nullptr, nullptr, now);
            return;
        }
        case EVT_IMU: {
            ImuEvt e;
            if (Body(b, bn, &e)) OnSample(InputEvt{}, e.accel, e.gyro, &e, now);
            return;
        }
        case EVT_SAMPLE: {
            SampleEvt s;
            if (!Body(b, bn, &s)) return;
            int32_t a[3] = {s.accel[0], s.accel[1], s.accel[2]}, g[3] = {s.gyro[0], s.gyro[1], s.gyro[2]};
            const bool repeat = s.in.flags & SAMPLE_IMU_REPEAT;  // the last IMU sample again: inputs only
            OnSample(s.in, repeat ? nullptr : a, repeat ? nullptr : g, nullptr, now);
            return;
        }
        case EVT_TEXT:
            Logf("radio: dongle: %.*s", int(bn), reinterpret_cast<const char*>(b));
            return;
        default:
            return;  // EVT_SOF, EVT_UPLINK, sniffer events: not for the driver
    }
}

void RadioSource::OnResult(const ResultEvt& r) {
    Pending p;
    auto it = pending_.find(r.tag);
    if (it != pending_.end() && it->second.cmd == r.cmd) {
        p = it->second;
        pending_.erase(it);
    } else {
        p.cmd = r.cmd;
    }
    int64_t now = HostNowNs();
    if (r.status != LINK_OK) {
        // Errors repeat (e.g. LED re-sends while RE is pending): one line per command a minute.
        int64_t& last = result_logged_[r.cmd];
        if (now - last > 60 * kSec) {
            last = now;
            Logf("radio: %s -> %s (detail %u)", CmdName(r.cmd), StatusName(r.status), r.detail);
        }
    }
    switch (r.cmd) {
        case CMD_HOST_START:
            if (r.status == LINK_OK) {
                state_ = kRunning;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    link_.hosting = true;
                }
                if (stored_) {
                    Logf("radio: hosting with the dongle's stored identity (netaddr 0x%08x); %u pairing(s) let in",
                         dongle_netaddr_, r.detail);
                    if (id_.paired.empty()) Logf("radio: no paired controllers yet (pair with driver_touchframe.radio_pair)");
                    Pending lp;
                    lp.cmd = CMD_PAIR_LIST;  // a first start just generated the identity: learn its netaddr
                    uint8_t tag = Tag(lp);
                    Send(CMD_PAIR_LIST, &tag, 1);
                } else {
                    Logf("radio: hosting as netaddr 0x%08x (driver-owned identity)", id_.netaddr);
                    ConnectPaired();
                }
            } else {
                state_ = kHello;  // retried by the session loop in a second
                state_since_ns_ = now;
            }
            return;
        case CMD_CONNECT:
            if (r.status == LINK_OK && p.device_id && id_.paired.count(p.device_id) && id_.paired[p.device_id] != r.detail) {
                id_.paired[p.device_id] = r.detail;
                SaveIdentity();
            }
            return;
        case CMD_PAIR_START:
            if (r.status != LINK_OK) {
                std::lock_guard<std::mutex> lk(mu_);
                pair_.active = false;
            }
            return;
        case CMD_REG_READ:
            if (r.status != LINK_OK && p.reg == kRegImuConfig && p.hand >= 0)
                Logf("radio: %s IMU config (cmd 0x32) read refused (%s); using the sample's scale fields or the "
                     "ICM-42686 default", kHandName[p.hand], StatusName(r.status));
            return;
        default:
            return;
    }
}

void RadioSource::MoveToReportedHands() {
    // A connected controller now known to be the other hand moves there, unless that hand's own
    // controller is on it: then it stays until it disconnects, and comes back on the right hand.
    // A controller that only borrowed that hand gives way (OnConn), so two controllers on each
    // other's hand swap.
    auto own_hand = [&](int hd) {
        auto it = id_.hand.find(hands_[hd].device_id);
        return it == id_.hand.end() ? -1 : it->second;
    };
    for (int hd = 0; hd < 2; hd++) {
        if (!hands_[hd].connected) continue;
        int want = own_hand(hd);
        if (want < 0 || want == hd) continue;
        if (hands_[1 - hd].connected && own_hand(1 - hd) != hd) {
            Logf("radio: controller %016" PRIx64 " is a %s controller, but that hand is in use; keeping it %s for now",
                 hands_[hd].device_id, kHandName[1 - hd], kHandName[hd]);
            continue;
        }
        ConnEvt c = hands_[hd].conn;
        Disconnected(hd, ("it is the " + std::string(kHandName[1 - hd]) + " controller").c_str());
        OnConn(c);
        return;  // hands_ changed under the loop; one move is enough (a swap completes inside OnConn)
    }
}

int RadioSource::HandOfSlot(int slot) const {
    for (int h = 0; h < 2; h++)
        if (hands_[h].connected && hands_[h].slot == slot) return h;
    return -1;
}

int RadioSource::HandForDevice(uint64_t dev) {
    auto it = id_.hand.find(dev);
    if (it != id_.hand.end()) return it->second;
    if (!id_.paired.count(dev)) return -1;
    // No hand known (paired with tools/radio.py, or the firmware can't tell): the first free hand,
    // right first (the planner's default; RequestPair(hand) overrides).
    for (int h = 1; h >= 0; h--) {
        bool used = false;  // by a paired controller (forgotten ones may linger in the file)
        for (auto& kv : id_.hand) used |= kv.second == h && id_.paired.count(kv.first);
        if (!used) {
            id_.hand[dev] = h;
            SaveIdentity();
            Logf("radio: controller %016" PRIx64 " has no hand in the identity file; using %s", dev, kHandName[h]);
            return h;
        }
    }
    return -1;
}

uint8_t RadioSource::HostFlags() const {
    return HOST_DM_BEACONS | (opt_.compact || (tr_ && tr_->IsHid()) ? HOST_COMPACT : 0) |
           (opt_.placeholder ? HOST_PLACEHOLDER : 0) | (stored_ ? HOST_STORED : 0);
}

void RadioSource::StartHost(int64_t now) {
    Pending p;
    if (hello_mode_ == 2) {  // already hosting: keep its connections if it is us
        p.cmd = CMD_HOST_STATUS;
        uint8_t tag = Tag(p);
        Send(CMD_HOST_STATUS, &tag, 1);
        state_ = kAdopting;
    } else {
        p.cmd = CMD_HOST_START;
        HostStart hs{};
        hs.tag = Tag(p);
        hs.flags = HostFlags();
        std::random_device rd;
        hs.session_nonce = uint16_t(rd());
        hs.netaddr = id_.netaddr;  // ignored with HOST_STORED
        memcpy(hs.link_key, id_.key, 16);
        memset(hs.chmap, 0xFF, 4);
        hs.chmap[4] = 0x1F;  // all 37 channels
        hs.tx_power_dbm = int8_t(opt_.tx_power_dbm);
        Send(CMD_HOST_START, &hs, sizeof(hs));
        state_ = kStarting;
    }
    state_since_ns_ = now;
}

void RadioSource::ForgetOrDrop(uint64_t device_id, int hand) {
    if (stored_) {
        PairForget f{};
        f.tag = Tag(Pending{CMD_PAIR_FORGET, hand, device_id, 0});
        f.device_id = device_id;
        Send(CMD_PAIR_FORGET, &f, sizeof(f));  // frees its slot too (EVT_CONN FREE)
    } else if (hands_[hand].connected && hands_[hand].device_id == device_id) {
        uint8_t d[3] = {Tag(Pending{CMD_DISCONNECT, hand, device_id, 0}), uint8_t(hands_[hand].slot), 1};
        Send(CMD_DISCONNECT, d, sizeof(d));
    }
    id_.paired.erase(device_id);
    id_.hand.erase(device_id);
}

void RadioSource::ConnectPaired() {
    for (auto& kv : id_.paired) {
        bool connected = false;
        for (auto& h : hands_) connected |= h.connected && h.device_id == kv.first;
        if (connected) continue;
        Connect c{};
        c.tag = Tag(Pending{CMD_CONNECT, -1, kv.first, 0});
        c.slot = 0xFF;
        c.device_id = kv.first;
        Send(CMD_CONNECT, &c, sizeof(c));
    }
    if (id_.paired.empty()) Logf("radio: no paired controllers yet (pair with driver_touchframe.radio_pair)");
}

void RadioSource::OnConn(const ConnEvt& c) {
    if (c.state == SLOT_CONNECTED) {
        parked_.erase(c.slot);
        int hand = c.device_id ? HandForDevice(c.device_id) : HandOfSlot(c.slot);
        if (hand < 0) {
            Logf("radio: controller %016" PRIx64 " connected in slot %u but isn't one of ours", c.device_id, c.slot);
            return;
        }
        if (hands_[hand].connected && hands_[hand].device_id != c.device_id) {
            const uint64_t there = hands_[hand].device_id;
            auto own = id_.hand.find(there);
            if (own == id_.hand.end() || own->second != hand) {
                // The controller there only borrowed this hand (below), or was just replaced (its
                // FREE is on the way): it gives way, back to its own hand if that is free now, else
                // it waits for a free hand.
                ConnEvt back = hands_[hand].conn;
                Disconnected(hand, "it gives way to this hand's own controller");
                if (hands_[1 - hand].connected) {
                    Logf("radio: controller %016" PRIx64 " (slot %u): both hands are in use; it waits for a free hand",
                         there, back.slot);
                    parked_[back.slot] = back;
                } else {
                    OnConn(back);
                }
            } else if (hands_[1 - hand].connected) {
                // Two controllers for one hand (e.g. cmd 1 said otherwise than the pairing): the
                // other hand if it is free, else wait for one to go.
                Logf("radio: controller %016" PRIx64 " (slot %u) is a %s controller and both hands are in use; "
                     "it waits for a free hand", c.device_id, c.slot, kHandName[hand]);
                parked_[c.slot] = c;
                return;
            } else {
                Logf("radio: controller %016" PRIx64 " is a %s controller, but that hand is in use; using it as %s for now",
                     c.device_id, kHandName[hand], kHandName[1 - hand]);
                hand = 1 - hand;
            }
        }
        {
            std::lock_guard<std::mutex> lk(mu_);
            Hand& h = hands_[hand];
            h.connected = true;
            h.slot = c.slot;
            h.device_id = c.device_id;
            h.conn = c;
            h.have_seq_input = h.have_seq_imu = false;
            h.scale = ImuScale();
            h.scale_from_controller = false;
            h.last_t = 0;
        }
        Logf("radio: %s controller %016" PRIx64 " connected (slot %u, rssi %d, pulsar 0x%04x)", kHandName[hand],
             c.device_id, c.slot, c.rssi, c.pulsar_version);
        RegCmd rc{};
        rc.tag = Tag(Pending{CMD_REG_READ, hand, 0, kRegImuConfig});
        rc.slot = c.slot;
        rc.reg = kRegImuConfig;
        rc.len = 16;
        Send(CMD_REG_READ, &rc, sizeof(rc));
        rc.tag = Tag(Pending{CMD_REG_READ, hand, 0, kRegDeviceDesc});
        rc.reg = kRegDeviceDesc;
        rc.len = kDeviceDescLen;
        Send(CMD_REG_READ, &rc, sizeof(rc));
        // The dongle learns the controller's hand from cmd 1 after connecting (REVIEW-RE R11):
        // read the pairings again once it has, so the hand can be corrected.
        if (stored_) pairlist_due_s_ = HostNowNs() * 1e-9 + 2.5;
        if (cb_.connection) cb_.connection(hand, true);
        return;
    }
    // By slot: a controller may sit on the other hand than its own for now (above).
    auto parked = parked_.find(c.slot);
    if (parked != parked_.end() && (!c.device_id || parked->second.device_id == c.device_id)) parked_.erase(parked);
    int hand = HandOfSlot(c.slot);
    if (hand >= 0 && (!c.device_id || hands_[hand].device_id == c.device_id)) {
        Disconnected(hand, (std::string(SlotStateName(c.state)) + (c.reason ? std::string(", ") + ReasonName(c.reason) : "")).c_str());
        if (!parked_.empty()) {  // a controller waiting for a free hand takes it
            ConnEvt next = parked_.begin()->second;
            OnConn(next);
        }
        return;
    }
    Logf("radio: slot %u %s (controller %016" PRIx64 ")", c.slot, SlotStateName(c.state), c.device_id);
}

void RadioSource::Disconnected(int hand, const char* why) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        Hand& h = hands_[hand];
        h.connected = false;
        h.slot = -1;
        h.led.reset();
        h.led_logged_state = -1;
        h.haptic = HapticScheduler();
    }
    Logf("radio: %s controller disconnected (%s)", kHandName[hand], why);
    if (cb_.connection) cb_.connection(hand, false);
}

void RadioSource::OnSample(const InputEvt& in, const int32_t* acc, const int32_t* gyr, const ImuEvt* imu_evt,
                           int64_t now) {
    const uint8_t slot = imu_evt ? imu_evt->slot : in.slot;
    const uint64_t t_us = imu_evt ? imu_evt->t_us : in.t_us;
    const uint16_t seq = imu_evt ? imu_evt->seq : in.seq;
    int hand = HandOfSlot(slot);
    if (hand < 0) return;
    bool synced = sync_.Valid();
    double t = synced ? sync_.ToHostNs(t_us) * 1e-9 : now * 1e-9;
    double now_s = now * 1e-9;
    if (t > now_s) t = now_s;  // a sample can't be from the future: sync error
    HandState hs{};
    float a[3], g[3];
    bool have_input = !imu_evt, have_imu = acc && synced;
    {
        std::lock_guard<std::mutex> lk(mu_);
        Hand& h = hands_[hand];
        // One stream per sample kind; EVT_SAMPLE carries both under one seq.
        bool& have = imu_evt ? h.have_seq_imu : h.have_seq_input;
        uint16_t& last = imu_evt ? h.seq_imu : h.seq_input;
        if (have && uint16_t(seq - last) > 1) h.gaps += uint16_t(seq - last) - 1;
        have = true;
        last = seq;
        if (t <= h.last_t) t = h.last_t + 1e-6;  // XRService drops samples "in the past"
        h.last_t = t;
        if (have_input) {
            hs = MapInputs(in);
            h.inputs++;
        }
        if (acc && !synced) h.unsynced++;
        if (have_imu) {
            ImuScale s = h.scale;
            if (!h.scale_from_controller && imu_evt) ScaleFromImuEvent(*imu_evt, &s);
            ImuToSI(s, h.rect, acc, gyr, a, g);
            h.imu++;
        }
    }
    if (have_input && cb_.inputs) cb_.inputs(hand, hs, t);
    if (have_imu && cb_.imu) cb_.imu(hand, t, a, g);
}

void RadioSource::ServiceHands(int64_t now) {
    const double now_s = now * 1e-9;
    struct Out {
        uint8_t cmd;
        std::vector<uint8_t> body;
    };
    std::vector<Out> out;
    if (pairlist_due_s_ > 0 && now_s >= pairlist_due_s_ && state_ == kRunning) {
        pairlist_due_s_ = 0;
        Pending lp;
        lp.cmd = CMD_PAIR_LIST;
        out.push_back(Out{CMD_PAIR_LIST, std::vector<uint8_t>(1, Tag(lp))});
    }
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (pair_.pending && state_ == kRunning) {
            pair_.pending = false;
            pair_.active = true;
            PairStart ps{};
            ps.tag = Tag(Pending{CMD_PAIR_START, pair_.hand, pair_.device_id, 0});
            ps.flags = PAIR_AUTO;
            ps.timeout_s = uint16_t(pair_.timeout_s);
            ps.device_id = pair_.device_id;
            Out o{CMD_PAIR_START, std::vector<uint8_t>(sizeof(ps))};
            memcpy(o.body.data(), &ps, sizeof(ps));
            out.push_back(std::move(o));
            Logf("radio: pairing the next %s controller (%s, %d s); put it in pairing mode", kHandName[pair_.hand],
                 pair_.device_id ? Hex16(pair_.device_id).c_str() : "any", pair_.timeout_s);
        }
        for (int hi = 0; hi < 2; hi++) {
            Hand& h = hands_[hi];
            Haptic hc;
            bool haptic = h.connected && h.haptic.Poll(now_s, &hc);
            if (haptic_due_[hi]) {
                haptic_due_[hi] = false;
                if (h.connected) hc = haptic_cmd_[hi], haptic = true;
            }
            if (haptic) {
                hc.tag = Tag(Pending{CMD_HAPTIC, hi, 0, 0});
                hc.slot = uint8_t(h.slot);
                Out o{CMD_HAPTIC, std::vector<uint8_t>(sizeof(hc))};
                memcpy(o.body.data(), &hc, sizeof(hc));
                out.push_back(std::move(o));
            }
            // LED phase loop: once connected and the time sync's slope is settled.
            if (!opt_.led_loop || !h.connected || state_ != kRunning) continue;
            if (!h.led) {
                if (sync_.span_s() < opt_.led_min_sync_span_s) continue;
                h.led.reset(new LedPhaseLoop(opt_.led));
                h.led->Start(now_s);
                Logf("radio: %s LED phase loop started (frame period %.1f us, k %d, dwell %.1f s)", kHandName[hi],
                     h.led->options().frame_period_us, h.led->options().coarse_divisor, h.led->options().dwell_s);
            }
            // The exposure phase is the camera's, not the controller's: start from the other hand's
            // live track, or this hand's last one (extrapolated with its drift), before sweeping.
            const Hand& other = hands_[1 - hi];
            if (h.led->state() == LedPhaseLoop::kSearch) {
                if (other.led && other.led->fine_track())
                    h.led->SeedPhase(now_s, other.led->centre_at(now_s), other.led->drift_us_per_s());
                else if (h.have_phase && now_s - h.phase_t < 600)
                    h.led->SeedPhase(now_s, h.phase_us + h.phase_rate * (now_s - h.phase_t), h.phase_rate);
            }
            if (h.led->fine_track()) {
                h.have_phase = true;
                h.phase_us = h.led->centre_at(now_s);
                h.phase_t = now_s;
                h.phase_rate = h.led->drift_us_per_s();
            }
            if (h.led->Update(now_s)) {
                Led l = LedCommandFor(h.led->schedule(now_s), sync_, uint8_t(h.slot));
                l.tag = Tag(Pending{CMD_LED, hi, 0, 0});
                Out o{CMD_LED, std::vector<uint8_t>(sizeof(l))};
                memcpy(o.body.data(), &l, sizeof(l));
                out.push_back(std::move(o));
            }
            int st = h.led->state();
            bool fine = h.led->fine_track();
            if (st != h.led_logged_state || fine != h.led_logged_fine) {
                h.led_logged_state = st;
                h.led_logged_fine = fine;
                std::string seed;
                if (fine && h.led->seed_offset_us(now_s) != 0)
                    seed = ", centre - logged frame stamp " + std::to_string(int(std::lround(h.led->seed_offset_us(now_s)))) +
                           " us";
                Logf("radio: %s LED loop -> %s%s (centre %.0f us, drift %+.2f us/s, %d probes, %d sweeps%s)",
                     kHandName[hi], LedPhaseLoop::StateName(LedPhaseLoop::State(st)),
                     st == LedPhaseLoop::kTrack && !fine ? " (coarse)" : "", h.led->centre_at(now_s),
                     h.led->drift_us_per_s(), h.led->probes(), h.led->sweeps(), seed.c_str());
            }
        }
    }
    for (auto& o : out) Send(o.cmd, o.body.data(), o.body.size());
}

// ------------------------------------------------------------------------------- API

void RadioSource::SendHaptic(int hand, float amplitude, float frequency, float duration_s) {
    if (hand < 0 || hand > 1) return;
    std::lock_guard<std::mutex> lk(mu_);
    haptic_cmd_[hand] = hands_[hand].haptic.Request(HostNowNs() * 1e-9, amplitude, frequency, duration_s);
    haptic_due_[hand] = true;
}

void RadioSource::RequestPair(int hand, uint64_t device_id, int timeout_s) {
    if (hand < 0 || hand > 1) return;
    std::lock_guard<std::mutex> lk(mu_);
    pair_.pending = true;
    pair_.hand = hand;
    pair_.device_id = device_id;
    pair_.timeout_s = timeout_s > 0 ? timeout_s : 60;
}

void RadioSource::ObservePose(int hand, double t, bool valid) {
    if (hand < 0 || hand > 1) return;
    std::lock_guard<std::mutex> lk(mu_);
    if (hands_[hand].led) hands_[hand].led->Observe(t, valid);
}

void RadioSource::FrameTimestamp(double read_t, double frame_t) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& h : hands_)
        if (h.led) h.led->Seed(read_t, frame_t);
}

void RadioSource::LedStatsHit(int hand, double t) {
    if (hand < 0 || hand > 1) return;
    std::lock_guard<std::mutex> lk(mu_);
    if (hands_[hand].led) hands_[hand].led->LedHit(t);
}

RadioSource::HandStatus RadioSource::hand_status(int hand) const {
    HandStatus s;
    if (hand < 0 || hand > 1) return s;
    std::lock_guard<std::mutex> lk(mu_);
    const Hand& h = hands_[hand];
    s.connected = h.connected;
    s.device_id = h.device_id;
    s.slot = h.slot;
    s.inputs = h.inputs, s.imu = h.imu, s.gaps = h.gaps, s.unsynced = h.unsynced;
    s.scale = h.scale;
    if (h.led) {
        s.led_state = h.led->state();
        s.led_centre_us = h.led->centre_us();
        s.led_width_us = h.led->width_us();
        s.led_drift = h.led->drift_us_per_s();
    }
    return s;
}

RadioSource::LinkStatus RadioSource::link_status() const {
    std::lock_guard<std::mutex> lk(mu_);
    return link_;
}

}  // namespace radio
}  // namespace tf
