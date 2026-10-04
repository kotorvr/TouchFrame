#include "radio_transport.h"

#include <dirent.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "radio_link.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tf {
namespace radio {

std::string FindHidraw(uint16_t vid, uint16_t pid, std::string* why, const std::string& sysfs,
                       const std::string& dev_dir) {
    DIR* d = opendir(sysfs.c_str());
    if (!d) {
        if (why) *why = sysfs + " not readable (no hidraw support?)";
        return "";
    }
    std::vector<std::string> names;
    while (dirent* e = readdir(d))
        if (strncmp(e->d_name, "hidraw", 6) == 0) names.push_back(e->d_name);
    closedir(d);
    std::sort(names.begin(), names.end(), [](const std::string& a, const std::string& b) {
        return a.size() != b.size() ? a.size() < b.size() : a < b;  // hidraw2 before hidraw10
    });
    std::string seen;
    for (const std::string& n : names) {
        std::ifstream f(sysfs + "/" + n + "/device/uevent");
        std::string line;
        while (std::getline(f, line)) {
            unsigned bus = 0, v = 0, p = 0;
            if (line.compare(0, 7, "HID_ID=") != 0 || sscanf(line.c_str() + 7, "%x:%x:%x", &bus, &v, &p) != 3) continue;
            char id[32];
            snprintf(id, sizeof(id), "%04x:%04x", v, p);
            seen += (seen.empty() ? "" : ", ") + n + "=" + id;
            if (v == vid && p == pid) return dev_dir + "/" + n;
        }
    }
    if (why) {
        char want[16];
        snprintf(want, sizeof(want), "%04x:%04x", vid, pid);
        *why = "no hidraw device " + std::string(want) + (seen.empty() ? " (no hidraw devices)" : " (seen: " + seen + ")");
    }
    return "";
}

#ifndef _WIN32
// ---------------------------------------------------------------------------------- hidraw
class HidrawTransport : public Transport {
public:
    explicit HidrawTransport(std::string path) : path_(std::move(path)) {}
    ~HidrawTransport() override { Close(); }
    bool Open(std::string* err) override {
        std::string path = path_;
        if (path.empty()) {
            path = FindHidraw(kUsbVid, kUsbPid, err);
            if (path.empty()) return false;
        }
        fd_ = open(path.c_str(), O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fd_ < 0) {
            *err = path + ": " + strerror(errno) + (errno == EACCES ? " (is the user in group input?)" : "");
            return false;
        }
        opened_ = path;
        return true;
    }
    void Close() override {
        if (fd_ >= 0) close(fd_);
        fd_ = -1;
    }
    int Read(uint8_t* buf, size_t cap, int timeout_ms) override {
        if (fd_ < 0) return -1;
        pollfd p{fd_, POLLIN, 0};
        int r = poll(&p, 1, timeout_ms);
        if (r == 0) return 0;
        if (r < 0) return errno == EINTR ? 0 : -1;
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
        uint8_t rep[kHidReport + 1];
        ssize_t n = read(fd_, rep, sizeof(rep));
        if (n < 0) return errno == EAGAIN || errno == EINTR ? 0 : -1;  // ENODEV: unplugged
        const uint8_t* payload;
        size_t len;
        if (!HidUnpack(rep, size_t(n), &payload, &len)) return 0;  // not ours / garbage: skip
        len = std::min(len, cap);
        memcpy(buf, payload, len);
        return int(len);
    }
    bool Write(const uint8_t* stream, size_t n) override {
        if (fd_ < 0) return false;
        reports_.clear();
        HidPack(stream, n, &reports_);
        for (size_t off = 0; off < reports_.size(); off += kHidReport) {
            uint8_t out[kHidReport + 1];
            out[0] = 0;  // no report IDs: hidraw wants a leading 0
            memcpy(out + 1, reports_.data() + off, kHidReport);
            for (int tries = 0;; tries++) {
                ssize_t w = write(fd_, out, sizeof(out));
                if (w == ssize_t(sizeof(out))) break;
                if (w < 0 && (errno == EAGAIN || errno == EINTR) && tries < 50) {
                    pollfd p{fd_, POLLOUT, 0};
                    poll(&p, 1, 2);
                    continue;
                }
                return false;
            }
        }
        return true;
    }
    std::string Describe() const override { return "hidraw " + (opened_.empty() ? path_ : opened_); }
    bool IsHid() const override { return true; }

private:
    std::string path_, opened_;
    int fd_ = -1;
    std::vector<uint8_t> reports_;
};
#endif

// ---------------------------------------------------------------------------------- tcp
#ifdef _WIN32
using sock_t = SOCKET;
static const sock_t kNoSock = INVALID_SOCKET;
static void CloseSock(sock_t s) { closesocket(s); }
static bool WouldBlock() { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
using sock_t = int;
static const sock_t kNoSock = -1;
static void CloseSock(sock_t s) { close(s); }
static bool WouldBlock() { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
#endif

// tcp: the raw COBS stream. tcphid: hidraw's view of the HID interface tunnelled over TCP (65-byte
// writes, 64-byte reports), so tests exercise the HID framing against fake_dongle --framing hid.
class TcpTransport : public Transport {
public:
    TcpTransport(std::string host, std::string port, bool hid)
        : host_(std::move(host)), port_(std::move(port)), hid_(hid) {
#ifdef _WIN32
        static bool wsa = [] {
            WSADATA w;
            return WSAStartup(MAKEWORD(2, 2), &w) == 0;
        }();
        (void)wsa;
#endif
    }
    ~TcpTransport() override { Close(); }
    bool Open(std::string* err) override {
        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host_.c_str(), port_.c_str(), &hints, &res) != 0 || !res) {
            *err = "can't resolve " + host_ + ":" + port_;
            return false;
        }
        s_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        bool ok = s_ != kNoSock && connect(s_, res->ai_addr, int(res->ai_addrlen)) == 0;
        freeaddrinfo(res);
        if (!ok) {
            *err = "can't connect to " + host_ + ":" + port_;
            Close();
            return false;
        }
        int one = 1;
        setsockopt(s_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
        return true;
    }
    void Close() override {
        if (s_ != kNoSock) CloseSock(s_);
        s_ = kNoSock;
    }
    int Read(uint8_t* buf, size_t cap, int timeout_ms) override {
        if (!hid_) return ReadRaw(buf, cap, timeout_ms);
        while (rep_.size() < kHidReport) {
            uint8_t tmp[4096];
            int n = ReadRaw(tmp, sizeof(tmp), rep_.empty() ? timeout_ms : 5);
            if (n <= 0) return n;
            rep_.insert(rep_.end(), tmp, tmp + n);
        }
        const uint8_t* payload;
        size_t len = 0;
        bool ok = HidUnpack(rep_.data(), kHidReport, &payload, &len);
        len = ok ? std::min(len, cap) : 0;
        if (len) memcpy(buf, payload, len);
        rep_.erase(rep_.begin(), rep_.begin() + kHidReport);
        return int(len);
    }
    bool Write(const uint8_t* data, size_t n) override {
        if (!hid_) return WriteRaw(data, n);
        std::vector<uint8_t> reports, out;
        HidPack(data, n, &reports);
        for (size_t off = 0; off < reports.size(); off += kHidReport) {
            out.push_back(0);
            out.insert(out.end(), reports.begin() + off, reports.begin() + off + kHidReport);
        }
        return WriteRaw(out.data(), out.size());
    }
    std::string Describe() const override { return std::string(hid_ ? "tcphid " : "tcp ") + host_ + ":" + port_; }
    bool IsHid() const override { return hid_; }

private:
    int ReadRaw(uint8_t* buf, size_t cap, int timeout_ms) {
        if (s_ == kNoSock) return -1;
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(s_, &rd);
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        int r = select(int(s_) + 1, &rd, nullptr, nullptr, &tv);
        if (r == 0) return 0;
        if (r < 0) return WouldBlock() ? 0 : -1;
        int n = int(recv(s_, reinterpret_cast<char*>(buf), int(cap), 0));
        if (n == 0) return -1;  // peer closed
        if (n < 0) return WouldBlock() ? 0 : -1;
        return n;
    }
    bool WriteRaw(const uint8_t* data, size_t n) {
        size_t off = 0;
        while (off < n && s_ != kNoSock) {
            int w = int(send(s_, reinterpret_cast<const char*>(data) + off, int(n - off), 0));
            if (w <= 0) {
                if (w < 0 && WouldBlock()) continue;
                return false;
            }
            off += size_t(w);
        }
        return off == n;
    }
    std::string host_, port_;
    bool hid_;
    sock_t s_ = kNoSock;
    std::vector<uint8_t> rep_;
};

std::unique_ptr<Transport> MakeTransport(const std::string& spec, std::string* err) {
    if (spec == "hidraw" || spec.compare(0, 7, "hidraw:") == 0) {
#ifdef _WIN32
        *err = "hidraw is Linux-only";
        return nullptr;
#else
        return std::unique_ptr<Transport>(new HidrawTransport(spec.size() > 7 ? spec.substr(7) : ""));
#endif
    }
    bool hid = spec.compare(0, 7, "tcphid:") == 0;
    if (hid || spec.compare(0, 4, "tcp:") == 0) {
        size_t start = hid ? 7 : 4, c = spec.rfind(':');
        if (c <= start) {
            *err = "tcp transport needs tcp:HOST:PORT";
            return nullptr;
        }
        return std::unique_ptr<Transport>(new TcpTransport(spec.substr(start, c - start), spec.substr(c + 1), hid));
    }
    *err = "unknown transport '" + spec + "' (hidraw, hidraw:/dev/hidrawN, tcp:HOST:PORT, tcphid:HOST:PORT)";
    return nullptr;
}

}  // namespace radio
}  // namespace tf
