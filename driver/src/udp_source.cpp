#include "source.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <cstring>

#include "log.h"

namespace tf {

uint64_t MonotonicNs() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ull + uint64_t(ts.tv_nsec);
}

bool UdpSource::Start() {
    fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        Log("udp: socket failed: %s", strerror(errno));
        return false;
    }
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    timeval tv{0, 100000};  // wake every 100 ms to notice Stop()
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port_);
    if (bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        Log("udp: bind port %u failed: %s", port_, strerror(errno));
        close(fd_);
        fd_ = -1;
        return false;
    }
    running_ = true;
    thread_ = std::thread(&UdpSource::Loop, this);
    Log("udp: listening on port %u", port_);
    return true;
}

void UdpSource::Stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
    if (fd_ >= 0) close(fd_);
    fd_ = -1;
}

void UdpSource::Loop() {
    StatePacket pkt;
    while (running_) {
        sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(fd_, &pkt, sizeof(pkt), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n != sizeof(StatePacket) || pkt.magic != kStateMagic) continue;
        uint64_t now = MonotonicNs();

        if (!have_peer_ || from.sin_addr.s_addr != peer_.sin_addr.s_addr || from.sin_port != peer_.sin_port) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
            Log("udp: source %s:%u", ip, ntohs(from.sin_port));
            peer_ = from;
            have_peer_ = true;
            last_seq_ = pkt.seq - 1;
        }
        // Drop reordered packets; a newer pose already went out.
        if (int32_t(pkt.seq - last_seq_) <= 0) continue;
        last_seq_ = pkt.seq;
        cb_(pkt, now);
    }
}

void UdpSource::SendHaptic(int hand, float amplitude, float frequency, float duration_s) {
    if (!have_peer_ || fd_ < 0) return;
    HapticPacket h{};
    h.magic = kHapticMagic;
    h.hand = uint8_t(hand);
    h.amplitude = amplitude;
    h.frequency = frequency;
    h.duration_s = duration_s;
    sendto(fd_, &h, sizeof(h), 0, reinterpret_cast<const sockaddr*>(&peer_), sizeof(peer_));
}

}  // namespace tf
