// Where Touch Plus state comes from. Phase 1: UDP relay from the Quest bridge APK
// (or tools/sim_sender.py). Later: the nRF52840 host radio and the camera tracker.
#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <thread>
#include <netinet/in.h>

#include "protocol.h"

namespace tf {

class ITouchSource {
public:
    virtual ~ITouchSource() = default;
    virtual bool Start() = 0;
    virtual void Stop() = 0;
    virtual void SendHaptic(int hand, float amplitude, float frequency, float duration_s) = 0;
};

using StateCallback = std::function<void(const StatePacket&, uint64_t recv_ns)>;

class UdpSource : public ITouchSource {
public:
    UdpSource(uint16_t port, StateCallback cb) : port_(port), cb_(std::move(cb)) {}
    ~UdpSource() override { Stop(); }
    bool Start() override;
    void Stop() override;
    void SendHaptic(int hand, float amplitude, float frequency, float duration_s) override;

private:
    void Loop();

    uint16_t port_;
    StateCallback cb_;
    int fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<bool> have_peer_{false};
    sockaddr_in peer_{};
    uint32_t last_seq_ = 0;
};

uint64_t MonotonicNs();

}  // namespace tf
