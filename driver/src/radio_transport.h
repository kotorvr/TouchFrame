// Byte-stream transports to the dongle. The link itself (COBS frames, radio_link.h) is the same
// on all of them:
//   hidraw  the Steam Frame: /dev/hidrawN of the dongle's vendor HID interface (VID:PID 1209:0001),
//           0664 root:input, and steamos is in input, so no udev rule (docs/re/DEV-1.md §5). The
//           COBS stream rides in 64-byte reports (radio_link.h HidPack).
//   tcp     tools/fake_dongle.py --tcp PORT (tests), raw COBS stream.
//   tcphid  the HID framing over TCP (driver/test/fake_dongle_server.py --framing hid).
// One thread uses a transport at a time.
#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tf {
namespace radio {

class Transport {
public:
    virtual ~Transport() = default;
    virtual bool Open(std::string* err) = 0;
    virtual void Close() = 0;
    // Stream bytes into buf: > 0 bytes read, 0 on timeout, < 0 when the device/connection is gone.
    virtual int Read(uint8_t* buf, size_t cap, int timeout_ms) = 0;
    virtual bool Write(const uint8_t* stream, size_t n) = 0;
    virtual std::string Describe() const = 0;
    virtual bool IsHid() const { return false; }
};

// "hidraw" (find the dongle), "hidraw:/dev/hidraw3", "tcp:HOST:PORT" or "tcphid:HOST:PORT".
// Null + err if malformed.
std::unique_ptr<Transport> MakeTransport(const std::string& spec, std::string* err);

// The /dev/hidrawN whose HID_ID (in <sysfs>/hidrawN/device/uevent) is bus:VID:PID, or "" with
// `why` saying what was seen. dev_dir is where the nodes live.
std::string FindHidraw(uint16_t vid, uint16_t pid, std::string* why, const std::string& sysfs = "/sys/class/hidraw",
                       const std::string& dev_dir = "/dev");

}  // namespace radio
}  // namespace tf
