// TouchFrame wire protocol: Touch Plus state sources -> Frame driver, haptics back.
// Shared by the SteamVR driver, the Quest bridge APK, and tools/sim_sender.py.
// Little-endian, packed, UDP. Keep tools/sim_sender.py and quest-bridge in sync.
#pragma once
#include <stdint.h>

namespace tf {

constexpr uint16_t kDefaultPort = 28430;
constexpr uint32_t kStateMagic = 0x31524654;   // "TFR1"
constexpr uint32_t kHapticMagic = 0x31484654;  // "TFH1"
constexpr uint32_t kHeartbeatMagic = 0x31424654;  // "TFB1"

enum HandFlags : uint8_t {
    kConnected = 1 << 0,
    kOrientationValid = 1 << 1,
    kPositionValid = 1 << 2,
    kOrientationTracked = 1 << 3,
    kPositionTracked = 1 << 4,
};

// Bit layout matches Touch Plus: A/X is the lower face button, B/Y the upper.
enum Buttons : uint16_t {
    kBtnLowerClick = 1 << 0,   // A (right) / X (left)
    kBtnUpperClick = 1 << 1,   // B / Y
    kBtnSystemClick = 1 << 2,  // Menu (left); Meta button is reserved by the OS on Quest
    kBtnStickClick = 1 << 3,
    kBtnLowerTouch = 1 << 4,
    kBtnUpperTouch = 1 << 5,
    kBtnStickTouch = 1 << 6,
    kBtnThumbrestTouch = 1 << 7,
    kBtnTriggerTouch = 1 << 8,
    kBtnGripTouch = 1 << 9,    // Touch Plus has no grip cap sensor; derived from value
};

#pragma pack(push, 1)
struct HandState {
    uint8_t flags;
    uint8_t battery;      // 0-100, 255 unknown
    uint16_t buttons;
    float trigger, grip, stick_x, stick_y;
    float pos[3];         // metres, source tracking space
    float rot[4];         // quaternion x, y, z, w
    float lin_vel[3];     // m/s
    float ang_vel[3];     // rad/s
};

struct StatePacket {
    uint32_t magic;       // kStateMagic
    uint32_t seq;
    uint64_t source_time_ns;
    HandState hand[2];    // 0 left, 1 right
};

struct HapticPacket {
    uint32_t magic;       // kHapticMagic
    uint8_t hand;         // 0 left, 1 right
    uint8_t pad[3];
    float amplitude;      // 0-1
    float frequency;      // Hz, 0 = default
    float duration_s;
};
// Driver -> source about once a second: echoes the newest StatePacket so the source knows
// it's linked and can measure the round trip on its own clock.
struct HeartbeatPacket {
    uint32_t magic;       // kHeartbeatMagic
    uint32_t seq;         // StatePacket.seq echoed
    uint64_t source_time_ns;  // StatePacket.source_time_ns echoed
};
#pragma pack(pop)

static_assert(sizeof(HandState) == 72, "HandState layout");
static_assert(sizeof(StatePacket) == 160, "StatePacket layout");
static_assert(sizeof(HapticPacket) == 20, "HapticPacket layout");
static_assert(sizeof(HeartbeatPacket) == 16, "HeartbeatPacket layout");

}  // namespace tf
