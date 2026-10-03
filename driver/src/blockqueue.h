// SteamVR-internal block-queue and path interfaces, plus the XRService controller block layouts.
//
// None of this is in the public openvr_driver.h. The C function tables for IVRBlockQueue_005 and
// IVRPaths_002 *are* published in Valve's openvr_capi.h / openvr_api.json (v1.23+), and the
// declarations below follow that published method order and argument lists. Every slot was
// then checked against the Steam Frame's own vrserver (SteamVR 2026-10-01, linuxarm64): vtable
// addresses are ELF vaddrs in that vrserver (Ghidra address = vaddr + 0x100000). See
// docs/FRAME-TRACKER.md, "IVRBlockQueue interface (verified)".
//
// ABI rules that matter (a wrong slot crashes vrserver):
//  - These are pure interfaces with NO virtual destructor. Do not add one; it would shift slots.
//  - Do not reorder methods. Slot offsets are pinned with comments and checked by Valve's own
//    callers (driver_cv.so, XRService) as noted.
//  - IVRBlockQueue_005 is the only version we call. _004/_003 are declared for completeness, in
//    case a future runtime drops _005; they are NOT slot-compatible with _005.
//
// Tags: CONFIRMED = read directly from the binaries; INFERRED = strongly implied, not yet tested.
#pragma once

#include <cstddef>
#include <cstdint>

#include <openvr_driver.h>  // vr::PropertyContainerHandle_t, vr::ETrackedPropertyError, tags

namespace tf {
namespace vrint {

using vr::PropertyContainerHandle_t;
using vr::PropertyTypeTag_t;
using vr::ETrackedPropertyError;

// Queue and block handles are both 64-bit PropertyContainerHandle_t. A block handle is also a
// property container: per-block metadata is attached to it through IVRPaths (CONFIRMED, see the
// event-block notes below).
using BlockQueueHandle_t = PropertyContainerHandle_t;
using BlockHandle_t = PropertyContainerHandle_t;
using PathHandle_t = uint64_t;

static const char* const IVRBlockQueue_Version = "IVRBlockQueue_005";
static const char* const IVRBlockQueue_Version_004 = "IVRBlockQueue_004";
static const char* const IVRBlockQueue_Version_003 = "IVRBlockQueue_003";
static const char* const IVRPaths_Version = "IVRPaths_002";

// Values from openvr_capi.h; CONFIRMED in use: vrserver Create returns 5/7/8/9 on its error paths
// (vaddr 0x260420, 0x260460, 0x26043c, 0x260480).
enum EBlockQueueError : int32_t {
    BlockQueueError_None = 0,
    BlockQueueError_QueueAlreadyExists = 1,
    BlockQueueError_QueueNotFound = 2,
    BlockQueueError_BlockNotAvailable = 3,
    BlockQueueError_InvalidHandle = 4,
    BlockQueueError_InvalidParam = 5,
    BlockQueueError_ParamMismatch = 6,
    BlockQueueError_InternalError = 7,
    BlockQueueError_AlreadyInitialized = 8,
    BlockQueueError_OperationIsServerOnly = 9,
    BlockQueueError_TooManyConnections = 10,
};

// Values from openvr_capi.h. In use on the Frame: driver_cv reads poses with New (1);
// XRService reads the IMU and event queues with Next (2). Semantics INFERRED from the names:
// Latest = newest block (may repeat), New = newest block only if not yet read, Next = FIFO.
enum EBlockQueueReadType : int32_t {
    BlockQueueRead_Latest = 0,
    BlockQueueRead_New = 1,
    BlockQueueRead_Next = 2,
};

// Create() flags. driver_cv passes OwnerIsReader for the per-device pose queue (the creator
// reads, XRService connects and writes) and 0 for the data/event queues (creator writes).
enum EBlockQueueCreationFlag : uint32_t {
    BlockQueueFlag_OwnerIsReader = 1,
};

// ---------------------------------------------------------------------------------------------
// IVRBlockQueue_005. Implementation in vrserver: CVRBlockQueueManager (typeinfo 0x5d0a38, derives
// from vr::IVRBlockQueue), vtable address point 0x5c35e8, exactly 9 slots, no destructor.
// Argument registers below were checked per slot (x0 = this).
class IVRBlockQueue {
public:
    // slot 0, +0x00, impl 0x260820 (x1,x2,w3,w4,w5,w6). Validation in CBlockQueue init 0x25ff28:
    // 1 <= unBlockCount <= 128 and unBlockDataSize != 0 (else InvalidParam), unBlockHeaderSize >= 16
    // (else InvalidParam). Server-process only (OperationIsServerOnly otherwise).
    // driver_cv uses (dataSize, 0x200, 4, flags) for all three controller queues.
    virtual EBlockQueueError Create(BlockQueueHandle_t* pulQueueHandle, const char* pchPath,
                                    uint32_t unBlockDataSize, uint32_t unBlockHeaderSize,
                                    uint32_t unBlockCount, uint32_t unFlags) = 0;
    // slot 1, +0x08, impl 0x261af8 (x1,x2).
    virtual EBlockQueueError Connect(BlockQueueHandle_t* pulQueueHandle, const char* pchPath) = 0;
    // slot 2, +0x10, impl 0x25fc08 (x1).
    virtual EBlockQueueError Destroy(BlockQueueHandle_t ulQueueHandle) = 0;
    // slot 3, +0x18, impl 0x25f5b0 (x1,x2,x3). Block pointer is valid until ReleaseWriteOnlyBlock.
    virtual EBlockQueueError AcquireWriteOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                   BlockHandle_t* pulBlockHandle,
                                                   void** ppvBuffer) = 0;
    // slot 4, +0x20, impl 0x2611e0 (x1,x2). Publishes the block.
    virtual EBlockQueueError ReleaseWriteOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                   BlockHandle_t ulBlockHandle) = 0;
    // slot 5, +0x28, impl 0x25fa30 (x1,x2,x3,w4,w5).
    virtual EBlockQueueError WaitAndAcquireReadOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                         BlockHandle_t* pulBlockHandle,
                                                         void** ppvBuffer,
                                                         EBlockQueueReadType eReadType,
                                                         uint32_t unTimeoutMs) = 0;
    // slot 6, +0x30, impl 0x25f930 (x1,x2,x3,w4). Non-blocking variant.
    virtual EBlockQueueError AcquireReadOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                  BlockHandle_t* pulBlockHandle, void** ppvBuffer,
                                                  EBlockQueueReadType eReadType) = 0;
    // slot 7, +0x38, impl 0x25eec8 (x1,x2).
    virtual EBlockQueueError ReleaseReadOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                  BlockHandle_t ulBlockHandle) = 0;
    // slot 8, +0x40, impl 0x25ec28 (x1,x2).
    virtual EBlockQueueError QueueHasReader(BlockQueueHandle_t ulQueueHandle,
                                            bool* pbHasReaders) = 0;
};

// IVRBlockQueue_004: vrserver wrapper class CVRBlockQueue_004, vtable 0x5c0ec0, 9 slots. Same as
// _005 except Create has no unFlags (the wrapper at 0x771e0 forwards to _005 Create with
// unFlags = 0). Matches openvr_capi.h v1.12-v1.16.
class IVRBlockQueue_004 {
public:
    virtual EBlockQueueError Create(BlockQueueHandle_t* pulQueueHandle, const char* pchPath,
                                    uint32_t unBlockDataSize, uint32_t unBlockHeaderSize,
                                    uint32_t unBlockCount) = 0;
    virtual EBlockQueueError Connect(BlockQueueHandle_t* pulQueueHandle, const char* pchPath) = 0;
    virtual EBlockQueueError Destroy(BlockQueueHandle_t ulQueueHandle) = 0;
    virtual EBlockQueueError AcquireWriteOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                   BlockHandle_t* pulBlockHandle,
                                                   void** ppvBuffer) = 0;
    virtual EBlockQueueError ReleaseWriteOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                   BlockHandle_t ulBlockHandle) = 0;
    virtual EBlockQueueError WaitAndAcquireReadOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                         BlockHandle_t* pulBlockHandle,
                                                         void** ppvBuffer,
                                                         EBlockQueueReadType eReadType,
                                                         uint32_t unTimeoutMs) = 0;
    virtual EBlockQueueError AcquireReadOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                  BlockHandle_t* pulBlockHandle, void** ppvBuffer,
                                                  EBlockQueueReadType eReadType) = 0;
    virtual EBlockQueueError ReleaseReadOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                  BlockHandle_t ulBlockHandle) = 0;
    virtual EBlockQueueError QueueHasReader(BlockQueueHandle_t ulQueueHandle,
                                            bool* pbHasReaders) = 0;
};

// IVRBlockQueue_003: wrapper CVRBlockQueue_003, vtable 0x5c0f48, 8 slots. Like _004 but with no
// Destroy (wrappers 0x77b88 0x77a08 0x77af8 0x77a20 0x77b58 0x77b40 0x77a38 0x779f0 forward to
// _005 slots 0,1,3,4,5,6,7,8). Not in any public header; reconstructed from those wrappers only.
class IVRBlockQueue_003 {
public:
    virtual EBlockQueueError Create(BlockQueueHandle_t* pulQueueHandle, const char* pchPath,
                                    uint32_t unBlockDataSize, uint32_t unBlockHeaderSize,
                                    uint32_t unBlockCount) = 0;
    virtual EBlockQueueError Connect(BlockQueueHandle_t* pulQueueHandle, const char* pchPath) = 0;
    virtual EBlockQueueError AcquireWriteOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                   BlockHandle_t* pulBlockHandle,
                                                   void** ppvBuffer) = 0;
    virtual EBlockQueueError ReleaseWriteOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                   BlockHandle_t ulBlockHandle) = 0;
    virtual EBlockQueueError WaitAndAcquireReadOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                         BlockHandle_t* pulBlockHandle,
                                                         void** ppvBuffer,
                                                         EBlockQueueReadType eReadType,
                                                         uint32_t unTimeoutMs) = 0;
    virtual EBlockQueueError AcquireReadOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                  BlockHandle_t* pulBlockHandle, void** ppvBuffer,
                                                  EBlockQueueReadType eReadType) = 0;
    virtual EBlockQueueError ReleaseReadOnlyBlock(BlockQueueHandle_t ulQueueHandle,
                                                  BlockHandle_t ulBlockHandle) = 0;
    virtual EBlockQueueError QueueHasReader(BlockQueueHandle_t ulQueueHandle,
                                            bool* pbHasReaders) = 0;
};

// ---------------------------------------------------------------------------------------------
// IVRPaths_002 (needed to attach the blockDataSize properties to an event block). Published in
// openvr_capi.h master. Slot order CONFIRMED by vrserver's CVRPaths_001 compat wrapper (vtable
// 0x5c0df8): its four entries forward to _002 slots +0x00 (3 args), +0x08 (3 args; the wrapper
// widens each 0x30-byte v001 PathWrite_t to a 0x38-byte v002 one with bPostEvents = 1),
// +0x10 (2 args), +0x18 (4 args).
enum EPropertyWriteType : int32_t {
    PropertyWrite_Set = 0,
    PropertyWrite_Erase = 1,
    PropertyWrite_SetError = 2,
};

struct PathWrite_t {
    PathHandle_t ulPath;                 // 0x00
    EPropertyWriteType writeType;        // 0x08
    ETrackedPropertyError eSetError;     // 0x0c
    void* pvBuffer;                      // 0x10
    uint32_t unBufferSize;               // 0x18
    PropertyTypeTag_t unTag;             // 0x1c
    ETrackedPropertyError eError;        // 0x20 (out)
    const char* pszPath;                 // 0x28 (optional, may be null)
    bool bPostEvents;                    // 0x30 (driver_cv sets 1)
    bool bValueChanged;                  // 0x31 (out)
};

struct PathRead_t {
    PathHandle_t ulPath;                 // 0x00
    void* pvBuffer;                      // 0x08
    uint32_t unBufferSize;               // 0x10
    PropertyTypeTag_t unTag;             // 0x14 (out)
    uint32_t unRequiredBufferSize;       // 0x18 (out)
    ETrackedPropertyError eError;        // 0x1c (out)
    const char* pszPath;                 // 0x20
};

class IVRPaths {
public:
    virtual ETrackedPropertyError ReadPathBatch(PropertyContainerHandle_t ulRootHandle,
                                                PathRead_t* pBatch, uint32_t unBatchEntryCount) = 0;
    virtual ETrackedPropertyError WritePathBatch(PropertyContainerHandle_t ulRootHandle,
                                                 PathWrite_t* pBatch,
                                                 uint32_t unBatchEntryCount) = 0;
    virtual ETrackedPropertyError StringToHandle(PathHandle_t* pHandle, const char* pchPath) = 0;
    virtual ETrackedPropertyError HandleToString(PathHandle_t pHandle, char* pchBuffer,
                                                 uint32_t unBufferSize,
                                                 uint32_t* punBufferSizeUsed) = 0;
};

// ---------------------------------------------------------------------------------------------
// XRService controller queues (names, sizes and creation parameters as driver_cv uses them,
// driver_cv FUN_001d9a40). All three use unBlockHeaderSize 0x200 and unBlockCount 4.
static const char* const kControllerEventQueue = "/xrservice/controller/event";
static const char* const kControllerDataQueue = "/xrservice/controller/data";
// Per device: "/xrservice/controller_<deviceId>/pose", deviceId in decimal.
static const char* const kControllerPoseQueuePrefix = "/xrservice/controller_";
static const char* const kControllerPoseQueueSuffix = "/pose";
static const uint32_t kControllerQueueHeaderSize = 0x200;
static const uint32_t kControllerQueueBlockCount = 4;

// Event block, data size 0x6010. Writer: driver_cv FUN_001dfe78; reader: XRService 0xf29cf0.
// After AcquireWriteOnlyBlock and BEFORE ReleaseWriteOnlyBlock, the writer must set two uint64
// properties (tag k_unUint64PropertyTag, 8 bytes) on the BLOCK handle via IVRPaths::WritePathBatch:
//   kOnboardConfigSizePath = strlen(onboardConfig), kDefaultConfigSizePath = strlen(defaultConfig).
// XRService copies exactly that many bytes of each string; if a property is missing or not
// tag 3, it uses length 0 (an empty config). CONFIRMED on both sides.
static const char* const kOnboardConfigSizePath = "/controllerOnboardConfigData/blockDataSize";
static const char* const kDefaultConfigSizePath = "/controllerDefaultConfigData/blockDataSize";
// Also written by driver_cv (string, tag 5) when known; XRService does not reference it.
static const char* const kConfigSerialPath = "/controllerConfigData/deviceSerialNumber";

enum EControllerEventType : uint32_t {
    ControllerEvent_Disconnect = 0,
    ControllerEvent_Connect = 1,  // XRService only parses the config strings for type 1
};

static const size_t kControllerConfigMax = 0x3000;

struct ControllerEventBlock {
    uint32_t deviceId;                    // 0x00 CONFIRMED
    uint32_t eventType;                   // 0x04 CONFIRMED (EControllerEventType)
    uint64_t hardwareId;                  // 0x08 CONFIRMED (XRService logs it as the controller's
                                          //      "hardware ID"; driver_cv copies it from its radio
                                          //      controller object. Write our own unique value)
    char onboardConfig[kControllerConfigMax];  // 0x10   JSON, length via kOnboardConfigSizePath
    char defaultConfig[kControllerConfigMax];  // 0x3010 JSON, length via kDefaultConfigSizePath
};

// IMU sample block, data size 0x30. Writer: driver_cv FUN_001d44d8 (writes only while
// QueueHasReader); reader: XRService 0xf29b20 (Next, 1 ms) -> 0xf2a460.
struct ControllerImuBlock {
    uint32_t deviceId;                    // 0x00 CONFIRMED
    uint32_t reserved04;                  // 0x04 not written by driver_cv; write 0
    double sampleTime;                    // 0x08 CONFIRMED seconds, same clock as pose timestamp
    float accel[3];                       // 0x10 CONFIRMED offset; INFERRED accel, m/s^2
                                          //      (XRService negates it on read)
    float gyro[3];                        // 0x1c CONFIRMED offset; INFERRED gyro, rad/s
    uint32_t flags;                       // 0x28 CONFIRMED offset; INFERRED off-scale flags
    uint32_t reserved2c;                  // 0x2c write 0
};

// Pose block, data size 0x90. Writer: XRService 0xeb36f0 (writes only while QueueHasReader);
// reader: driver_cv FUN_001d4760 (New, 100 ms) -> FUN_001d9e60.
struct ControllerPoseBlock {
    uint32_t deviceId;                    // 0x00 CONFIRMED
    uint8_t unknown04;                    // 0x04 UNKNOWN (a flag byte; driver_cv ignores it)
    uint8_t reserved05[3];                // 0x05
    double timestamp;                     // 0x08 CONFIRMED; -1.0 = no valid pose (tracking lost)
    double qw, qx, qy, qz;                // 0x10 CONFIRMED orientation quaternion, w first
    double position[3];                   // 0x30 CONFIRMED; INFERRED metres
    double velocity[3];                   // 0x48 CONFIRMED linear velocity; INFERRED m/s
    double angularVelocity[3];            // 0x60 CONFIRMED (NaN replaced by 0); INFERRED rad/s,
                                          //      body frame (driver_cv does not rotate it)
    double unknown78[3];                  // 0x78 UNKNOWN 3-vector; driver_cv ignores it
};
// When timestamp == -1.0 only deviceId and timestamp are meaningful: the invalid-pose writers at
// XRService 0xeb2170/0xec0d30/0xec1640 fill those two fields and leave the rest uninitialised.

static_assert(sizeof(PathWrite_t) == 0x38, "IVRPaths_002 PathWrite_t");
static_assert(offsetof(PathWrite_t, pszPath) == 0x28, "PathWrite_t.pszPath");
static_assert(offsetof(PathWrite_t, bPostEvents) == 0x30, "PathWrite_t.bPostEvents");
static_assert(sizeof(PathRead_t) == 0x28, "PathRead_t");
static_assert(offsetof(PathRead_t, eError) == 0x1c, "PathRead_t.eError");
static_assert(sizeof(ControllerEventBlock) == 0x6010, "event block");
static_assert(offsetof(ControllerEventBlock, defaultConfig) == 0x3010, "event.defaultConfig");
static_assert(sizeof(ControllerImuBlock) == 0x30, "IMU block");
static_assert(offsetof(ControllerImuBlock, gyro) == 0x1c, "IMU.gyro");
static_assert(offsetof(ControllerImuBlock, flags) == 0x28, "IMU.flags");
static_assert(sizeof(ControllerPoseBlock) == 0x90, "pose block");
static_assert(offsetof(ControllerPoseBlock, qw) == 0x10, "pose.qw");
static_assert(offsetof(ControllerPoseBlock, position) == 0x30, "pose.position");
static_assert(offsetof(ControllerPoseBlock, angularVelocity) == 0x60, "pose.angularVelocity");

}  // namespace vrint
}  // namespace tf
