// CvClone: step-1 validation of the camera-tracker route with no new hardware. Registers a clone
// of one of the user's real Steam Frame controllers with XRService under a new deviceId, using
// that controller's own config (LED model + IMU/head extrinsics) and an IMU stream synthesized
// from its SteamVR pose, then compares the poses XRService returns for the clone with the real
// controller's. Off unless driver_touchframe.cv_clone_serial is set. See docs/FRAME-TRACKER.md §9.
#pragma once
#include <memory>

namespace tf {

class CvClone {
public:
    virtual ~CvClone() = default;
    // Null when driver_touchframe.cv_clone_serial is empty or the config can't be loaded.
    static std::unique_ptr<CvClone> CreateFromSettings();
    virtual void Stop() = 0;
};

}  // namespace tf
