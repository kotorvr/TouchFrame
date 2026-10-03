// Hand skeleton for /input/skeleton/left|right, estimated from Touch Plus buttons and touches
// (no finger tracking on the controller): trigger and its cap sensor curl the index, grip
// curls middle/ring/pinky, any thumb surface (A/B/X/Y, stick, thumbrest) lowers the thumb.
//
// Finger poses come from SteamVR's own open->fist animation (resources/anims/
// hand_right_closeanim.glb), read from the SteamVR install at runtime so nothing of
// Valve's ships with TouchFrame. Each finger plays it at its own curl, converted to
// OpenVR bone space and mirrored for the left hand.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "protocol.h"

namespace tf {

constexpr int kBoneCount = 31;  // OpenVR hand skeleton (HandSkeletonBone)

// Same layout as vr::VRBoneTransform_t: position (x, y, z, 1) and orientation (w, x, y, z),
// parent space.
struct Bone {
    float pos[4];
    float rot[4];
};

// The curl animation, shared by both hands.
class CurlAnimation {
public:
    // steamvr_root: SteamVR install dir (empty: work it out from /proc/self/exe).
    bool Load(const std::string& steamvr_root, std::string* err);
    bool Loaded() const { return !times_.empty(); }
    // Bones of the right hand in OpenVR space, finger f (0 thumb .. 4 pinky) at curl[f] (0 open, 1 fist).
    void SampleRight(const float curl[5], Bone out[kBoneCount]) const;
    const std::string& Path() const { return path_; }

private:
    struct Track {
        std::vector<float> t3;  // translation keys, xyz
        std::vector<float> q4;  // rotation keys, wxyz
    };
    std::vector<float> times_;
    Track track_[kBoneCount];
    std::string path_;
};

// Converts a right-hand pose (OpenVR space) to the left hand in place.
void MirrorToLeft(Bone b[kBoneCount]);

class HandPoser {
public:
    explicit HandPoser(int hand) : hand_(hand) {}
    // Sets the target curls from the controller state and moves toward them (dt seconds).
    void Update(const CurlAnimation& anim, const HandState& s, double dt);
    const Bone* WithController() const { return with_; }
    const Bone* WithoutController() const { return without_; }

private:
    int hand_;
    bool first_ = true;
    float curl_with_[5] = {}, curl_without_[5] = {};
    Bone with_[kBoneCount], without_[kBoneCount];
};

}  // namespace tf
