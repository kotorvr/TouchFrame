// tf_skeldump: checks the driver's hand skeleton from the client side.
//
//   tf_skeldump ref     compare skeleton.cpp's open hand / fist with SteamVR's own
//                       reference poses (should match to ~1e-4: same source animation)
//   tf_skeldump watch [seconds]
//                       live finger curl per hand (GetSkeletalSummaryData) and the device
//                       bound to each skeleton action
#include <openvr.h>

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <thread>

#include "skeleton.h"

namespace {

void WriteFile(const std::string& path, const std::string& text) {
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return;
    fputs(text.c_str(), f);
    fclose(f);
}

std::string Binding(const char* type) {
    return std::string("{\"controller_type\":\"") + type + "\",\"bindings\":{\"/actions/tf\":{\"skeleton\":["
           "{\"output\":\"/actions/tf/in/skel_left\",\"path\":\"/user/hand/left/input/skeleton/left\"},"
           "{\"output\":\"/actions/tf/in/skel_right\",\"path\":\"/user/hand/right/input/skeleton/right\"}],"
           "\"sources\":[],\"poses\":[],\"haptics\":[]}}}";
}

const char* kRefNames[] = {"bind", "open", "fist", "griplimit"};

}  // namespace

int main(int argc, char** argv) {
    std::string mode = argc > 1 ? argv[1] : "ref";
    double seconds = argc > 2 ? atof(argv[2]) : 20;

    std::string dir = "/tmp/tf_skeldump";
    mkdir(dir.c_str(), 0755);
    WriteFile(dir + "/bind_touch.json", Binding("oculus_touch"));
    WriteFile(dir + "/bind_frame.json", Binding("frame_controller"));
    WriteFile(dir + "/actions.json",
              "{\"default_bindings\":["
              "{\"controller_type\":\"oculus_touch\",\"binding_url\":\"bind_touch.json\"},"
              "{\"controller_type\":\"frame_controller\",\"binding_url\":\"bind_frame.json\"}],"
              "\"actions\":["
              "{\"name\":\"/actions/tf/in/skel_left\",\"type\":\"skeleton\",\"skeleton\":\"/skeleton/hand/left\"},"
              "{\"name\":\"/actions/tf/in/skel_right\",\"type\":\"skeleton\",\"skeleton\":\"/skeleton/hand/right\"}],"
              "\"action_sets\":[{\"name\":\"/actions/tf\",\"usage\":\"leftright\"}]}");

    vr::EVRInitError err = vr::VRInitError_None;
    vr::VR_Init(&err, vr::VRApplication_Overlay);  // background apps get no skeleton input
    if (err != vr::VRInitError_None) {
        fprintf(stderr, "VR_Init failed: %s\n", vr::VR_GetVRInitErrorAsEnglishDescription(err));
        return 1;
    }
    vr::IVRInput* in = vr::VRInput();
    if (auto e = in->SetActionManifestPath((dir + "/actions.json").c_str())) fprintf(stderr, "manifest: %d\n", e);
    vr::VRActionSetHandle_t set = 0;
    vr::VRActionHandle_t act[2] = {};
    in->GetActionSetHandle("/actions/tf", &set);
    in->GetActionHandle("/actions/tf/in/skel_left", &act[0]);
    in->GetActionHandle("/actions/tf/in/skel_right", &act[1]);
    vr::VRActiveActionSet_t aas{};
    aas.ulActionSet = set;

    tf::CurlAnimation anim;
    std::string lerr;
    bool have_anim = anim.Load("", &lerr);
    if (!have_anim) fprintf(stderr, "own animation: %s\n", lerr.c_str());

    auto device_of = [&](int h) {
        vr::VRInputValueHandle_t origins[4] = {};
        in->GetActionOrigins(set, act[h], origins, 4);
        vr::InputOriginInfo_t info{};
        if (!origins[0] || in->GetOriginTrackedDeviceInfo(origins[0], &info, sizeof(info))) return std::string("unbound");
        char serial[128] = {};
        vr::VRSystem()->GetStringTrackedDeviceProperty(info.trackedDeviceIndex, vr::Prop_SerialNumber_String, serial, sizeof(serial));
        return std::to_string(info.trackedDeviceIndex) + " " + serial;
    };

    auto start = std::chrono::steady_clock::now();
    bool done = false;
    while (!done) {
        in->UpdateActionState(&aas, sizeof(aas), 1);
        if (mode == "ref") {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            in->UpdateActionState(&aas, sizeof(aas), 1);
            for (int h = 0; h < 2; h++) {
                printf("== %s hand, action bound to %s\n", h ? "right" : "left", device_of(h).c_str());
                for (int r = 0; r < 4; r++) {
                    vr::VRBoneTransform_t ref[tf::kBoneCount];
                    auto e = in->GetSkeletalReferenceTransforms(act[h], vr::VRSkeletalTransformSpace_Parent,
                                                                vr::EVRSkeletalReferencePose(r), ref, tf::kBoneCount);
                    if (e) { printf("  %-9s error %d\n", kRefNames[r], e); continue; }
                    printf("  %-9s wrist p=(%.4f %.4f %.4f) q=(%.4f %.4f %.4f %.4f)\n", kRefNames[r],
                           ref[1].position.v[0], ref[1].position.v[1], ref[1].position.v[2], ref[1].orientation.w,
                           ref[1].orientation.x, ref[1].orientation.y, ref[1].orientation.z);
                    if (!have_anim || (r != 1 && r != 2)) continue;
                    float curl[5];
                    for (float& c : curl) c = r == 1 ? 0.f : 1.f;
                    tf::Bone ours[tf::kBoneCount];
                    anim.SampleRight(curl, ours);
                    if (h == 0) tf::MirrorToLeft(ours);
                    double worst_p = 0, worst_q = 0;
                    int worst_b = 0;
                    for (int b = 0; b < tf::kBoneCount; b++) {
                        const auto& R = ref[b];
                        double dp = std::sqrt(std::pow(R.position.v[0] - ours[b].pos[0], 2) +
                                              std::pow(R.position.v[1] - ours[b].pos[1], 2) +
                                              std::pow(R.position.v[2] - ours[b].pos[2], 2));
                        double dot = std::fabs(R.orientation.w * ours[b].rot[0] + R.orientation.x * ours[b].rot[1] +
                                               R.orientation.y * ours[b].rot[2] + R.orientation.z * ours[b].rot[3]);
                        double dq = 2 * std::acos(std::fmin(1.0, dot)) * 180 / M_PI;
                        if (dp > 1e-3 || dq > 1) {
                            printf("    bone %2d: dp %.4f m, dq %.1f deg  ref p=(%.4f %.4f %.4f) q=(%.4f %.4f %.4f %.4f)"
                                   "  ours p=(%.4f %.4f %.4f) q=(%.4f %.4f %.4f %.4f)\n", b, dp, dq,
                                   R.position.v[0], R.position.v[1], R.position.v[2], R.orientation.w, R.orientation.x,
                                   R.orientation.y, R.orientation.z, ours[b].pos[0], ours[b].pos[1], ours[b].pos[2],
                                   ours[b].rot[0], ours[b].rot[1], ours[b].rot[2], ours[b].rot[3]);
                        }
                        if (dp + dq / 100 > worst_p + worst_q / 100) { worst_p = dp; worst_q = dq; worst_b = b; }
                    }
                    printf("    ours vs SteamVR: worst bone %d (%.4f m, %.2f deg)\n", worst_b, worst_p, worst_q);
                }
            }
            done = true;
        } else {
            for (int h = 0; h < 2; h++) {
                vr::VRSkeletalSummaryData_t with{}, without{};
                auto e1 = in->GetSkeletalSummaryData(act[h], vr::VRSummaryType_FromDevice, &with);
                auto e2 = in->GetSkeletalSummaryData(act[h], vr::VRSummaryType_FromAnimation, &without);
                printf("%s [%s] ", h ? "R" : "L", device_of(h).c_str());
                if (e1 || e2) printf("err %d/%d   ", e1, e2);
                else printf("curl dev %.2f %.2f %.2f %.2f %.2f anim %.2f %.2f %.2f %.2f %.2f   ",
                            with.flFingerCurl[0], with.flFingerCurl[1], with.flFingerCurl[2], with.flFingerCurl[3],
                            with.flFingerCurl[4], without.flFingerCurl[0], without.flFingerCurl[1],
                            without.flFingerCurl[2], without.flFingerCurl[3], without.flFingerCurl[4]);
            }
            printf("roles L=%d R=%d\n",
                   int(vr::VRSystem()->GetTrackedDeviceIndexForControllerRole(vr::TrackedControllerRole_LeftHand)),
                   int(vr::VRSystem()->GetTrackedDeviceIndexForControllerRole(vr::TrackedControllerRole_RightHand)));
            fflush(stdout);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            done = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() > seconds;
        }
    }
    vr::VR_Shutdown();
    return 0;
}
