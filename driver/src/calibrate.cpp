// tf_calibrate: aligns the relay source's tracking space (the Quest's stage) with the
// Frame's. Hold a Touch controller and a Frame controller together in one hand (rigidly,
// any grip) and slowly rotate/move them through big turns for the capture time.
//
//   tf_calibrate [left|right] [seconds]
//
// Model: Frame controller F_i = W * R_i * Y, with R_i the Touch pose in source space,
// W (source -> SteamVR raw world, yaw + translation since both spaces are gravity aligned)
// and Y the unknown rigid grip offset. Yaw comes from matching rotation deltas, then W.t
// and Y.t from linear least squares. The result goes to driver_touchframe.calib_* and
// the driver reloads it live (calib_version).
#include <openvr.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

const char* kSection = "driver_touchframe";

struct V3 { double x, y, z; };
struct Q { double w, x, y, z; };
struct Pose { Q q; V3 p; };

V3 operator+(V3 a, V3 b) { return {a.x + b.x, a.y + b.y, a.z + b.z}; }
V3 operator-(V3 a, V3 b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
V3 operator*(V3 a, double s) { return {a.x * s, a.y * s, a.z * s}; }
Q Mul(Q a, Q b) {
    return {a.w * b.w - a.x * b.x - a.y * b.y - a.z * b.z, a.w * b.x + a.x * b.w + a.y * b.z - a.z * b.y,
            a.w * b.y - a.x * b.z + a.y * b.w + a.z * b.x, a.w * b.z + a.x * b.y - a.y * b.x + a.z * b.w};
}
Q Conj(Q q) { return {q.w, -q.x, -q.y, -q.z}; }
V3 Rot(Q q, V3 v) {
    Q r = Mul(Mul(q, Q{0, v.x, v.y, v.z}), Conj(q));
    return {r.x, r.y, r.z};
}
Pose Compose(Pose a, Pose b) { return {Mul(a.q, b.q), a.p + Rot(a.q, b.p)}; }
Pose Inverse(Pose a) { Q c = Conj(a.q); return {c, Rot(c, a.p * -1)}; }

// Rotation vector (axis * angle) of q.
V3 RotVec(Q q) {
    if (q.w < 0) q = {-q.w, -q.x, -q.y, -q.z};
    double s = std::sqrt(q.x * q.x + q.y * q.y + q.z * q.z);
    if (s < 1e-9) return {0, 0, 0};
    double angle = 2 * std::atan2(s, q.w);
    return V3{q.x, q.y, q.z} * (angle / s);
}
double Len(V3 v) { return std::sqrt(v.x * v.x + v.y * v.y + v.z * v.z); }

Pose FromMatrix(const vr::HmdMatrix34_t& m) {
    Pose p;
    p.p = {m.m[0][3], m.m[1][3], m.m[2][3]};
    double tr = m.m[0][0] + m.m[1][1] + m.m[2][2];
    Q q;
    if (tr > 0) {
        double s = std::sqrt(tr + 1.0) * 2;
        q = {0.25 * s, (m.m[2][1] - m.m[1][2]) / s, (m.m[0][2] - m.m[2][0]) / s, (m.m[1][0] - m.m[0][1]) / s};
    } else if (m.m[0][0] > m.m[1][1] && m.m[0][0] > m.m[2][2]) {
        double s = std::sqrt(1.0 + m.m[0][0] - m.m[1][1] - m.m[2][2]) * 2;
        q = {(m.m[2][1] - m.m[1][2]) / s, 0.25 * s, (m.m[0][1] + m.m[1][0]) / s, (m.m[0][2] + m.m[2][0]) / s};
    } else if (m.m[1][1] > m.m[2][2]) {
        double s = std::sqrt(1.0 + m.m[1][1] - m.m[0][0] - m.m[2][2]) * 2;
        q = {(m.m[0][2] - m.m[2][0]) / s, (m.m[0][1] + m.m[1][0]) / s, 0.25 * s, (m.m[1][2] + m.m[2][1]) / s};
    } else {
        double s = std::sqrt(1.0 + m.m[2][2] - m.m[0][0] - m.m[1][1]) * 2;
        q = {(m.m[1][0] - m.m[0][1]) / s, (m.m[0][2] + m.m[2][0]) / s, (m.m[1][2] + m.m[2][1]) / s, 0.25 * s};
    }
    p.q = q;
    return p;
}

std::string StrProp(vr::IVRSystem* sys, uint32_t i, vr::ETrackedDeviceProperty prop) {
    char buf[256] = {};
    sys->GetStringTrackedDeviceProperty(i, prop, buf, sizeof(buf));
    return buf;
}

// Solve the symmetric 6x6 system A x = b (Gaussian elimination with partial pivoting).
bool Solve6(double A[6][6], double b[6], double x[6]) {
    for (int c = 0; c < 6; c++) {
        int piv = c;
        for (int r = c + 1; r < 6; r++) if (std::fabs(A[r][c]) > std::fabs(A[piv][c])) piv = r;
        if (std::fabs(A[piv][c]) < 1e-12) return false;
        std::swap(A[c], A[piv]);
        std::swap(b[c], b[piv]);
        for (int r = c + 1; r < 6; r++) {
            double f = A[r][c] / A[c][c];
            for (int k = c; k < 6; k++) A[r][k] -= f * A[c][k];
            b[r] -= f * b[c];
        }
    }
    for (int r = 5; r >= 0; r--) {
        double s = b[r];
        for (int k = r + 1; k < 6; k++) s -= A[r][k] * x[k];
        x[r] = s / A[r][r];
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    std::string hand = argc > 1 ? argv[1] : "right";
    double seconds = argc > 2 ? atof(argv[2]) : 20.0;
    std::string touch_serial = hand == "left" ? "TouchFrame_Left" : "TouchFrame_Right";

    vr::EVRInitError err;
    vr::IVRSystem* sys = vr::VR_Init(&err, vr::VRApplication_Background);
    if (!sys) {
        fprintf(stderr, "VR_Init failed: %s\n", vr::VR_GetVRInitErrorAsEnglishDescription(err));
        return 1;
    }
    vr::IVRSettings* settings = vr::VRSettings();

    uint32_t touch = vr::k_unTrackedDeviceIndexInvalid;
    std::vector<uint32_t> frames;
    for (uint32_t i = 0; i < vr::k_unMaxTrackedDeviceCount; i++) {
        if (sys->GetTrackedDeviceClass(i) != vr::TrackedDeviceClass_Controller) continue;
        std::string serial = StrProp(sys, i, vr::Prop_SerialNumber_String);
        std::string type = StrProp(sys, i, vr::Prop_ControllerType_String);
        printf("controller %u: serial=%s type=%s\n", i, serial.c_str(), type.c_str());
        if (serial == touch_serial) touch = i;
        else if (serial.rfind("TouchFrame_", 0) != 0) frames.push_back(i);
    }
    if (touch == vr::k_unTrackedDeviceIndexInvalid || frames.empty()) {
        fprintf(stderr, "need %s and a Frame controller connected\n", touch_serial.c_str());
        vr::VR_Shutdown();
        return 1;
    }

    // Undo the calibration currently applied so samples are in source space.
    Pose cur{{settings->GetFloat(kSection, "calib_qw"), settings->GetFloat(kSection, "calib_qx"),
              settings->GetFloat(kSection, "calib_qy"), settings->GetFloat(kSection, "calib_qz")},
             {settings->GetFloat(kSection, "calib_tx"), settings->GetFloat(kSection, "calib_ty"),
              settings->GetFloat(kSection, "calib_tz")}};
    double n = std::sqrt(cur.q.w * cur.q.w + cur.q.x * cur.q.x + cur.q.y * cur.q.y + cur.q.z * cur.q.z);
    cur.q = n < 1e-6 ? Q{1, 0, 0, 0} : Q{cur.q.w / n, cur.q.x / n, cur.q.y / n, cur.q.z / n};
    Pose cur_inv = Inverse(cur);

    printf("Hold the %s Touch and one Frame controller together; rotate and move them slowly for %.0f s...\n",
           hand.c_str(), seconds);
    fflush(stdout);
    // Sample every Frame controller; afterwards keep the one whose rotation speed follows the Touch.
    std::vector<Pose> Rall;
    std::vector<double> touch_speed;
    std::vector<std::vector<Pose>> Fall(frames.size());
    std::vector<std::vector<double>> fspeed(frames.size());
    std::vector<std::vector<char>> fok(frames.size());
    int touch_bad = 0, total = 0;
    auto t0 = std::chrono::steady_clock::now();
    double next_report = 5;
    for (;;) {
        double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (el >= seconds) break;
        vr::TrackedDevicePose_t poses[vr::k_unMaxTrackedDeviceCount];
        sys->GetDeviceToAbsoluteTrackingPose(vr::TrackingUniverseRawAndUncalibrated, 0, poses, vr::k_unMaxTrackedDeviceCount);
        const auto& pt = poses[touch];
        total++;
        if (pt.bPoseIsValid && pt.eTrackingResult == vr::TrackingResult_Running_OK) {
            Rall.push_back(Compose(cur_inv, FromMatrix(pt.mDeviceToAbsoluteTracking)));
            touch_speed.push_back(Len({pt.vAngularVelocity.v[0], pt.vAngularVelocity.v[1], pt.vAngularVelocity.v[2]}));
            for (size_t k = 0; k < frames.size(); k++) {
                const auto& pf = poses[frames[k]];
                Fall[k].push_back(FromMatrix(pf.mDeviceToAbsoluteTracking));
                fspeed[k].push_back(Len({pf.vAngularVelocity.v[0], pf.vAngularVelocity.v[1], pf.vAngularVelocity.v[2]}));
                fok[k].push_back(pf.bPoseIsValid && pf.eTrackingResult == vr::TrackingResult_Running_OK);
            }
        } else {
            touch_bad++;
        }
        if (el >= next_report) {
            next_report += 5;
            printf("  %.0fs: Touch tracked %d/%d", el, total - touch_bad, total);
            for (size_t k = 0; k < frames.size(); k++) {
                int n = 0;
                for (char b : fok[k]) n += b;
                printf(", Frame controller %u tracked %d", frames[k], n);
            }
            printf("\n");
            fflush(stdout);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    // Pick the Frame controller whose angular speed correlates best with the Touch's.
    int best = -1;
    double best_corr = -2;
    for (size_t k = 0; k < frames.size(); k++) {
        double sa = 0, sb = 0, saa = 0, sbb = 0, sab = 0;
        int cnt = 0;
        for (size_t i = 0; i < touch_speed.size(); i++) {
            if (!fok[k][i]) continue;
            double a = touch_speed[i], b = fspeed[k][i];
            sa += a; sb += b; saa += a * a; sbb += b * b; sab += a * b; cnt++;
        }
        if (cnt < 100) continue;
        double cov = sab / cnt - sa / cnt * sb / cnt;
        double va = saa / cnt - sa / cnt * sa / cnt, vb = sbb / cnt - sb / cnt * sb / cnt;
        double corr = cov / std::sqrt(std::max(va * vb, 1e-12));
        printf("Frame controller %u: %d samples, speed correlation %.2f\n", frames[k], cnt, corr);
        if (corr > best_corr) { best_corr = corr; best = int(k); }
    }
    std::vector<Pose> R, F;
    if (best >= 0) {
        for (size_t i = 0; i < Rall.size(); i++) {
            if (!fok[best][i] || touch_speed[i] > 2.0) continue;
            R.push_back(Rall[i]);
            F.push_back(Fall[best][i]);
        }
    }
    printf("%zu samples (Touch untracked in %d of %d polls)\n", R.size(), touch_bad, total);
    if (best >= 0 && best_corr < 0.5) {
        fprintf(stderr, "no Frame controller moved with the Touch (best correlation %.2f)\n", best_corr);
        vr::VR_Shutdown();
        return 1;
    }
    if (R.size() < 200) {
        fprintf(stderr, "too few tracked samples; keep both controllers in view of their trackers\n");
        vr::VR_Shutdown();
        return 1;
    }

    // Yaw: world rotation deltas of F equal W-rotated source deltas of R.
    double S = 0, C = 0;
    int pairs = 0;
    for (size_t i = 0; i < R.size(); i++) {
        for (size_t stride : {10, 25, 50}) {
            size_t j = i + stride;
            if (j >= R.size()) continue;
            V3 a = RotVec(Mul(R[j].q, Conj(R[i].q)));
            V3 b = RotVec(Mul(F[j].q, Conj(F[i].q)));
            double la = Len(a), lb = Len(b);
            if (la < 0.3 || la > 2.5 || std::fabs(la - lb) > 0.2) continue;
            S += a.z * b.x - a.x * b.z;
            C += a.x * b.x + a.z * b.z;
            pairs++;
        }
    }
    if (pairs < 50) {
        fprintf(stderr, "only %d usable rotation pairs; rotate more (big wrist turns)\n", pairs);
        vr::VR_Shutdown();
        return 1;
    }
    double yaw = std::atan2(S, C);
    Q wq{std::cos(yaw / 2), 0, std::sin(yaw / 2), 0};

    // Translation: F.p - Wq*R.p = (Wq*R.q) * y + W.t
    double A[6][6] = {}, bb[6] = {}, x[6];
    for (size_t i = 0; i < R.size(); i++) {
        V3 rhs = F[i].p - Rot(wq, R[i].p);
        Q m = Mul(wq, R[i].q);
        V3 cx = Rot(m, {1, 0, 0}), cy = Rot(m, {0, 1, 0}), cz = Rot(m, {0, 0, 1});
        double rows[3][6] = {{cx.x, cy.x, cz.x, 1, 0, 0}, {cx.y, cy.y, cz.y, 0, 1, 0}, {cx.z, cy.z, cz.z, 0, 0, 1}};
        double r3[3] = {rhs.x, rhs.y, rhs.z};
        for (int k = 0; k < 3; k++)
            for (int a = 0; a < 6; a++) {
                bb[a] += rows[k][a] * r3[k];
                for (int c = 0; c < 6; c++) A[a][c] += rows[k][a] * rows[k][c];
            }
    }
    if (!Solve6(A, bb, x)) {
        fprintf(stderr, "translation solve failed; rotate the controllers more\n");
        vr::VR_Shutdown();
        return 1;
    }
    V3 y{x[0], x[1], x[2]}, wt{x[3], x[4], x[5]};
    double se = 0;
    for (size_t i = 0; i < R.size(); i++) {
        V3 pred = Rot(wq, R[i].p + Rot(R[i].q, y)) + wt;
        V3 e = pred - F[i].p;
        se += e.x * e.x + e.y * e.y + e.z * e.z;
    }
    double rms = std::sqrt(se / R.size());
    printf("yaw %.1f deg, translation (%.3f %.3f %.3f) m, grip offset %.3f m, pairs %d, RMS %.1f mm\n",
           yaw * 180 / M_PI, wt.x, wt.y, wt.z, Len(y), pairs, rms * 1000);
    if (rms > 0.05 || Len(y) > 0.3) {
        fprintf(stderr, "fit too poor (RMS %.0f mm, offset %.2f m); not saving. Hold them tighter together.\n",
                rms * 1000, Len(y));
        vr::VR_Shutdown();
        return 1;
    }

    settings->SetFloat(kSection, "calib_qw", float(wq.w));
    settings->SetFloat(kSection, "calib_qx", float(wq.x));
    settings->SetFloat(kSection, "calib_qy", float(wq.y));
    settings->SetFloat(kSection, "calib_qz", float(wq.z));
    settings->SetFloat(kSection, "calib_tx", float(wt.x));
    settings->SetFloat(kSection, "calib_ty", float(wt.y));
    settings->SetFloat(kSection, "calib_tz", float(wt.z));
    settings->SetInt32(kSection, "calib_version", settings->GetInt32(kSection, "calib_version") + 1);
    printf("saved; the driver applies it within a second\n");
    vr::VR_Shutdown();
    return 0;
}
