// Small rigid-transform helpers for the camera-tracker backend (tf::cv). Kept apart from
// driver.cpp's own Quat/Vec3 so the two can evolve independently.
#pragma once
#include <cmath>

#include <openvr_driver.h>

namespace tf {
namespace cv {

struct V3 {
    double x = 0, y = 0, z = 0;
};
struct Q {
    double w = 1, x = 0, y = 0, z = 0;
};
// Rigid transform; as "a_from_b" it maps b-frame coordinates into frame a.
struct Pose {
    Q q;
    V3 p;
};

inline V3 operator+(V3 a, V3 b) { return {a.x + b.x, a.y + b.y, a.z + b.z}; }
inline V3 operator-(V3 a, V3 b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
inline V3 operator*(V3 a, double s) { return {a.x * s, a.y * s, a.z * s}; }
inline double Dot(V3 a, V3 b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
inline V3 Cross(V3 a, V3 b) { return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x}; }
inline double Len(V3 v) { return std::sqrt(Dot(v, v)); }

inline Q Mul(Q a, Q b) {
    return {a.w * b.w - a.x * b.x - a.y * b.y - a.z * b.z, a.w * b.x + a.x * b.w + a.y * b.z - a.z * b.y,
            a.w * b.y - a.x * b.z + a.y * b.w + a.z * b.x, a.w * b.z + a.x * b.y - a.y * b.x + a.z * b.w};
}
inline Q Conj(Q q) { return {q.w, -q.x, -q.y, -q.z}; }
inline Q Normalized(Q q) {
    double n = std::sqrt(q.w * q.w + q.x * q.x + q.y * q.y + q.z * q.z);
    if (n < 1e-12) return Q{};
    return {q.w / n, q.x / n, q.y / n, q.z / n};
}
inline V3 Rot(Q q, V3 v) {
    V3 u{q.x, q.y, q.z};
    V3 t = Cross(u, v) * 2.0;
    return v + t * q.w + Cross(u, t);
}
inline Pose Compose(const Pose& a, const Pose& b) { return {Mul(a.q, b.q), a.p + Rot(a.q, b.p)}; }
inline Pose Inverse(const Pose& a) {
    Q c = Conj(a.q);
    return {c, Rot(c, a.p * -1.0)};
}

// Rotation vector (axis * angle, radians) of q, shortest way round.
inline V3 RotVec(Q q) {
    if (q.w < 0) q = {-q.w, -q.x, -q.y, -q.z};
    double s = std::sqrt(q.x * q.x + q.y * q.y + q.z * q.z);
    if (s < 1e-12) return {q.x * 2, q.y * 2, q.z * 2};
    return V3{q.x, q.y, q.z} * (2 * std::atan2(s, q.w) / s);
}
inline Q FromRotVec(V3 r) {
    double a = Len(r);
    if (a < 1e-12) return Normalized(Q{1, r.x / 2, r.y / 2, r.z / 2});
    double s = std::sin(a / 2) / a;
    return {std::cos(a / 2), r.x * s, r.y * s, r.z * s};
}
inline double AngleDeg(Q a, Q b) { return Len(RotVec(Mul(Conj(a), b))) * 180.0 / M_PI; }

// Rotation whose columns are the frame's x, y = z × x, z axes (Valve config "plus_x"/"plus_z").
inline Q FromAxes(V3 x, V3 z) {
    x = x * (1.0 / Len(x));
    V3 y = Cross(z, x);
    y = y * (1.0 / Len(y));
    z = Cross(x, y);
    double m[3][3] = {{x.x, y.x, z.x}, {x.y, y.y, z.y}, {x.z, y.z, z.z}};
    double tr = m[0][0] + m[1][1] + m[2][2];
    Q q;
    if (tr > 0) {
        double s = std::sqrt(tr + 1.0) * 2;
        q = {0.25 * s, (m[2][1] - m[1][2]) / s, (m[0][2] - m[2][0]) / s, (m[1][0] - m[0][1]) / s};
    } else if (m[0][0] > m[1][1] && m[0][0] > m[2][2]) {
        double s = std::sqrt(1.0 + m[0][0] - m[1][1] - m[2][2]) * 2;
        q = {(m[2][1] - m[1][2]) / s, 0.25 * s, (m[0][1] + m[1][0]) / s, (m[0][2] + m[2][0]) / s};
    } else if (m[1][1] > m[2][2]) {
        double s = std::sqrt(1.0 + m[1][1] - m[0][0] - m[2][2]) * 2;
        q = {(m[0][2] - m[2][0]) / s, (m[0][1] + m[1][0]) / s, 0.25 * s, (m[1][2] + m[2][1]) / s};
    } else {
        double s = std::sqrt(1.0 + m[2][2] - m[0][0] - m[1][1]) * 2;
        q = {(m[1][0] - m[0][1]) / s, (m[0][2] + m[2][0]) / s, (m[1][2] + m[2][1]) / s, 0.25 * s};
    }
    return Normalized(q);
}

inline Pose FromMatrix(const vr::HmdMatrix34_t& m) {
    Pose p;
    p.p = {m.m[0][3], m.m[1][3], m.m[2][3]};
    p.q = FromAxes({m.m[0][0], m.m[1][0], m.m[2][0]}, {m.m[0][2], m.m[1][2], m.m[2][2]});
    return p;
}

}  // namespace cv
}  // namespace tf
