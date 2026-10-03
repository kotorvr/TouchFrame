#include "skeleton.h"

#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iterator>
#include <utility>

namespace tf {
namespace {

// --- Minimal JSON reader, just enough for a glTF header -------------------------------
struct Json {
    enum Type { kNull, kBool, kNum, kStr, kArr, kObj } type = kNull;
    double num = 0;
    std::string str;
    std::vector<Json> arr;
    std::vector<std::pair<std::string, Json>> obj;

    const Json& operator[](const char* key) const {
        for (const auto& kv : obj) if (kv.first == key) return kv.second;
        return None();
    }
    const Json& operator[](int i) const { return i >= 0 && size_t(i) < arr.size() ? arr[size_t(i)] : None(); }
    size_t size() const { return type == kArr ? arr.size() : 0; }
    bool Has(const char* key) const { return &(*this)[key] != &None(); }
    double Num(double def = 0) const { return type == kNum ? num : def; }
    static const Json& None() { static const Json n; return n; }
};

class JsonParser {
public:
    JsonParser(const char* p, const char* end) : p_(p), end_(end) {}
    bool Parse(Json& out) { return Value(out, 0); }

private:
    void Ws() { while (p_ < end_ && (*p_ == ' ' || *p_ == '\n' || *p_ == '\r' || *p_ == '\t')) p_++; }
    bool Lit(const char* s) {
        size_t n = strlen(s);
        if (size_t(end_ - p_) < n || memcmp(p_, s, n) != 0) return false;
        p_ += n;
        return true;
    }
    bool String(std::string& s) {
        if (p_ >= end_ || *p_ != '"') return false;
        p_++;
        while (p_ < end_ && *p_ != '"') {
            char c = *p_++;
            if (c == '\\' && p_ < end_) {
                char e = *p_++;
                switch (e) {
                    case 'n': c = '\n'; break;
                    case 't': c = '\t'; break;
                    case 'r': c = '\r'; break;
                    case 'b': c = '\b'; break;
                    case 'f': c = '\f'; break;
                    case 'u': p_ = std::min(p_ + 4, end_); c = '?'; break;  // names are ASCII
                    default: c = e;
                }
            }
            s += c;
        }
        if (p_ >= end_) return false;
        p_++;
        return true;
    }
    bool Value(Json& v, int depth) {
        if (depth > 64) return false;
        Ws();
        if (p_ >= end_) return false;
        char c = *p_;
        if (c == '{') {
            v.type = Json::kObj;
            p_++;
            Ws();
            if (p_ < end_ && *p_ == '}') { p_++; return true; }
            for (;;) {
                Ws();
                std::string k;
                if (!String(k)) return false;
                Ws();
                if (p_ >= end_ || *p_++ != ':') return false;
                v.obj.emplace_back(std::move(k), Json());
                if (!Value(v.obj.back().second, depth + 1)) return false;
                Ws();
                if (p_ < end_ && *p_ == ',') { p_++; continue; }
                if (p_ < end_ && *p_ == '}') { p_++; return true; }
                return false;
            }
        }
        if (c == '[') {
            v.type = Json::kArr;
            p_++;
            Ws();
            if (p_ < end_ && *p_ == ']') { p_++; return true; }
            for (;;) {
                v.arr.emplace_back();
                if (!Value(v.arr.back(), depth + 1)) return false;
                Ws();
                if (p_ < end_ && *p_ == ',') { p_++; continue; }
                if (p_ < end_ && *p_ == ']') { p_++; return true; }
                return false;
            }
        }
        if (c == '"') { v.type = Json::kStr; return String(v.str); }
        if (Lit("true")) { v.type = Json::kBool; v.num = 1; return true; }
        if (Lit("false")) { v.type = Json::kBool; return true; }
        if (Lit("null")) return true;
        char* e = nullptr;
        std::string tmp(p_, std::min<size_t>(end_ - p_, 64));
        v.num = strtod(tmp.c_str(), &e);
        if (e == tmp.c_str()) return false;
        v.type = Json::kNum;
        p_ += e - tmp.c_str();
        return true;
    }
    const char* p_;
    const char* end_;
};

// --- Bones ----------------------------------------------------------------------------
// OpenVR HandSkeletonBone order, as named in SteamVR's right-hand glb files.
const char* const kBoneNames[kBoneCount] = {
    "Root", "wrist_r",
    "finger_thumb_0_r", "finger_thumb_1_r", "finger_thumb_2_r", "finger_thumb_r_end",
    "finger_index_meta_r", "finger_index_0_r", "finger_index_1_r", "finger_index_2_r", "finger_index_r_end",
    "finger_middle_meta_r", "finger_middle_0_r", "finger_middle_1_r", "finger_middle_2_r", "finger_middle_r_end",
    "finger_ring_meta_r", "finger_ring_0_r", "finger_ring_1_r", "finger_ring_2_r", "finger_ring_r_end",
    "finger_pinky_meta_r", "finger_pinky_0_r", "finger_pinky_1_r", "finger_pinky_2_r", "finger_pinky_r_end",
    "finger_thumb_r_aux", "finger_index_r_aux", "finger_middle_r_aux", "finger_ring_r_aux", "finger_pinky_r_aux",
};

int FingerOf(int b) {
    if (b >= 26) return b - 26;
    if (b >= 21) return 4;
    if (b >= 16) return 3;
    if (b >= 11) return 2;
    if (b >= 6) return 1;
    if (b >= 2) return 0;
    return -1;  // root, wrist
}

bool ParentIsRoot(int b) { return b == 1 || b >= 26; }
bool ParentIsWrist(int b) { return b == 2 || b == 6 || b == 11 || b == 16 || b == 21; }

std::string SteamVrRootFromExe() {
    // vrserver lives in <root>/bin/linuxarm64/.
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    std::string p(buf, size_t(n));
    for (int i = 0; i < 3; i++) {
        size_t s = p.rfind('/');
        if (s == std::string::npos) return {};
        p.resize(s);
    }
    return p;
}

void Normalize(float q[4]) {
    float n = std::sqrt(q[0] * q[0] + q[1] * q[1] + q[2] * q[2] + q[3] * q[3]);
    if (n < 1e-9f) { q[0] = 1; q[1] = q[2] = q[3] = 0; return; }
    for (int i = 0; i < 4; i++) q[i] /= n;
}

}  // namespace

bool CurlAnimation::Load(const std::string& steamvr_root, std::string* err) {
    std::vector<std::string> roots;
    if (!steamvr_root.empty()) roots.push_back(steamvr_root);
    std::string exe_root = SteamVrRootFromExe();
    if (!exe_root.empty()) roots.push_back(exe_root);
    roots.push_back("/opt/steamvr");

    std::vector<char> d;
    for (const auto& r : roots) {
        std::ifstream f(r + "/resources/anims/hand_right_closeanim.glb", std::ios::binary);
        if (!f) continue;
        d.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
        path_ = r + "/resources/anims/hand_right_closeanim.glb";
        break;
    }
    auto fail = [&](const char* why) { if (err) *err = path_.empty() ? why : path_ + ": " + why; return false; };
    if (d.empty()) return fail("resources/anims/hand_right_closeanim.glb not found in the SteamVR install");

    auto u32 = [&](size_t off) { uint32_t v; memcpy(&v, d.data() + off, 4); return v; };
    if (d.size() < 28 || u32(0) != 0x46546C67u) return fail("not a glb");
    uint32_t json_len = u32(12);
    if (u32(16) != 0x4E4F534Au || 20 + size_t(json_len) + 8 > d.size()) return fail("bad JSON chunk");
    size_t bin_off = 20 + json_len + 8;
    size_t bin_len = u32(20 + json_len);
    if (u32(20 + json_len + 4) != 0x004E4942u || bin_off + bin_len > d.size()) return fail("bad BIN chunk");

    Json j;
    if (!JsonParser(d.data() + 20, d.data() + 20 + json_len).Parse(j)) return fail("JSON parse error");

    // Float accessor -> flat vector, n components each.
    auto read = [&](size_t acc, int n, std::vector<float>& out) {
        const Json& a = j["accessors"][int(acc)];
        const Json& bv = j["bufferViews"][int(a["bufferView"].Num(-1))];
        if (a["componentType"].Num() != 5126 || bv.type != Json::kObj) return false;
        size_t count = size_t(a["count"].Num());
        size_t stride = size_t(bv["byteStride"].Num(0));
        if (!stride) stride = 4 * n;
        size_t off = bin_off + size_t(bv["byteOffset"].Num()) + size_t(a["byteOffset"].Num());
        if (count == 0 || off + stride * (count - 1) + 4 * n > bin_off + bin_len) return false;
        out.resize(count * n);
        for (size_t i = 0; i < count; i++) memcpy(&out[i * n], d.data() + off + i * stride, 4 * n);
        return true;
    };

    const Json& nodes = j["nodes"];
    int node_bone[512];
    std::fill(std::begin(node_bone), std::end(node_bone), -1);
    for (size_t i = 0; i < nodes.size() && i < 512; i++) {
        std::string name = nodes[int(i)]["name"].str;
        if (name.compare(0, 4, "REF:") == 0) name = name.substr(4);
        for (int b = 0; b < kBoneCount; b++) {
            if (name != kBoneNames[b]) continue;
            node_bone[i] = b;
            // Rest pose for bones the animation doesn't move.
            const Json& t = nodes[int(i)]["translation"];
            const Json& r = nodes[int(i)]["rotation"];  // glTF x, y, z, w
            track_[b].t3 = {float(t[0].Num()), float(t[1].Num()), float(t[2].Num())};
            track_[b].q4 = {float(r[3].Num(1)), float(r[0].Num()), float(r[1].Num()), float(r[2].Num())};
        }
    }
    for (int b = 0; b < kBoneCount; b++)
        if (track_[b].q4.empty()) return fail((std::string("missing bone ") + kBoneNames[b]).c_str());

    const Json& anim = j["animations"][0];
    for (size_t c = 0; c < anim["channels"].size(); c++) {
        const Json& ch = anim["channels"][int(c)];
        size_t node = size_t(ch["target"]["node"].Num(-1));
        int b = node < 512 ? node_bone[node] : -1;
        if (b < 0) continue;
        const Json& smp = anim["samplers"][int(ch["sampler"].Num(-1))];
        std::vector<float> times, v;
        if (!read(size_t(smp["input"].Num(-1)), 1, times)) return fail("bad sampler input");
        if (times_.empty()) times_ = times;
        if (times.size() != times_.size()) return fail("channels with different key counts");
        const std::string& path = ch["target"]["path"].str;
        if (path == "translation") {
            if (!read(size_t(smp["output"].Num(-1)), 3, v)) return fail("bad translation keys");
            track_[b].t3 = v;
        } else if (path == "rotation") {
            if (!read(size_t(smp["output"].Num(-1)), 4, v)) return fail("bad rotation keys");
            track_[b].q4.resize(v.size());
            for (size_t k = 0; k < v.size(); k += 4) {
                track_[b].q4[k] = v[k + 3];
                track_[b].q4[k + 1] = v[k];
                track_[b].q4[k + 2] = v[k + 1];
                track_[b].q4[k + 3] = v[k + 2];
            }
        }
    }
    if (times_.size() < 2) return fail("no animation keys");
    return true;
}

void CurlAnimation::SampleRight(const float curl[5], Bone out[kBoneCount]) const {
    size_t keys = times_.size();
    for (int b = 0; b < kBoneCount; b++) {
        int f = FingerOf(b);
        float c = f < 0 ? 0.f : std::min(1.f, std::max(0.f, curl[f]));
        float t = times_.front() + c * (times_.back() - times_.front());
        size_t k = 0;
        while (k + 2 < keys && times_[k + 1] < t) k++;
        float span = times_[k + 1] - times_[k];
        float a = span > 0 ? std::min(1.f, std::max(0.f, (t - times_[k]) / span)) : 0.f;

        const Track& tr = track_[b];
        size_t k0 = std::min(k, tr.t3.size() / 3 - 1), k1 = std::min(k + 1, tr.t3.size() / 3 - 1);
        float p[3], q[4];
        for (int i = 0; i < 3; i++) p[i] = tr.t3[k0 * 3 + i] * (1 - a) + tr.t3[k1 * 3 + i] * a;
        k0 = std::min(k, tr.q4.size() / 4 - 1);
        k1 = std::min(k + 1, tr.q4.size() / 4 - 1);
        const float* q0 = &tr.q4[k0 * 4];
        const float* q1 = &tr.q4[k1 * 4];
        float dot = q0[0] * q1[0] + q0[1] * q1[1] + q0[2] * q1[2] + q0[3] * q1[3];
        float s = dot < 0 ? -1.f : 1.f;
        for (int i = 0; i < 4; i++) q[i] = q0[i] * (1 - a) + s * q1[i] * a;  // nlerp, keys are close
        Normalize(q);

        if (b == 0) {
            p[0] = p[1] = p[2] = 0;
            q[0] = 1; q[1] = q[2] = q[3] = 0;
        } else if (ParentIsRoot(b)) {
            // glb -> OpenVR: the hand faces the other way, a 180 degree turn about +Y at the root.
            float w = q[0], x = q[1], y = q[2], z = q[3];
            q[0] = -y; q[1] = z; q[2] = w; q[3] = -x;
            p[0] = -p[0];
            p[2] = -p[2];
        }
        Bone& o = out[b];
        o.pos[0] = p[0]; o.pos[1] = p[1]; o.pos[2] = p[2]; o.pos[3] = 1;
        memcpy(o.rot, q, sizeof(q));
    }
}

void MirrorToLeft(Bone bones[kBoneCount]) {
    // Mirror across the X=0 plane. Root, wrist and aux frames are mirrored; finger frames
    // are mirrored and turned 180 degrees about X so they stay right-handed (as in SteamVR's
    // vr_glove_left/right skeletons; checked against its reference poses with tf_skeldump).
    // So, per parent-relative transform:
    //   wrist, aux:            t = (-x, y, z), q = (w, x, -y, -z)
    //   first bone of a chain: t = (-x, y, z), q = (w, x, -y, -z) * Rx(180)
    //   finger -> finger:      t = -t,        q unchanged
    for (int b = 1; b < kBoneCount; b++) {
        float* p = bones[b].pos;
        float* q = bones[b].rot;
        if (ParentIsRoot(b) || ParentIsWrist(b)) {
            p[0] = -p[0];
            q[2] = -q[2];
            q[3] = -q[3];
            if (ParentIsWrist(b)) {
                float w = q[0], x = q[1], y = q[2], z = q[3];
                q[0] = -x; q[1] = w; q[2] = z; q[3] = -y;
            }
        } else {
            p[0] = -p[0]; p[1] = -p[1]; p[2] = -p[2];
        }
    }
}

void HandPoser::Update(const CurlAnimation& anim, const HandState& s, double dt) {
    // Curl is in animation time: 0 open hand, 1 fist (thumb folds last, from ~0.5 on).
    uint16_t b = s.buttons;
    bool thumb_touch = b & (kBtnLowerTouch | kBtnUpperTouch | kBtnStickTouch | kBtnThumbrestTouch |
                            kBtnLowerClick | kBtnUpperClick | kBtnStickClick);
    bool thumb_press = b & (kBtnLowerClick | kBtnUpperClick | kBtnStickClick);
    bool index_touch = (b & kBtnTriggerTouch) || s.trigger > 0.05f;
    float trig = std::min(1.f, std::max(0.f, s.trigger));
    float grip = std::min(1.f, std::max(0.f, s.grip));

    // Without the controller: a pulled trigger/grip is a closed finger.
    float without[5] = {thumb_touch ? (thumb_press ? 0.7f : 0.6f) : 0.f,
                        index_touch ? 0.3f + 0.7f * trig : 0.f,
                        0.08f + 0.92f * grip, 0.08f + 0.92f * grip, 0.08f + 0.92f * grip};
    // With the controller: fingers stop where they meet the handle and trigger.
    float with[5] = {thumb_touch ? 0.55f : 0.f,
                     index_touch ? 0.25f + 0.15f * trig : 0.05f,
                     0.08f + 0.32f * grip, 0.08f + 0.32f * grip, 0.08f + 0.32f * grip};

    float a = first_ ? 1.f : float(1.0 - std::exp(-std::max(0.0, dt) / 0.04));  // 40 ms smoothing
    first_ = false;
    for (int f = 0; f < 5; f++) {
        curl_with_[f] += (with[f] - curl_with_[f]) * a;
        curl_without_[f] += (without[f] - curl_without_[f]) * a;
    }
    anim.SampleRight(curl_with_, with_);
    anim.SampleRight(curl_without_, without_);
    if (hand_ == 0) {
        MirrorToLeft(with_);
        MirrorToLeft(without_);
    }
}

}  // namespace tf
