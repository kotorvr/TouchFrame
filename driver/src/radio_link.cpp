#include "radio_link.h"

#include <cstring>

namespace tf {
namespace radio {

const char* StatusName(uint8_t s) {
    static const char* const names[] = {"ok", "bad args", "wrong state", "busy", "timeout",
                                        "pending RE (format not pinned)", "no slot", "crypto", "rejected",
                                        "unknown command", "not connected", "queue full"};
    return s < sizeof(names) / sizeof(names[0]) ? names[s] : "?";
}

void CobsEncode(const uint8_t* data, size_t n, std::vector<uint8_t>* out) {
    size_t code_at = out->size();
    out->push_back(0);
    uint8_t code = 1;
    for (size_t i = 0; i < n; i++) {
        if (data[i] == 0) {
            (*out)[code_at] = code;
            code_at = out->size();
            out->push_back(0);
            code = 1;
            continue;
        }
        out->push_back(data[i]);
        if (++code == 0xFF) {
            (*out)[code_at] = code;
            code_at = out->size();
            out->push_back(0);
            code = 1;
        }
    }
    (*out)[code_at] = code;
    out->push_back(0);
}

bool CobsDecode(const uint8_t* data, size_t n, std::vector<uint8_t>* out) {
    out->clear();
    size_t i = 0;
    while (i < n) {
        uint8_t code = data[i];
        if (code == 0 || i + code > n) return false;
        out->insert(out->end(), data + i + 1, data + i + code);
        i += code;
        if (code != 0xFF && i < n) out->push_back(0);
    }
    return true;
}

std::vector<uint8_t> EncodeCommand(uint8_t cmd, const void* body, size_t n, const void* tail, size_t tail_n) {
    std::vector<uint8_t> raw(1 + n + tail_n);
    raw[0] = cmd;
    if (n) memcpy(raw.data() + 1, body, n);
    if (tail_n) memcpy(raw.data() + 1 + n, tail, tail_n);
    std::vector<uint8_t> out;
    CobsEncode(raw.data(), raw.size(), &out);
    return out;
}

void HidPack(const uint8_t* stream, size_t n, std::vector<uint8_t>* reports) {
    for (size_t off = 0; off < n; off += kHidPayload) {
        size_t k = n - off < kHidPayload ? n - off : kHidPayload;
        size_t at = reports->size();
        reports->resize(at + kHidReport, 0);
        (*reports)[at] = uint8_t(k);
        memcpy(reports->data() + at + 1, stream + off, k);
    }
}

bool HidUnpack(const uint8_t* report, size_t n, const uint8_t** payload, size_t* payload_n) {
    if (n < 1 || report[0] > kHidPayload || size_t(report[0]) + 1 > n) return false;
    *payload = report + 1;
    *payload_n = report[0];
    return true;
}

}  // namespace radio
}  // namespace tf
