// Minimal JSON DOM: enough to read and re-emit XRService controller configs (objects, arrays,
// numbers, strings, bools, null). Not a general-purpose parser: no \u escapes beyond ASCII, and
// key order is kept so a re-emitted config reads like the original.
#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace tf {
namespace json {

struct Value {
    enum Type { Null, Bool, Number, String, Array, Object } type = Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<Value> arr;
    std::vector<std::pair<std::string, Value>> obj;

    const Value* Get(const char* key) const {
        if (type != Object) return nullptr;
        for (auto& kv : obj)
            if (kv.first == key) return &kv.second;
        return nullptr;
    }
    Value* Get(const char* key) { return const_cast<Value*>(static_cast<const Value*>(this)->Get(key)); }
    void Set(const char* key, Value v) {
        if (Value* e = Get(key)) *e = std::move(v);
        else obj.emplace_back(key, std::move(v));
    }
    static Value Str(std::string s) { Value v; v.type = String; v.str = std::move(s); return v; }
};

class Parser {
public:
    Parser(const char* p, const char* end) : p_(p), end_(end) {}
    bool Parse(Value* out) { return ParseValue(out, 0); }
    const char* pos() const { return p_; }

private:
    void Ws() { while (p_ < end_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\n' || *p_ == '\r')) p_++; }
    bool ParseValue(Value* v, int depth) {
        if (depth > 64) return false;
        Ws();
        if (p_ >= end_) return false;
        char c = *p_;
        if (c == '{') {
            v->type = Value::Object;
            p_++;
            Ws();
            if (p_ < end_ && *p_ == '}') { p_++; return true; }
            for (;;) {
                Ws();
                std::string key;
                if (!ParseString(&key)) return false;
                Ws();
                if (p_ >= end_ || *p_ != ':') return false;
                p_++;
                Value child;
                if (!ParseValue(&child, depth + 1)) return false;
                v->obj.emplace_back(std::move(key), std::move(child));
                Ws();
                if (p_ < end_ && *p_ == ',') { p_++; continue; }
                if (p_ < end_ && *p_ == '}') { p_++; return true; }
                return false;
            }
        }
        if (c == '[') {
            v->type = Value::Array;
            p_++;
            Ws();
            if (p_ < end_ && *p_ == ']') { p_++; return true; }
            for (;;) {
                Value child;
                if (!ParseValue(&child, depth + 1)) return false;
                v->arr.push_back(std::move(child));
                Ws();
                if (p_ < end_ && *p_ == ',') { p_++; continue; }
                if (p_ < end_ && *p_ == ']') { p_++; return true; }
                return false;
            }
        }
        if (c == '"') { v->type = Value::String; return ParseString(&v->str); }
        if (Lit("true")) { v->type = Value::Bool; v->b = true; return true; }
        if (Lit("false")) { v->type = Value::Bool; v->b = false; return true; }
        if (Lit("null")) { v->type = Value::Null; return true; }
        if (c == '-' || (c >= '0' && c <= '9')) {
            std::string tok;
            while (p_ < end_ && (strchr("+-.eE", *p_) || (*p_ >= '0' && *p_ <= '9'))) tok += *p_++;
            char* e = nullptr;
            v->type = Value::Number;
            v->num = strtod(tok.c_str(), &e);
            return e && *e == 0;
        }
        return false;
    }
    bool Lit(const char* s) {
        size_t n = strlen(s);
        if (size_t(end_ - p_) < n || strncmp(p_, s, n) != 0) return false;
        p_ += n;
        return true;
    }
    bool ParseString(std::string* s) {
        if (p_ >= end_ || *p_ != '"') return false;
        p_++;
        while (p_ < end_ && *p_ != '"') {
            char c = *p_++;
            if (c == '\\') {
                if (p_ >= end_) return false;
                char e = *p_++;
                switch (e) {
                    case 'n': c = '\n'; break;
                    case 't': c = '\t'; break;
                    case 'r': c = '\r'; break;
                    case 'b': c = '\b'; break;
                    case 'f': c = '\f'; break;
                    case 'u': {
                        if (end_ - p_ < 4) return false;
                        c = char(strtol(std::string(p_, 4).c_str(), nullptr, 16) & 0x7f);
                        p_ += 4;
                        break;
                    }
                    default: c = e;
                }
            }
            *s += c;
        }
        if (p_ >= end_) return false;
        p_++;
        return true;
    }
    const char* p_;
    const char* end_;
};

inline void Emit(const Value& v, std::string* out) {
    switch (v.type) {
        case Value::Null: *out += "null"; break;
        case Value::Bool: *out += v.b ? "true" : "false"; break;
        case Value::Number: {
            char buf[40];
            snprintf(buf, sizeof(buf), "%.17g", v.num);
            *out += buf;
            break;
        }
        case Value::String:
            *out += '"';
            for (char c : v.str) {
                if (c == '"' || c == '\\') { *out += '\\'; *out += c; }
                else if (c == '\n') *out += "\\n";
                else *out += c;
            }
            *out += '"';
            break;
        case Value::Array:
            *out += '[';
            for (size_t i = 0; i < v.arr.size(); i++) {
                if (i) *out += ',';
                Emit(v.arr[i], out);
            }
            *out += ']';
            break;
        case Value::Object:
            *out += '{';
            for (size_t i = 0; i < v.obj.size(); i++) {
                if (i) *out += ',';
                Emit(Value::Str(v.obj[i].first), out);
                *out += ':';
                Emit(v.obj[i].second, out);
            }
            *out += '}';
            break;
    }
}

// Finds the first complete JSON object in arbitrary text (e.g. an XRService log excerpt) for
// which accept(obj) is true.
template <typename Pred>
bool FindObject(const std::string& text, Value* out, Pred accept) {
    for (size_t i = text.find('{'); i != std::string::npos; i = text.find('{', i + 1)) {
        Value v;
        Parser p(text.data() + i, text.data() + text.size());
        if (p.Parse(&v) && v.type == Value::Object && accept(v)) {
            *out = std::move(v);
            return true;
        }
    }
    return false;
}

}  // namespace json
}  // namespace tf
