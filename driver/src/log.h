#pragma once
#include <cstdarg>
#include <cstdio>

#include <openvr_driver.h>

namespace tf {

// Goes to vrserver.txt with the driver's prefix.
inline void Log(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (vr::VRDriverLog()) vr::VRDriverLog()->Log(buf);
}

}  // namespace tf
