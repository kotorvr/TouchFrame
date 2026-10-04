#pragma once
#include <cstdarg>
#include <cstdio>

#include <openvr_driver.h>

namespace tf {

// Goes to vrserver.txt with the driver's prefix; to stderr outside vrserver (host tests), where
// VRDriverLog() would dereference the missing driver context.
inline void Log(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (!vr::VRDriverContext()) fprintf(stderr, "%s\n", buf);
    else if (vr::VRDriverLog()) vr::VRDriverLog()->Log(buf);
}

}  // namespace tf
