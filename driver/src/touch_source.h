// The interface every Touch Plus state source implements (UDP relay, camera tracker, radio).
// Kept apart from source.h so portable sources (the radio backend) build without socket headers.
#pragma once

namespace tf {

class ITouchSource {
public:
    virtual ~ITouchSource() = default;
    virtual bool Start() = 0;
    virtual void Stop() = 0;
    virtual void SendHaptic(int hand, float amplitude, float frequency, float duration_s) = 0;
};

}  // namespace tf
