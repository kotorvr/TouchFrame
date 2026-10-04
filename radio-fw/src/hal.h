// Small nRF52840 helpers behind platform_t: the CCM peripheral, the RNG, the FICR device id.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// AES-CCM in the CCM peripheral, Pulsar profile (crypto.h): out-of-line, one packet per call,
// busy-waits ~20-60 us. encrypt: out = in || MIC; decrypt: in has the MIC, false if it fails.
// Not re-entrant: the host uses it only from the main loop, the fake controller only from the
// radio interrupt. len 0 falls back to software (the peripheral adds no MIC to empty packets).
bool hal_ccm(bool encrypt, const uint8_t key[16], const uint8_t nonce[13], const uint8_t* in, uint8_t len,
             uint8_t* out);
void hal_random(uint8_t* out, size_t n);
uint64_t hal_device_id(void);
