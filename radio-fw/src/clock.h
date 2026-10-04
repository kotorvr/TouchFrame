// The dongle's microsecond clock: TIMER0 at 1 MHz, 32 bits, extended to 64 in software. Every
// timestamp on the USB link and the host beacons' 48-bit sync time come from it. CC[0] is the
// "now" capture, CC[1] the RADIO ADDRESS capture (PPI channel 26, fixed), CC[2]/CC[3] belong to
// radio_engine.c.
#pragma once
#include <stdint.h>

void clock_init(void);
uint32_t clock_now32(void);
uint64_t clock_now64(void);          // safe from any context; call at least once per 71 minutes
uint64_t clock_extend(uint32_t t32); // a recent (or near-future) 32-bit stamp -> 64-bit
uint32_t clock_address_capture(void);  // TIMER0 CC[1]: the last RADIO ADDRESS event
