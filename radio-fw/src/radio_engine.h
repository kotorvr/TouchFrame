// Executes radio_op_t operations (radio_op.h) on the nRF52840 RADIO for one attached core (the
// host or the fake controller). Op start times are hit in hardware: TIMER0 CC[2] fires TXEN/RXEN
// through a PPI channel, so beacon timing does not depend on interrupt latency. CC[3] closes RX
// windows. All core callbacks run in the RADIO / TIMER0 interrupts (priority 0).
#pragma once
#include <stdbool.h>
#include <stdint.h>

#include "radio_op.h"

typedef struct {
    bool (*next_op)(void* ctx, uint64_t now, radio_op_t* op);
    void (*on_rx)(void* ctx, const radio_rx_t* rx);
    void (*on_done)(void* ctx, const radio_op_t* op, uint64_t now);
    void* ctx;
} engine_core_t;

// From TXEN to the ADDRESS event: 40 us fast ramp-up + 8-bit preamble + 5-byte address at 2 Mbit.
// Verify on hardware day with a second dongle (HARDWARE-DAY: compare a beacon's 48-bit timestamp
// with the sniffer's ADDRESS capture; the offset between the two dongles' clocks is constant).
#define ENGINE_TX_TO_ADDRESS_US 64
#define ENGINE_RX_RAMP_US 40
#define ENGINE_MIN_LEAD_US 20  // the trigger must be at least this far in the future when armed

void engine_init(void);
void engine_attach(const engine_core_t* core);  // halts first; kick to start
void engine_detach(void);
void engine_halt(void);                         // synchronous: radio disabled, no callbacks until kick
void engine_kick(void);                         // safe from the main loop
void engine_set_tx_power(int8_t dbm);
uint32_t engine_late_ops(void);                 // ops whose start time had already passed
bool engine_active(void);

void engine_radio_irq(void);
void engine_timer_irq(void);
