#include "clock.h"

#include "nrf.h"

static uint32_t last_low, high;  // guarded by masking interrupts

void clock_init(void) {
    NRF_TIMER0->TASKS_STOP = 1;
    NRF_TIMER0->MODE = TIMER_MODE_MODE_Timer;
    NRF_TIMER0->BITMODE = TIMER_BITMODE_BITMODE_32Bit;
    NRF_TIMER0->PRESCALER = 4;  // 16 MHz / 2^4
    NRF_TIMER0->TASKS_CLEAR = 1;
    NRF_TIMER0->TASKS_START = 1;
    NRF_PPI->CHENSET = PPI_CHENSET_CH26_Msk;  // RADIO ADDRESS -> TIMER0 CAPTURE[1]
    last_low = high = 0;
}

uint32_t clock_now32(void) {
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    NRF_TIMER0->TASKS_CAPTURE[0] = 1;
    uint32_t t = NRF_TIMER0->CC[0];
    __set_PRIMASK(primask);
    return t;
}

uint64_t clock_now64(void) {
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    NRF_TIMER0->TASKS_CAPTURE[0] = 1;
    uint32_t low = NRF_TIMER0->CC[0];
    if (low < last_low) high++;
    last_low = low;
    uint64_t t = (uint64_t)high << 32 | low;
    __set_PRIMASK(primask);
    return t;
}

uint64_t clock_extend(uint32_t t32) {
    uint64_t now = clock_now64();
    uint64_t t = (now & ~0xFFFFFFFFull) | t32;
    if (t > now + (1ull << 31)) t -= 1ull << 32;
    else if (now > t + (1ull << 31)) t += 1ull << 32;
    return t;
}

uint32_t clock_address_capture(void) { return NRF_TIMER0->CC[1]; }
