#include "radio_engine.h"

#include <string.h>

#include "clock.h"
#include "nrf.h"
#include "pulsar_ll.h"

#define PPI_CH_START 0  // TIMER0 COMPARE[2] -> RADIO TXEN or RXEN

enum { ST_IDLE, ST_ARMED, ST_ACTIVE };

static const engine_core_t* core;
static volatile bool halted = true;
static uint8_t state;
static radio_op_t op;
static bool closing;  // RX window over: stop after the packet in flight
static uint8_t buf[2 + 256];
static uint32_t late;
static int8_t tx_power;

static uint32_t txpower_reg(int8_t dbm) {
    static const struct { int8_t dbm; uint32_t reg; } steps[] = {
        {8, RADIO_TXPOWER_TXPOWER_Pos8dBm}, {7, RADIO_TXPOWER_TXPOWER_Pos7dBm}, {6, RADIO_TXPOWER_TXPOWER_Pos6dBm},
        {5, RADIO_TXPOWER_TXPOWER_Pos5dBm}, {4, RADIO_TXPOWER_TXPOWER_Pos4dBm}, {3, RADIO_TXPOWER_TXPOWER_Pos3dBm},
        {2, RADIO_TXPOWER_TXPOWER_Pos2dBm}, {0, RADIO_TXPOWER_TXPOWER_0dBm}, {-4, RADIO_TXPOWER_TXPOWER_Neg4dBm},
        {-8, RADIO_TXPOWER_TXPOWER_Neg8dBm}, {-12, RADIO_TXPOWER_TXPOWER_Neg12dBm},
        {-16, RADIO_TXPOWER_TXPOWER_Neg16dBm}, {-20, RADIO_TXPOWER_TXPOWER_Neg20dBm},
    };
    for (unsigned i = 0; i < sizeof steps / sizeof steps[0]; i++)
        if (dbm >= steps[i].dbm) return steps[i].reg;
    return RADIO_TXPOWER_TXPOWER_Neg40dBm;
}

void engine_init(void) {
    NRF_PPI->CH[PPI_CH_START].EEP = (uint32_t)&NRF_TIMER0->EVENTS_COMPARE[2];
    NRF_PPI->CHENCLR = 1u << PPI_CH_START;
    NRF_TIMER0->INTENCLR = TIMER_INTENCLR_COMPARE2_Msk | TIMER_INTENCLR_COMPARE3_Msk;
    NVIC_SetPriority(TIMER0_IRQn, 0);
    NVIC_SetPriority(RADIO_IRQn, 0);
    tx_power = 0;
}

static void radio_off(void) {
    NRF_PPI->CHENCLR = 1u << PPI_CH_START;
    NRF_TIMER0->INTENCLR = TIMER_INTENCLR_COMPARE3_Msk;
    NRF_RADIO->INTENCLR = 0xFFFFFFFF;
    NRF_RADIO->SHORTS = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE = 1;
    while (!NRF_RADIO->EVENTS_DISABLED) {}
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->EVENTS_ADDRESS = 0;
    NRF_TIMER0->EVENTS_COMPARE[2] = 0;
    NRF_TIMER0->EVENTS_COMPARE[3] = 0;
}

void engine_halt(void) {
    NVIC_DisableIRQ(RADIO_IRQn);
    NVIC_DisableIRQ(TIMER0_IRQn);
    halted = true;
    radio_off();
    state = ST_IDLE;
    NVIC_ClearPendingIRQ(RADIO_IRQn);
    NVIC_ClearPendingIRQ(TIMER0_IRQn);
}

void engine_attach(const engine_core_t* c) {
    engine_halt();
    core = c;
}

void engine_detach(void) {
    engine_halt();
    core = NULL;
}

void engine_kick(void) {
    if (!core) return;
    halted = false;
    NVIC_ClearPendingIRQ(TIMER0_IRQn);
    NVIC_EnableIRQ(TIMER0_IRQn);
    NVIC_EnableIRQ(RADIO_IRQn);
    NVIC_SetPendingIRQ(RADIO_IRQn);  // the ISR asks the core for its next op
}

void engine_set_tx_power(int8_t dbm) { tx_power = dbm; }
uint32_t engine_late_ops(void) { return late; }
bool engine_active(void) { return core && !halted; }

static uint8_t hdr_len(void) { return op.addr.profile == RADIO_PROFILE_CONNECTED ? 2 : 1; }

static void configure(void) {
    const radio_addr_t* a = &op.addr;
    bool s0 = a->profile == RADIO_PROFILE_CONNECTED;
    NRF_RADIO->MODE = RADIO_MODE_MODE_Nrf_2Mbit;
    NRF_RADIO->MODECNF0 = RADIO_MODECNF0_RU_Fast << RADIO_MODECNF0_RU_Pos;
    NRF_RADIO->PCNF0 = (8u << RADIO_PCNF0_LFLEN_Pos) | ((s0 ? 1u : 0u) << RADIO_PCNF0_S0LEN_Pos) |
                       (RADIO_PCNF0_PLEN_8bit << RADIO_PCNF0_PLEN_Pos);
    NRF_RADIO->PCNF1 = (255u << RADIO_PCNF1_MAXLEN_Pos) | (4u << RADIO_PCNF1_BALEN_Pos) |
                       (RADIO_PCNF1_ENDIAN_Big << RADIO_PCNF1_ENDIAN_Pos);
    NRF_RADIO->CRCCNF = RADIO_CRCCNF_LEN_Three << RADIO_CRCCNF_LEN_Pos;  // SKIPADDR = 0: address in the CRC
    NRF_RADIO->CRCPOLY = 0x108421;
    NRF_RADIO->CRCINIT = 0xFFFFFF;
    NRF_RADIO->BASE0 = a->base0;
    NRF_RADIO->BASE1 = a->base1;
    NRF_RADIO->PREFIX0 = (uint32_t)a->prefix[0] | (uint32_t)a->prefix[1] << 8 | (uint32_t)a->prefix[2] << 16 |
                         (uint32_t)a->prefix[3] << 24;
    NRF_RADIO->PREFIX1 = (uint32_t)a->prefix[4] | (uint32_t)a->prefix[5] << 8 | (uint32_t)a->prefix[6] << 16 |
                         (uint32_t)a->prefix[7] << 24;
    NRF_RADIO->TXADDRESS = a->tx_addr;
    NRF_RADIO->RXADDRESSES = a->rx_mask;
    NRF_RADIO->FREQUENCY = a->freq;
    NRF_RADIO->TXPOWER = txpower_reg(tx_power);
    NRF_RADIO->PACKETPTR = (uint32_t)buf;
}

// Ask the core for ops until one can be armed in time (or it has none). ISR context.
static void start_next(void) {
    while (core && !halted) {
        uint64_t now = clock_now64();
        if (!core->next_op(core->ctx, now, &op)) {
            state = ST_IDLE;
            return;
        }
        bool tx = op.kind == RADIO_OP_TX;
        uint64_t trig = op.start_us - (tx ? ENGINE_TX_TO_ADDRESS_US : ENGINE_RX_RAMP_US);
        if ((int64_t)(trig - now) < ENGINE_MIN_LEAD_US) {
            late++;  // too late to hit the start time: report it done untouched, the core moves on
            core->on_done(core->ctx, &op, now);
            continue;
        }
        configure();
        if (tx) {
            uint8_t h = hdr_len();
            if (h == 2) buf[0] = PULSAR_S0;
            buf[h - 1] = op.len;
            memcpy(buf + h, op.payload, op.len);
            NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_END_DISABLE_Msk;
            NRF_PPI->CH[PPI_CH_START].TEP = (uint32_t)&NRF_RADIO->TASKS_TXEN;
        } else {
            NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_ADDRESS_RSSISTART_Msk |
                                RADIO_SHORTS_DISABLED_RSSISTOP_Msk;
            NRF_PPI->CH[PPI_CH_START].TEP = (uint32_t)&NRF_RADIO->TASKS_RXEN;
            NRF_TIMER0->CC[3] = (uint32_t)(op.start_us + op.window_us);
            NRF_TIMER0->EVENTS_COMPARE[3] = 0;
            NRF_TIMER0->INTENSET = TIMER_INTENSET_COMPARE3_Msk;
        }
        closing = false;
        NRF_RADIO->EVENTS_END = 0;
        NRF_RADIO->EVENTS_DISABLED = 0;
        NRF_RADIO->EVENTS_ADDRESS = 0;
        NRF_RADIO->INTENSET = RADIO_INTENSET_END_Msk | RADIO_INTENSET_DISABLED_Msk;
        NRF_TIMER0->CC[2] = (uint32_t)trig;
        NRF_TIMER0->EVENTS_COMPARE[2] = 0;
        NRF_PPI->CHENSET = 1u << PPI_CH_START;
        state = ST_ARMED;
        // Re-check: if the compare time slipped past while we were programming, it will not fire.
        if ((int32_t)((uint32_t)trig - clock_now32()) <= 1 && !NRF_TIMER0->EVENTS_COMPARE[2]) {
            NRF_PPI->CHENCLR = 1u << PPI_CH_START;
            radio_off();
            late++;
            core->on_done(core->ctx, &op, clock_now64());
            continue;
        }
        return;
    }
    state = ST_IDLE;
}

static void finish(void) {
    NRF_PPI->CHENCLR = 1u << PPI_CH_START;
    NRF_TIMER0->INTENCLR = TIMER_INTENCLR_COMPARE3_Msk;
    state = ST_IDLE;
    core->on_done(core->ctx, &op, clock_now64());
    start_next();
}

void engine_radio_irq(void) {
    if (halted || !core) {
        NVIC_ClearPendingIRQ(RADIO_IRQn);
        return;
    }
    if (state == ST_IDLE) {  // kicked
        start_next();
        return;
    }
    if (NRF_RADIO->EVENTS_END) {
        NRF_RADIO->EVENTS_END = 0;
        state = ST_ACTIVE;
        if (op.kind == RADIO_OP_RX) {
            uint8_t h = hdr_len();
            uint8_t len = buf[h - 1];
            radio_rx_t rx = {clock_extend(clock_address_capture()), op.addr.freq, op.addr.profile,
                             (uint8_t)NRF_RADIO->RXMATCH, (int8_t)-(int32_t)NRF_RADIO->RSSISAMPLE,
                             NRF_RADIO->CRCSTATUS != 0, len, buf + h};
            NRF_RADIO->EVENTS_ADDRESS = 0;
            core->on_rx(core->ctx, &rx);  // the core copies what it keeps
            if (op.rx_multi && !closing) NRF_RADIO->TASKS_START = 1;
            else NRF_RADIO->TASKS_DISABLE = 1;
        }
    }
    if (NRF_RADIO->EVENTS_DISABLED) {
        NRF_RADIO->EVENTS_DISABLED = 0;
        finish();
    }
}

void engine_timer_irq(void) {
    if (!NRF_TIMER0->EVENTS_COMPARE[3]) return;
    NRF_TIMER0->EVENTS_COMPARE[3] = 0;
    NRF_TIMER0->INTENCLR = TIMER_INTENCLR_COMPARE3_Msk;
    if (halted || op.kind != RADIO_OP_RX) return;
    if (NRF_RADIO->EVENTS_ADDRESS) {
        closing = true;  // a packet is coming in: the END handler stops after it
    } else {
        NRF_PPI->CHENCLR = 1u << PPI_CH_START;
        if (NRF_RADIO->STATE == RADIO_STATE_STATE_Disabled) {
            finish();  // never started (cannot happen once armed in time, but be safe)
        } else {
            NRF_RADIO->TASKS_DISABLE = 1;  // -> DISABLED -> finish()
        }
    }
}
