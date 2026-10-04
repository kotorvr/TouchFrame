// The driver's mirror of the link protocol (src/radio_link.h) against the firmware's own header
// (radio-fw/src/link.h): sizes, field offsets and command/event numbers. Fails to compile or
// fails at run time when BUILD-1/BUILD-1b change link.h and the mirror lags.
#include <cstddef>
#include <cstdio>

#include "radio_link.h"  // first: link.h's macros must not touch it

#define _Static_assert static_assert
extern "C" {
#include "../../radio-fw/src/link.h"
}

namespace R = tf::radio;

static int g_fail = 0;
#define SAME_SIZE(ours, theirs)                                                                       \
    do {                                                                                              \
        if (sizeof(R::ours) != sizeof(theirs)) {                                                      \
            printf("FAIL sizeof(%s) %zu != sizeof(%s) %zu\n", #ours, sizeof(R::ours), #theirs, sizeof(theirs)); \
            g_fail++;                                                                                 \
        }                                                                                             \
    } while (0)
#define SAME_OFF(ours, of, theirs, tf)                                                                \
    do {                                                                                              \
        if (offsetof(R::ours, of) != offsetof(theirs, tf)) {                                          \
            printf("FAIL %s.%s at %zu, %s.%s at %zu\n", #ours, #of, offsetof(R::ours, of), #theirs, #tf, \
                   offsetof(theirs, tf));                                                             \
            g_fail++;                                                                                 \
        }                                                                                             \
    } while (0)
#define SAME_VAL(ours, theirs)                                                                     \
    do {                                                                                           \
        if (long(R::ours) != long(theirs)) {                                                       \
            printf("FAIL %s = 0x%lx, link.h %s = 0x%lx\n", #ours, long(R::ours), #theirs, long(theirs)); \
            g_fail++;                                                                              \
        }                                                                                          \
    } while (0)

int main() {
    SAME_VAL(kLinkVersion, LINK_VERSION);
    SAME_VAL(kMaxSlots, LINK_MAX_SLOTS);

    SAME_VAL(CMD_STOP, ::CMD_STOP);
    SAME_VAL(CMD_HELLO, ::CMD_HELLO);
    SAME_VAL(CMD_HOST_START, ::CMD_HOST_START);
    SAME_VAL(CMD_HOST_STATUS, ::CMD_HOST_STATUS);
    SAME_VAL(CMD_PAIR_START, ::CMD_PAIR_START);
    SAME_VAL(CMD_PAIR_STOP, ::CMD_PAIR_STOP);
    SAME_VAL(CMD_CONNECT, ::CMD_CONNECT);
    SAME_VAL(CMD_DISCONNECT, ::CMD_DISCONNECT);
    SAME_VAL(CMD_REG_READ, ::CMD_REG_READ);
    SAME_VAL(CMD_REG_WRITE, ::CMD_REG_WRITE);
    SAME_VAL(CMD_REG_SUBSCRIBE, ::CMD_REG_SUBSCRIBE);
    SAME_VAL(CMD_LED, ::CMD_LED);
    SAME_VAL(CMD_HAPTIC, ::CMD_HAPTIC);
    SAME_VAL(CMD_TIME_PING, ::CMD_TIME_PING);
    SAME_VAL(CMD_PAIR_LIST, ::CMD_PAIR_LIST);
    SAME_VAL(CMD_PAIR_FORGET, ::CMD_PAIR_FORGET);
    SAME_VAL(EVT_TEXT, ::EVT_TEXT);
    SAME_VAL(EVT_RESULT, ::EVT_RESULT);
    SAME_VAL(EVT_HELLO, ::EVT_HELLO);
    SAME_VAL(EVT_HOST_STATUS, ::EVT_HOST_STATUS);
    SAME_VAL(EVT_ADVERT, ::EVT_ADVERT);
    SAME_VAL(EVT_PAIR, ::EVT_PAIR);
    SAME_VAL(EVT_CONN, ::EVT_CONN);
    SAME_VAL(EVT_REG, ::EVT_REG);
    SAME_VAL(EVT_INPUT, ::EVT_INPUT);
    SAME_VAL(EVT_IMU, ::EVT_IMU);
    SAME_VAL(EVT_TIME, ::EVT_TIME);
    SAME_VAL(EVT_UPLINK, ::EVT_UPLINK);
    SAME_VAL(EVT_SAMPLE, ::EVT_SAMPLE);
    SAME_VAL(EVT_SOF, ::EVT_SOF);
    SAME_VAL(EVT_PAIRINGS, ::EVT_PAIRINGS);
    SAME_VAL(HAND_LEFT, LINK_HAND_LEFT);
    SAME_VAL(HAND_RIGHT, LINK_HAND_RIGHT);
    SAME_VAL(LED_STROBE, LINK_LED_STROBE);
    SAME_VAL(HAPTIC_SIMPLE, LINK_HAPTIC_SIMPLE);
    SAME_VAL(FORGET_ALL, LINK_FORGET_ALL);
    SAME_VAL(FORGET_IDENTITY, LINK_FORGET_IDENTITY);

    SAME_SIZE(ResultEvt, link_result_t);
    SAME_SIZE(HelloEvt, link_hello_t);
    SAME_SIZE(HostStart, link_host_start_t);
    SAME_SIZE(PairStart, link_pair_start_t);
    SAME_SIZE(PairEvt, link_pair_event_t);
    SAME_SIZE(PairForget, link_pair_forget_t);
    SAME_SIZE(Pairings, link_pairings_t);
    SAME_SIZE(Pairing, link_pairing_t);
    SAME_SIZE(Connect, link_connect_t);
    SAME_SIZE(ConnEvt, link_conn_event_t);
    SAME_SIZE(RegCmd, link_reg_cmd_t);
    SAME_SIZE(RegEvt, link_reg_event_t);
    SAME_SIZE(InputEvt, link_input_t);
    SAME_SIZE(ImuEvt, link_imu_t);
    SAME_SIZE(SampleEvt, link_sample_t);
    SAME_SIZE(Led, link_led_t);
    SAME_SIZE(Haptic, link_haptic_t);
    SAME_SIZE(TimePing, link_time_ping_t);
    SAME_SIZE(TimePong, link_time_pong_t);

    SAME_OFF(HelloEvt, caps, link_hello_t, caps);
    SAME_OFF(HelloEvt, now_us, link_hello_t, now_us);
    SAME_OFF(PairEvt, hand, link_pair_event_t, hand);
    SAME_OFF(PairEvt, device_id, link_pair_event_t, device_id);
    SAME_OFF(Pairing, hand, link_pairing_t, hand);
    SAME_OFF(Pairings, writes_left, link_pairings_t, writes_left);
    SAME_OFF(ConnEvt, device_id, link_conn_event_t, device_id);
    SAME_OFF(ConnEvt, pulsar_version, link_conn_event_t, pulsar_version);
    SAME_OFF(InputEvt, buttons, link_input_t, buttons);
    SAME_OFF(InputEvt, battery_pct, link_input_t, battery_pct);
    SAME_OFF(InputEvt, touch, link_input_t, touch);
    SAME_OFF(InputEvt, stick, link_input_t, stick);
    SAME_OFF(InputEvt, trigger, link_input_t, trigger);
    SAME_OFF(InputEvt, grip, link_input_t, grip);
    SAME_OFF(InputEvt, pressure, link_input_t, pressure);
    SAME_OFF(ImuEvt, accel, link_imu_t, accel);
    SAME_OFF(ImuEvt, gyro, link_imu_t, gyro);
    SAME_OFF(ImuEvt, accel_fs_g, link_imu_t, accel_fs_g);
    SAME_OFF(ImuEvt, gyro_fs_dps, link_imu_t, gyro_fs_dps);
    SAME_OFF(SampleEvt, accel, link_sample_t, accel);
    SAME_OFF(SampleEvt, gyro, link_sample_t, gyro);
    SAME_OFF(Led, period_us, link_led_t, period_us);
    SAME_OFF(Led, on_us, link_led_t, on_us);
    SAME_OFF(Led, phase_us, link_led_t, phase_us);
    SAME_OFF(Haptic, freq_hz, link_haptic_t, freq_hz);
    SAME_OFF(Haptic, duration_ms, link_haptic_t, duration_ms);
    SAME_OFF(TimePong, dongle_rx_us, link_time_pong_t, dongle_rx_us);
    SAME_OFF(TimePong, dongle_tx_us, link_time_pong_t, dongle_tx_us);

    printf(g_fail ? "link_check_test: %d mismatch(es) with radio-fw/src/link.h\n" : "link_check_test passed\n", g_fail);
    return g_fail ? 1 : 0;
}
