# driver_touchframe with the Touch Plus radio dongle

`driver_touchframe.mode` picks where the Touch Plus state comes from:

| mode | source | 6DoF | calibration |
|---|---|---|---|
| `relay` (default) | the Quest bridge over UDP | the Quest's tracking | `tools/frame.sh calibrate` |
| `radio_camera` | the nRF52840 dongle (link v3, `radio-fw/`) | XRService's camera tracker, from the LEDs | none: poses are in SteamVR's space |
| `radio_3dof` | the dongle | rotation from the IMU, position from an arm model | none |

Setup: `tools/install.sh frame`, then `MODE=radio_camera tools/install.sh radio`. That copies the
XRService LED-model configs and Meta's IMU calibration (from `tools/touchplus_config.py`) to
`~/.config/touchframe/` and checks the dongle's hidraw node.

## Transport
The Frame has no `cdc_acm`, so the driver talks to the dongle's vendor HID interface through
`/dev/hidrawN`. `radio_transport` = `hidraw` finds the node whose `HID_ID` is `1209:0001`. The node
is 0664 root:input and steamos is in group input, so no udev rule is needed. The Frame has one
USB-C port, so use a hub. Other transports, for tests: `hidraw:/dev/hidraw3`, `tcp:HOST:PORT`
(`tools/fake_dongle.py --tcp`), and `tcphid:HOST:PORT` (`driver/test/fake_dongle_server.py --framing hid`).

## Settings (section `driver_touchframe`)
| key | default | |
|---|---|---|
| `mode` | `relay` | `relay`, `radio_camera` or `radio_3dof` |
| `radio_transport` | `hidraw` | see above |
| `radio_state` | `~/.config/touchframe/radio_state.json` | identity and hand per controller (radio.py-compatible) |
| `radio_identity_mode` | `auto` | `stored` (the dongle's flash), `driver` (the state file), `auto` = stored if the dongle can |
| `radio_config_left/right` | `~/.config/touchframe/touchplus_<hand>.json` | XRService controller config (LED model). Sent as is, with `model_number` `TouchFrame_TouchPlus_<Hand>_Roy_EV1.5` |
| `radio_imu_cal_left/right` | `~/.config/touchframe/touchplus_<hand>_meta_cal.json` | Meta's per-unit IMU calibration, `M·(raw − offset)` (order INFERRED); skipped if missing |
| `radio_device_id_left/right` | 0 (= 48 / 49) | XRService deviceId, 16..63 |
| `radio_led_loop` | true | camera mode: the LED phase closed loop (below) |
| `radio_led_period_us` | 33333.333 | controller-frame period (mode 4, 30 Hz) |
| `radio_led_window_us` | 65 | pulse 75 µs − exposure 10 µs (docs/re/FRAME-MODEL.md §3.3) |
| `radio_led_seed_offset_us` | 0 | pulse centre minus XRService's logged frame timestamp; the log reports the measured value once tracking |
| `radio_led_dwell_s`, `radio_led_settle_s` | 1.5, 0.5 | probe length, and how long to ignore XRService after a change |
| `radio_create_queues` | true | Touch-only: create XRService's controller queues if no Steam Frame controller did... |
| `radio_create_queues_after_s` | 20 | ...after this long. Cost: the first Frame controller turned on later in that SteamVR session gets no pose until SteamVR restarts (docs/re/DEV-1.md) |
| `radio_xrservice_logs` | `""` (= `~/.local/share/Steam/logs`) | where XRService's log is read for LED hits and frame timestamps; `-` = off |
| `radio_reannounce` | true | camera: re-announce a hand under a fresh deviceId when a competing controller for that hand turns off |
| `radio_pair_version`, `radio_pair_hand` | 0, `right` | bump the version to pair the next controller in pairing mode as that hand |
| `radio_recenter_version` | 0 | 3dof: bump to re-align yaw with the headset |

## LED phase loop (camera mode)
The Touch Plus can only strobe its LEDs (pulses ≤ 75 µs, centred at a phase on the dongle clock).
XRService's controller frames expose for 10 µs at 30 Hz, so the pulse must sit within ±32.5 µs of
the exposure. We have no tap on the exposure schedule, so `led_phase.h` finds and holds the phase
from what XRService gives back: pose validity on our pose queue, `[ContrLedsStats N]` lines, and
any controller-frame timestamps in its log. It searches at P/16 (16 phases per probe), tracks
there to learn the camera's clock drift, works out which of the 16 is the real one, then tracks
at P with sentinel probes. The sim in `driver/test/radio_unit_test.cpp` covers camera drift up to
±25 ppm. Thresholds and dwell times are the model's guesses until hardware day.

## Tests
`driver/test/run.sh` builds and runs everything on the PC: config parsing, `link_check_test`
(this mirror against `radio-fw/src/link.h`), the unit tests (COBS/HID, time sync, decode, the
LED loop against a camera model), RadioSource against `tools/fake_dongle.py` over raw and HID
framing plus a dongle reboot, and RadioBackend in both modes. `QUICK=1` skips the fake-dongle runs.
