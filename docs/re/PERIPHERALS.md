# Touch Plus peripherals: IR LEDs, IMU, input map, haptics, calibration (RE-2)

Static RE only, 2026-10-04, against OTA build 52433670048800520 (elk-app `ruby_prq` git
`edbf4671d29b`, deerfly-app same git, host `odm/lib64/libsyncboss.so`). No device was touched.

Tags: **CONFIRMED** = read in code/data (decompile checked against disassembly where it matters);
**INFERRED** = strongly implied; **UNKNOWN** = not established. Addresses: elk-app and deerfly are
Ghidra load addresses (elk base `0x14000`, deerfly base `0x6800`, i.e. `dAeH` vector address
`0x6900` − 0x100). libsyncboss addresses are ELF vaddrs (Ghidra shows them +0x100000).

**New source used:** `libsyncboss.so` carries a `.gnu_debugdata` section (xz MiniDebugInfo) with
**1044 internal function names** (`pulsar_manager_set_led_timing`, `update_irled_config_work`,
`controller_process_notification`, `pulsar_input_cache.c` enumeration, ...). Extract with
`lzma.decompress(section('.gnu_debugdata'))` and apply as labels; every host claim below cites
those names.

---

## 0. Answers first

### G-LED: can the LEDs be held on? **No. Strobe only: max 75 µs per pulse, pulses phase-locked to the host clock.**

- **On-time is hard-capped at 75 µs** (CONFIRMED). The cap is set once at boot
  (`elk 0x16ea8 movs r3,#0x4b` → `0x20004c28+0xa0`) and nothing else writes it. A host write of a
  larger on-time is **silently clamped**, not rejected: the reg-0x28 write handler does
  `ot = min(ot_req, 75)` (`elk 0x27fe6..0x27ff0`) before validating.
- **Period ≤ 500 000 µs, and on-time ≤ period** (CONFIRMED, validator `elk FUN_0001fbb8`).
  Anything else is rejected with `"IR LED configuration rejected: p=%lu, ot=%lu, d=%li"` and the
  old config stays.
- **Effective duty is ~9 % at the very best** (INFERRED from CONFIRMED code). Each pulse is a
  one-shot timer compare pair, re-armed in software after the previous pulse ends. The next start
  is the next grid point at least **700 µs** ahead (`elk FUN_0001873c`: `if (min_lead < 700)
  min_lead = 700`, then *one* extra period if the lead is short). With p ≥ ~800 µs a pulse can
  land on every grid point, so duty ≤ 75/800. With p < 700 µs the floor is applied only once and
  the lead can drop below the firmware's own 700 µs safety margin. A missed compare would starve
  the 1 s "IR LED timeout" assert (a controller reset), so **never send p < 700 µs**. The design
  is evidently "short, rare pulses": the Quest default is **19 µs every 33 333 µs (0.06 %)**.
- **`ot = 0` turns the LEDs off** without stopping the LED thread (CONFIRMED,
  `elk FUN_0001554c`, `local_20 == 0` branch).
- **Phase is defined on the host's clock** (CONFIRMED): pulse *start* is the next time `t` (≥ now
  + 700 µs) with `t ≡ (d − ot/2) (mod p)` in **translator time**, the controller's copy of the
  host's Pulsar clock. So **`d` is the pulse centre** modulo the period. Our dongle *is* the host,
  so if the driver knows the Frame's controller-camera exposure times in dongle µs, one reg-0x28
  write places every pulse inside every exposure.

**Consequence for the plan (MASTER-PLAN §3.1.5, §6 G-LED):** "always on" is impossible. 6DoF on
the Frame needs **strobing in sync with the Frame controller-frame exposures**: RE-3's exposure
schedule tap, plus dongle-clock ↔ CLOCK_MONOTONIC_RAW sync. Choose `p` equal to the
controller-frame period (or a multiple), `d` equal to the exposure centre in dongle time mod `p`,
and `ot` up to 75 µs. The 75 µs max is the knob that buys tolerance for sync error. A fallback with
no sync, like many pulses per frame, doesn't work: the re-arm scheduling limits it to about one
pulse per ~0.8 ms, which only helps if the Frame exposure is ≥ ~0.8 ms.

**Quest-side knobs for Gate B over the relay (no dongle):** the sensors HAL exposes a debug
command `setTalDeviceIrLedConfig <deviceId> <ontimeUs>` / `getTalDeviceIrLedConfig <deviceId>`
(strings in `odm/bin/hw/vendor.oculus.hardware.sensors@1.0-service`, usage line
`lshal debug [AndroidSensors service name] ...`) that ends in `syncboss_input_set_led_ontime_us` →
`pulsar_manager_set_led_ontime_us` (INFERRED path; the strings are CONFIRMED). The service
range-checks it (`"Invalid ontime %d, max is %d"`), and the tracking engine refuses values above
"what headset allows". Only the **on-time** is settable from the OS:
`syncboss_input_set_led_config` logs `"Only IRLED on time can be set from the OS; this will not
modify period or delay"` (CONFIRMED, `libsyncboss 0x535fc`). Period/delay follow the headset's
camera cadence (`syncboss_nice_config_constellation 0x10e04`,
`stream_processor_NICE_nice_constellation_config 0x10ee4`). For DEV-1's relay Gate B, raising the
on-time from 19 to 75 µs (if the service max allows) gives ~4× the chance of a Frame exposure
catching a pulse. No system property for LED timing was found (the only `persist.vendor.syncbosshal.*`
props are version-check, pulsar_manager, telemetry, camera-init, spoof, TX-slot).

### IMU (CONFIRMED unless noted)
ICM-42686 (WHO_AM_I 0x44) at **±32 g, ±4000 dps, 500 Hz** accel and gyro. The controller reports
its own scale in cmd 0x32 (`imu_config`): **accel 1/1024 g/LSB, gyro 1/8.192 dps/LSB**. The host
converts with `a[m/s²] = raw·f_acc·9.80665` and `ω[rad/s] = raw·f_gyr·π/180`. Samples arrive as
notification chunk **type 1** (18 B: 48-bit µs timestamp in host/translator time + 3×i16 accel +
3×i16 gyro), **not** reg 0xb/0x16 (PROTOCOL Q4 is wrong there, §8).

### Input map (CONFIRMED via host labels + elk remap)
Buttons = **notification reg 4** (A/X, B/Y, stick-click, system/menu). Capacitive touch +
proximity = **reg 9** (12 bits). Thumbstick = **reg 2** (2×i16). Index trigger + grip = **reg 3**
(two 12-bit). Deerfly buf `0x31/0x33` are **not** stick axes: they are index-finger "curl" joint
angles (reg 0x17). Buf `0x37` is **index-trigger pressure**, not battery.

### Haptics (CONFIRMED)
Simple: write reg **0x97** = 1 byte amplitude (0 = stop; auto-stop after 2 s unless refreshed).
Amplitude+frequency: reg **0xa0** = `{u8 amp, u16 freq_hz 40..561}`. PCM: reg **0x9d** = 31-byte
IMA-ADPCM chunks of 72 samples. Sync buffer: reg **0x9b** = `{u8 len≤31, len bytes}`.
`set_multi_haptics` (reg 0x9c) is **not supported** by Touch Plus elk.

---

## 1. Three register spaces (do not mix them)

| Space | Who reads/writes | Dispatch (controller) | Notes |
|---|---|---|---|
| **Command registers** ("pulsar registers") | host `pulsar_read` / `pulsar_write` / `pulsar_manager_read_sync` / `pulsar_manager_queue_*write*` | read: `elk FUN_00025c98` (switch on reg id); write: `elk FUN_00027ebc` (`app_command_registers.c`). Both registered by the CL device init (`elk 0x18d38/0x18d3c` hold `0x27ebd`, `0x25c99`) | ids up to 0xb6; carries LED config, IMU config, calibration blob, haptics, "data ready" |
| **Notification registers** ("ntf"/hreg) | controller pushes; host parses chunks in `controller_process_notification` (`libsyncboss 0x57324`) | elk table `0x2e7dc` (16-B entries `{data*, ?, ?, size \| count<<8}`, ids `0..0x2d`), writer `elk FUN_0001f464(id, &val)` | the streaming input path: buttons, sticks, IMU, battery, LED echo |
| **Deerfly SPI registers** | elk ↔ deerfly over SPI | elk `FUN_00021fd4(reg, buf, len)` read, `FUN_00022154(reg, buf, len)` write | reg 0x37 = 61-B input sample, reg 0x4a = haptics drive, reg 0x02 status, 0x59 cal write |

The ids overlap numerically (for example command 9 = "data ready" vs ntf 9 = touch flags), which
is why PROTOCOL Q4's table got confused.

### 1.1 Notification chunk framing (CONFIRMED, host side)
`controller_process_notification` (`0x57324`) skips a 0x14-byte notification header (byte 0x13
must be 0, else `"Unexpected controller notification register %i"`; an optional sidechannel chunk
may precede the chunks; framing is RE-1's area), then iterates chunks with `ntf_unpacker_next`
(`0x12e74`). Each chunk is a little-endian u16 header plus payload:

| bits | meaning |
|---|---|
| 0..4 | chunk type bits 0..4 |
| 5..10 | payload length in bytes (0..63) |
| 11 | chunk type bit 5 (`type = (h & 0x1f) \| ((h >> 6) & 0x20)`) |
| 12..14 | fragment sequence number (0 = first) |
| 15 | last fragment |

`(h & 0xf000) == 0x8000` is an unfragmented chunk. Fragments of the same type with seq n+1 are
appended; the total must stay < 64 bytes; the reassembled chunk is delivered when bit 15 is set.
**Chunk type = ntf register id** (CONFIRMED: sizes match the elk table, e.g. type 1 = 18 B,
0xb = 12 B, 3 = 3 B). Implemented in `tools/pulsar_input.py unpack_chunks`.

### 1.2 Host enumeration sequence (CONFIRMED, `input_refresh_cache 0x5d090`)
What a real headset does once per newly connected controller (all `pulsar_read`/`pulsar_write`,
timeout 0x960 = 2400 ms):

1. write cmd **0x20** = `00` (select primary MCU), read **0x24** (28 B app version), **0x25** (28 B DM version); if the type has a secondary MCU: write 0x20 = `01`, read 0x24, write 0x20 = `00`.
2. read **0x32** `imu_config` (16 B) → cache `+0x49c`.
3. read **0x31** `imu_info` (16 B) → `+0x4ac`.
4. read **3** `assembly_sn` (16 B), **2** `pcb_sn` (16 B), **1** `device_desc` (32 B).
5. read **0x2f** `battery_info` (9 B).
6. read **10** capabilities (8 B) → `+0x47e` (bit 1 = PCM haptics, bit 11 = settable IR LED on-time, byte1 bit0 = dual IMU, byte0 bit7 = fft).
7. assert check; optional reads 0x54 (dual-IMU config, 9 B), 0xb6 (fft config, 9 B).
8. **write cmd 9 = `00` "data ready signal"**. On elk this signals the streaming thread (`FUN_00027ebc` case 9). INFERRED: a non-Meta host must send it before input/IMU notifications flow.
9. write cmd **0xa1** = `00` (unless a headset flag is set). elk: signals thread 5 flag 0x40.
10. then `pulsar_manager_refresh_controller_led_config` → cmd **0x28** (see §2).

---

## 2. IR LEDs

### 2.1 Command 0x28: LED config (CONFIRMED both sides)
Payload is 12 bytes, little-endian:

| off | type | field |
|---|---|---|
| 0 | u32 | `period_us` (p) |
| 4 | u32 | `ontime_us` (ot) |
| 8 | i32 | `delay_us` (d): pulse **centre** phase on the host clock, mod p |

- Host: `pulsar_manager_set_single_led_config_internal` (`0x5c0b0`) →
  `pulsar_write(h, dev, 0x28, {p, ot, d}, 0xc, 0x960)`, log `"Setting controller ID %08x%08x LED
  config to period: %uus, on-time: %uus, delay: %dus"`. Host default on-time when none was set:
  **19 µs** (`0x13`, same function). Period/delay are global (`DAT 0x1af8f8/0x1af8fc`), set from the
  headset's camera cadence (`pulsar_manager_set_led_period_delay_us 0x5ad54`).
- Readback: `pulsar_manager_read_sync(dev, 0x28, len 0xc)` (`syncboss_input_get_led_config
  0x533a0`); elk read case 0x28 returns the applied config (`elk FUN_00025c98`).
- Echo: the controller pushes the applied `{p, ot, d}` as **ntf reg 0xb** (`elk FUN_00014c1c`:
  `FUN_0001f464(0xb, …)`, registered as the irled callback `+0xb8` in `elk FUN_00016e7c`). The host
  compares it with its cache and re-sends 0x28 on mismatch (`"%08x%08x: Shutter / IRLED mismatch,
  period = %u/%u, ontime = %u/%u, delay = %d/%d"`, notification case for type 0xb).

### 2.2 Limits and defaults (CONFIRMED, `elk FUN_00016e7c @ 0x16e7c`, disasm 0x16e98..0x16eb0)
Init struct on the stack (`sp+0x14`): `{p = 0x8235 = 33333, ot = 19, d = −9, max_ot = 0x4b = 75,
max_p = 0x7a120 = 500000, 0x12, …}`. `max_ot`/`max_p` are copied to `0x20004c28+0xa0/+0xa4`,
then the defaults are validated and applied.

Validator `elk FUN_0001fbb8`: reject if `ot > max_ot || ot > p || p > max_p`; otherwise copy
`{p, ot, d}` to `0x200069f8` under a critical section and wake the LED thread. Write handler
`elk FUN_00027ebc` case 0x28 (`0x27fdc`): `ot = min(ot, max_ot)`, logs `"IR LED configured: p=%lu,
ot=%lu, d=%li"`, then validates. There is no minimum period check beyond `ot ≤ p`. There is
**no current/brightness field** in the controller's LED config.

### 2.3 Pulse generation (CONFIRMED unless noted)
- LED thread `elk FUN_0001554c` (`irled_manager.c`): powers the LED rail via callback `+0xb0` =
  `0x16e51` (`FUN_000160e0(3, on)`, plus GPIO 0x11 on board ids 1..5), waits for system time, sets
  up a sync trigger (`sync_trigger.c`) on an nRF52 TIMER with two compare channels driving a GPIOTE
  output via PPI (start CC / end CC; `"Pulse start CC (%d) and pulse end CC (%d) must not be the
  same"`, `elk FUN_00029308`).
- Per config message: `period = p`, `pulse = ot`, `offset = d − ot/2`, then arm (`FUN_000293ac`).
- Arm (`FUN_000293ac @ 0x293ac`): gets current translator time (`FUN_000250ac`, `"Failed to get
  current translator time"`), computes the next aligned start with `FUN_0001873c(p, offset, …,
  min_lead)` (`sync_helpers.c`: next `t ≥ now + max(min_lead, 700)` with `t ≡ offset (mod p)`),
  converts to local time (`FUN_00028d6c`) and programs start CC = t, end CC = t + ot.
- End-of-pulse ISR callback `0x1b531` → `+0xb4` = `0x14815` → `FUN_00027d74(4, 1)` signals the
  thread, which re-arms the next pulse (INFERRED that thread index 4 is the LED thread).
- The thread asserts `"IR LED timeout"` if no event arrives within 1000 ms. That is consistent
  with `max_p = 500 ms` (INFERRED: the period cap exists so the watchdog never trips).
- `min_lead` = `+0x6c` copied to `+0x10`, never written after the init `memset`, so it is 0 and
  floored to **700 µs**. The floor adds at most one period (`if (delta < min_lead) delta += p`),
  so for p < 700 µs the lead can stay under 700 µs. Modelled in
  `tools/pulsar_input.py next_pulse_start`.

### 2.4 Host-side LED APIs that are *not* the controller IR LEDs
`syncboss_led_set_on_time_and_current(_v2/_sequence)`, `syncboss_led_*` (`0x6bec8..0x6cabc`) use
`syncboss_set_data(0x99/0x9a)` to the **headset** MCU (headset LEDs/illuminators). They have
current fields, but they don't reach the controller. CONFIRMED.

---

## 3. IMU

### 3.1 Part, range and rate (CONFIRMED, `elk 0x16cc8` + driver `elk FUN_00026df8`)
- Driver chosen by board id (`elk FUN_00016bcc`): ids 0x90..0x93, 0x96, 0x97 → ICM-476xx vtable
  `0x2e438`; otherwise ICM-426xx vtable `0x2e378` (0x98 logs "LSM6DSV not supported").
- ICM-426xx config (24 B copied from flash `0x2e1fc`): accel_range idx 0, accel_odr idx 6,
  gyro_range idx 0, gyro_odr idx 6. Model from WHO_AM_I (reg 0x75): 0x41 → 42602, **0x44 →
  42686**, 0x47 → 42688. Per-model code tables: accel range `0x31394`, gyro range `0x31544`,
  accel ODR `0x312bc`, gyro ODR `0x31464`. For the 42686 (column 1):

| idx | accel code / FS / LSB/g | gyro code / FS / LSB/dps | ODR code / Hz |
|---|---|---|---|
| 0 | 0x00 / ±32 g / **1024** | 0x00 / ±4000 dps / **8.192** | |
| 6 | | | 0x0f / **500 Hz** (accel and gyro) |

  The register writes match: GYRO_CONFIG0 (0x4f) = FS<<5 | ODR, ACCEL_CONFIG0 = FS<<5 | ODR,
  GYRO_ACCEL_CONFIG0 (0x52) from config bytes 0x14/0x15 (both 0).
- Temperature: 132.48 LSB/°C (42686/42688; 126.8 for 42602), offset 25 °C (`0x31af8`, `+0x24 =
  25.0f`).
- ICM-47688 boards (INFERRED, struct offsets assumed): ±32 g / ±4000 dps, **800 Hz**. The driver
  must not hardcode: read cmd 0x32.

### 3.2 Command 0x32 `imu_config` (16 B, CONFIRMED both sides)
elk read case 0x32 (`FUN_00025c98`) fills, from the driver vtable:

| off | type | value (42686) | source |
|---|---|---|---|
| 0 | u16 | accel range = 32000 (mg) | vt+0x60 → accel-range entry +8 |
| 2 | u16 | gyro range = 4000 (dps) | vt+0x68 |
| 4 | u16 | accel ODR = 500 (Hz) | vt+0x6c |
| 6 | u16 | gyro ODR = 500 (Hz) | vt+0x70 |
| 8 | f32 | **accel g/LSB = 1/1024** | vt+0x3c(1) = `1.0 / 1024.0` (`FUN_00022bac`) |
| 12 | f32 | **gyro dps/LSB = 1/8.192** | vt+0x44(1) = `1.0 / 8.192` (`FUN_00022bd4`) |

The host caches it at `+0x49c`. The notification decoder multiplies by `*(f32*)(+0x4a4)`
(bytes 8..11) × 9.80665 for accel, and by `*(f32*)(+0x4a8)` (bytes 12..15) × 0.017453292 for
gyro (CONFIRMED, case type 1 in `controller_process_notification`, AArch64 at `0x57bf8..0x57c70`).
cmd 0x31 `imu_info` = 16-byte model string (vt+0x7c, `"ICM42686"`). cmd 0x33 = 4 B IMU
temperature (`syncboss_input_get_imu_temp`).

### 3.3 Notification type 1: IMU sample (18 B, CONFIRMED)
Built by the IMU thread `elk FUN_00015280 @ 0x15280` (`imu_thread.c`):

| off | type | field |
|---|---|---|
| 0 | u48 LE | timestamp, µs, **translator (host) time** (`FUN_000250e4(local_irq_time)`) |
| 6 | i16 ×3 | accel x, y, z (raw) |
| 12 | i16 ×3 | gyro x, y, z (raw) |

- One sample per IMU data-ready (500 Hz). The ntf slot holds a queue of 6 (`0x2e7ec` size field
  `0x612`; INFERRED that up to 6 can be buffered across lost uplinks).
- Temperature goes separately to **ntf 0x28** (i32 raw, only when it changes).
- Host checks (`controller_process_imu_timestamp_data 0x58ec8`): delta ≤ 0 → "IMU stall";
  |delta| > 48 000 → "IMU corrupt"; delta > 2099 → missed = (delta + 1000)/2000 − 1 (division
  magic `0x20c49ba5e353f7cf` with the 2000 shift). So the host expects **2000 µs** spacing
  (INFERRED, consistent with 500 Hz).
- Type 0x1b (24 B) is a dual-accelerometer variant (ts, accel1, accel2 × `+0x471` scale, gyro);
  not used by Touch Plus (no 0x54 capability). INFERRED.
- Axis frame: raw chip axes. Rectification into the model frame uses the per-unit calibration
  (§6); `tools/touchplus_config.py` already documents `model = M (raw − offset)` from
  Acc/GyroCalibration.

**For BUILD-2 (XRService wants SI units at ≥240 Hz):** accel m/s² = `i16 × f32@8 × 9.80665`, gyro
rad/s = `i16 × f32@12 × π/180`, timestamp = dongle µs (the dongle is the translator-time master)
→ CLOCK_MONOTONIC_RAW via the driver's time sync. 500 Hz covers 240 Hz.

---

## 4. Input map

### 4.1 Notification registers (CONFIRMED: elk packs, host unpacks and labels)
Host labels come from `print_decoded_controller_input` (`libsyncboss 0x69018`), which prints the
input record + 0x10. Record layout (stream type 8, 0x38 B, built at the end of
`controller_process_notification`): `+0x10 button[ax, by, sys, ts]`, `+0x14 touch[ax, by, trig,
ts, tr, trig2]`, `+0x1a prox[ax, by, trig, ts, tr, trig2]`, `+0x20 f32 stick_x`, `+0x24 f32
stick_y`, `+0x28 f32 grip`, `+0x2c f32 fore (index trigger)`, `+0x30 u8 battery %`.

| ntf | size | content | deerfly source (`elk FUN_000173bc`) | host decode |
|---|---|---|---|---|
| 0 | 1 | battery % | elk `FUN_0001cf70` (`FUN_00014c38`) | u8 % ("battery level changed") |
| 1 | 18 | IMU sample | elk IMU thread | §3.3 |
| **2** | 4 | **thumbstick x, y** | buf[0..3] | i16 ÷ 32767 if > 0 else ÷ 32768 |
| **3** | 3 | **index trigger (bits 0..11), grip (bits 12..23)** | lo = buf u16@0x23 & 0xfff, hi = buf u16@0x25 & 0xfff | each ÷ 4095; AArch64 `0x58900..0x58918`: `>>12` → grip, `&0xfff` → fore |
| **4** | 1 | **buttons**: b0 A/X, b1 B/Y, b2 thumbstick click, b3 system/menu | out = {in.1, in.2, in.3, in.0} of buf[4] (disasm `0x17a84..0x17ac6`) | b0 → `ax`, b1 → `by`, b3 → `sys`, b2 → `ts` |
| 6 | 1 | state: b0 low_power, b1 assert, b2 cap_touch_err, b3 imu_err, b4 asleep, b5 attachment | elk | log strings |
| 8 | 10 | cap-touch raw | buf[7..10], [0xb..0xc], [5..6], [0xd..0xe] | stream 0x18 (raw) |
| **9** | 4 | **touch + proximity flags**, 12 bits (map below) | remap of buf[0x21], buf[0x22] | bit → record byte via shift tables `0x85130 {10,5,6,8}`, `0x85140 {1,4,2,3}` |
| 0xb | 12 | IR LED config echo {p, ot, d} | elk `FUN_00014c1c` | §2.1 |
| 0x15 | 2 | **index-trigger pressure** (12-bit) | buf[0x37..0x38] | ÷ 4095 × **8.5 N** max (`pressureMaxNewtons`) |
| 0x16 | 2 | battery alerts: b0 too_hot, b1 too_cold, b2 dead_battery, b3 brownout_secondary, b4 brownout | elk `0x20003a00` | log strings |
| **0x17** | 8 | **index "curl"**: u8 curl1d, u8 idx_slider, 4 × s12 joint angles | buf[0x2d], [0x2e], s12 @0x2f, 0x31, 0x33, 0x35 | u8 ÷ 255; s12 × 360/4096 → degrees (`0_z, 0_y, 1, 2`) |
| 0x20 | 6 | sensor bytes | buf[0x1b], [0x1d], [0x1c], [0x1e], [0x1f..0x20] | cached only (UNKNOWN) |
| 0x21 | 12 | cap-touch raw | buf[0xf..0x1a] (reordered) | cached only |
| 0x28 | 4 | IMU temperature raw | IMU thread | cached |
| 0x2b | 2 | buf[4] bit 4 | buf[4].4 | cached (UNKNOWN meaning; a 5th GPIO input on deerfly, `P915`) |

**Reg 9 touch/prox map** (deerfly b = buf[0x21], c = buf[0x22]; elk remap CONFIRMED,
host labels CONFIRMED):

| ntf9 bit | deerfly | label |
|---|---|---|
| 0 | b.0 | touch A/X |
| 1 | b.2 | touch B/Y |
| 2 | b.4 | touch thumbstick |
| 3 | c.2 | touch `tr` (thumbrest, INFERRED from the label) |
| 4 | b.6 | touch index trigger |
| 5 | b.1 | prox A/X |
| 6 | b.3 | prox B/Y |
| 7 | b.5 | prox thumbstick |
| 8 | b.7 | prox index trigger |
| 9 | c.3 | prox `tr` (thumbrest, INFERRED) |
| 10 | c.0 | touch trigger2 |
| 11 | c.1 | prox trigger2 |

The deerfly side is the tidy pattern you'd expect from the source: b = (touch, prox) pairs for
A/X, B/Y, stick, trigger; c = pairs for trigger2, thumbrest. Deerfly also sets buf[0x21] bits 6/7
from two float compares against 191.25 and 252.45 (`dfy FUN_0000ae94`), INFERRED to be the
index-trigger touch/prox thresholds.
"trigger2" meaning (second index-trigger zone?) is UNKNOWN.

**Contested reg-4 ordering: settled.** The hreg-4 write is `{in.1, in.2, in.3, in.0}` (disasm
`0x17ab2..0x17ac2`); the other ordering `{in.1, in.2, in.0, in.3}` is the separate 10-bit
`FUN_0001f748(value, 10)` call (`0x17aa6..0x17aac`, INFERRED: a wake/edge bitmap). Host labels
then give deerfly buf[4]: **b0 = system/menu, b1 = A/X, b2 = B/Y, b3 = thumbstick click**, b4 →
ntf 0x2b.

Left vs right: the labels are positional (A/X = lower face button, B/Y = upper). "sys" is the
menu button on the left controller and the Meta button on the right (INFERRED from Touch
convention). Handedness: cmd 1 `device_desc` / `"Failed to get Input MCU handedness."` (UNKNOWN
layout).

### 4.2 Deerfly (RA2E1) side (CONFIRMED where cited)
- Header: `dAeH`, kind app, vector table at **0x6900** (base 0x6800), reset `0x10919`, git
  `edbf4671d29b`, FSP 4.2.0.
- Sample builder `dfy FUN_0000ae94` (61-B buffer; decompile is noisy because of per-board
  branches):
  - buf[4] b0..b4 = GPIO reads via PmnPFS PIDR bits (`0x400408b8` P214, `0x40040900` P400,
    `0x40040880` P200, `0x4004091c` P407, `0x40040a7c` P915), some active-low.
  - **Index trigger and grip are Hall-effect sensors**, not ADCs: `dfy FUN_0000ad7c(idx)` reads
    3×i16 from an I²C sensor (address table `0x163dc`), log tag `"HALL"`, names `"Fore"` (idx 0)
    and `"Grip"` (idx 1) at `0x1597c/0x15984`. They become the 12-bit values at buf 0x23/0x25
    (INFERRED: via `"Using %d as trigger min"` calibration).
  - Thumbstick: raw ADC u16 at buf[5..6] and buf[0xb..0xc] → per-unit centre/min/max cal, a
    rotation (float sin/cos) and clamp to ±0x7fff → buf[0..3] as 2×i16 (CONFIRMED clamp/scale;
    which raw is X vs Y: the host's first i16 is X).
  - `pinch.c`: piecewise force calibration ("Force not in increasing order", `"Pinch (%d mN, %d)
    to (%d mN, %d)"`) → index pressure (buf 0x37).
  - Checksum: CRC-32/IEEE (nibble table `0x16448` = 0, 0x1db71064, …; init ~0, final ~) over
    buf[0..0x38] → buf[0x39..0x3c] LE. Matches elk `FUN_00029f4c` and `zlib.crc32`.

---

## 5. Battery (CONFIRMED)
- ntf 0: battery percent (u8), also via the "battery level changed: %u%% -> %u%%" path.
- cmd **0x2f** `battery_info` (9 B): `[0..3] f32 battery %` (INFERRED: `FUN_0002beb0` int→float of the `FUN_0001cf70` byte), `[4..7] u32
  voltage in mV` (elk: `uint(float@0x20003b44)`; host `syncboss_input_get_battery_voltage 0x53428`
  reads it as `u32@4 / 1000.0f` → volts), `[8]` = elk `0x200053f4[6]` if `[5]` is set (INFERRED:
  charging/health state).
- ntf 0x16 alerts (§4.1). Deerfly buf 0x37 is **not** battery (it is pressure). PROTOCOL Q4's
  "reg 0x15 battery mV" is wrong.

---

## 6. Per-unit calibration over the radio

- **cmd 0x2b = the `ir_led_cal` blob** (CONFIRMED controller side, `elk FUN_00025c98` case 0x2b,
  asserts tagged `ir_led_cal.c`): read params `{u32 offset (low 16 bits used), u32 len ≤ 32}`;
  returns `len` bytes from flash `0x3d000 + offset`, at most 0x2000 bytes total; returns zeros if
  the region is erased (`*(u32*)0x3d000 == 0xffffffff`).
- Host (`syncboss_input_get_calibration_data 0x53150`) reads **0x1fe0 bytes in 32-byte chunks**:
  `pulsar_manager_read_sync(dev, 0x2b, params={offset, len}, 8, out, 0x20)`. Only for pulsar types
  in mask `0x7aa00d00000`.
- **Content: INFERRED** to be the per-unit constellation calibration JSON
  (`"Device"/"TrackedObject"` with `ModelPoints`, `ImuPosition`, `AccCalibration`,
  `GyroCalibration`). Evidence: the name `ir_led_cal`, 8 KB size, NUL-padded text-sized read, and
  the HAL's `getTalDeviceCalibration <deviceId>` debug command. That is the format
  `tools/touchplus_config.py` already parses from the OTA's embedded units, so
  `touchplus_config.py --cal <file>` can consume a dump unchanged. The blob is per-unit flash, not
  in the OTA, so the content can't be confirmed statically. **Live check:** read cmd 0x2b from a
  controller (or `lshal debug … getTalDeviceCalibration`) and see if it parses as JSON.
- User calibration (thumbstick/trigger) lives in deerfly flash (`user_calibration_*.c`, magic
  check) and is synced over SPI reg 0x59. The host has `syncboss_input_{get,set,clear}_thumbstick_user_calibration`
  (not traced; the deerfly output is already calibrated).

---

## 7. Haptics (CONFIRMED unless noted)

| cmd | len | host API | elk handling (`FUN_00027ebc` → `FUN_0001f968(type, …)` → haptics thread `FUN_0001ac74`) |
|---|---|---|---|
| **0x97** | 1 | `syncboss_input_set_haptic` (`0x53a6c`), low-priority write | type 0: amp == 0 → stop; else state 2 + deerfly SPI reg **0x4a** = `{amp, 0, 0, 0}` (`FUN_000168a4`). **Auto-stops 2000 ms** after the last request (`FUN_0001f8c0` stamps `+0x17c`; thread checks `> 2000`). |
| **0xa0** | 3 | (no libsyncboss writer found) | type 1: `{u8 amp, u16 freq}`; `FUN_000150fa` accepts freq 40..561 (`freq − 40 < 0x20a`) and writes deerfly reg 0x4a `{amp, …, freq}`. Same 2 s timeout. INFERRED: freq in Hz. |
| **0x9b** | 32 | `syncboss_input_send/append_haptic_syncbuffer` | type 2: `{u8 n & 0x1f, n samples}` into a 100-entry ring of 1-byte amplitudes played by a synctask (`FUN_000187e0`) on the host clock. Sample rate UNKNOWN. |
| **0x9d** | 31 | `syncboss_input_send_pcm_haptics` (`0x53b58`), needs capability bit 1 | type 3: IMA-ADPCM (`adpcm_encode 0x69864`) of **72 samples** per write, with the encoder state (predictor/index bytes from cache `+0x1c0/+0x1c1`) in the header; state resets if > 100 ms since the last chunk. The controller asks for more data with a notification (`pcm_request_data_callback`, host `stream_processor_INPUT_SELF_TRACKED_pcm_haptics_request`). |
| 0x9c | 4 | `syncboss_input_set_multi_haptics` | **no case in Touch Plus elk** (returns 0): unsupported. |

**For BUILD-1/2:** map SteamVR `TriggerHapticVibration(duration, freq, amp)` to cmd **0xa0**
`{round(amp × 255), clamp(freq, 40, 561)}` (or cmd 0x97 when freq = 0), re-send every < 2 s for
long pulses, and send cmd 0x97 = 0 to stop early.

---

## 8. Corrections to PROTOCOL.md (for the planner)

1. **Q4 "IMU = reg 0xb (12B) / 0x16 (2B)" is wrong.** ntf 0xb = IR LED config echo
   (`elk FUN_00014c1c`); ntf 0x16 = battery alert bits (`FUN_00014c38`, which also writes ntf 0 =
   battery %). IMU = **ntf 1** (18 B), plus temperature at ntf 0x28.
2. **Q4 buttons vs touch are swapped.** ntf **9** (buf 0x21/0x22) = touch + proximity; ntf **4**
   (buf[4]) = physical buttons.
3. **Q4 analog identities.** buf[0..3] (ntf 2) is the **thumbstick** (2×i16), not a sample
   counter. buf 0x23/0x25 (ntf 3) = **index trigger / grip**. buf 0x31/0x33 (ntf 0x17) are
   **index-curl joint angles**, not stick axes.
4. **Q4 "reg 0x15 battery mV" is wrong.** It is index-trigger pressure (12-bit, 8.5 N full scale).
   Battery = ntf 0 (%) and cmd 0x2f (mV).
5. **Q4 "subscribe to / poll the hreg registers".** The streaming path is *notification chunks*
   (§1.1) that the controller pushes after the host writes cmd 9 "data ready". cmd ids (pulsar
   read/write) are a different number space.
6. **Q4 IMU part:** the Touch Plus IMU (ICM-42686) range/rate is now pinned (§3); scales are
   carried by cmd 0x32, not a JSON.
7. **Q4 LED prose "ot = on-time (~15–100 µs exposure window)":** on-time max is exactly 75 µs
   (clamped), default 19 µs; d is the pulse **centre**.
8. **Q4 contested reg-4 out2/out3:** resolved (§4.1).
9. **Q5 "LED 3D positions NOT in the controller's readable cal":** probably wrong. cmd 0x2b
   `ir_led_cal` (8 KB flash) is the obvious home (INFERRED, §6).

## 9. Open items
- Content of the cmd 0x2b blob (needs one live read).
- Sync-buffer haptics sample rate; cmd 0xa0 frequency units (Hz assumed).
- ntf 0x20 / 0x21 / 0x2b and "trigger2" meanings.
- Whether a non-Meta host must also send cmd 0xa1 (Meta sends it).
- Handedness / `device_desc` (cmd 1) layout.
- ICM-47688 board config offsets (only matters if such a unit turns up; read cmd 0x32 anyway).

## Reproduce
```sh
# libsyncboss internal names (MiniDebugInfo) -> "addr size name" list for Ghidra labels
python -c "import lzma;from elftools.elf.elffile import ELFFile as E;f=E(open('artifacts/quest/odm/lib64/libsyncboss.so','rb'));open('sb_debug.elf','wb').write(lzma.decompress(f.get_section_by_name('.gnu_debugdata').data()))"
# elk: tools/ghidra/run.sh elk-app-ruby_prq 0x14100 ; disasm checks with tools/ghidra/disasm.py
# deerfly: BinaryLoader base 0x6800, ARM:LE:32:Cortex, functions from the vector table at 0x6900
# the switch in controller_process_notification needs a manual jump-table override:
#   type tables at libsyncboss 0x85150 (types < 0x1f, base 0x57708) and 0x8518e (types < 0x2e, base 0x58334), entry*4
```
