# DEV-1: on-device bench (no dongle), 2026-10-04

Session DEV-1 from [MASTER-PLAN.md](../MASTER-PLAN.md) §5, Phase D. Tags: **CONFIRMED** = seen on the
device in this session, **INFERRED** = deduced, not observed directly. Log excerpts are trimmed;
the full logs stay on the Frame in `~/touchframe-cv/dev1_*.txt` (not committed).

## Summary

| Question | Answer |
|---|---|
| Version drift since the RE baseline | **None** on the Frame (byte-identical). The Quest is on the RE OTA build. The controllers run fw 207.5.0, which matches the OTA images' header version. |
| **G-Touch-only:** can our driver Create the shared queues, and will XRService use them? | **Yes, CONFIRMED.** No Frame controller since SteamVR start → we Create `/event` + `/data` → XRService connects, accepts our device, streaming mode 4, "Trying to track first LED frame". |
| Does a Frame controller still work after we Created them? | **The first driver_cv controller instance of the session doesn't** (its Create fails, it has no Connect fallback, so no pose; buttons and haptics still work). A power cycle doesn't fix it. **The second instance (the other hand) Connects and tracks fine.** |
| Do driver_cv's queues survive its last controller disconnecting? | **Yes, CONFIRMED** (65 s after the disconnect, XRService still reads our IMU and writes our poses). |
| Gate B via the relay | **0 hits** (`[ContrLedsStats 1]` = 0) in a ~4.5 min run, with the relay IMU feed up only ~31% of the time. As §3.2 predicts, a negative proves nothing. The new LED-cadence data (below) shows why. |
| New risk found | XRService logs **~300 "Couldn't find any neighbor" errors per second** with the Touch Plus LED model (8 LEDs). Zero with Frame-controller models. It is not caused by `model_number`. Possible PnP blocker for Gate B. |
| Dongle on the Frame | **`CONFIG_USB_ACM` is not set: there is no `/dev/ttyACM*`, ever.** hidraw is built in, and `/dev/hidraw*` is `0664 root:input` with `steamos` in `input`. **A USB-HID dongle works with no udev rule and no root.** One USB-C port. |
| Quest pairing secrets | Both files are ENOENT for the shell user. There are no syncbosshal props. |

## 1. Version drift (read-only)

**Frame: no drift (CONFIRMED).** sha256 of the device files = the `artifacts/frame` copies:

| File | sha256 (first 16 hex) |
|---|---|
| `drivers/cv/bin/linuxarm64/XRService` | `9e1c6f57a7e3613c` |
| `drivers/cv/bin/linuxarm64/driver_cv.so` | `001ea72f73c613bf` |
| `bin/linuxarm64/vrserver` | `5814a1dd2274401c` |
| `drivers/cv/bin/linuxarm64/libArcturusPerception.so` | `44ca80763343d658` |

- `XRService version: 2026-09-23 23:30:05 64f342ccba` (log header). `VR server 2.18.2 (v1790822802)`; the
  build id 1790822802 = 2026-10-01 03:46 IST. File mtimes are 2026-10-01 03:53. The FRAME-TRACKER §8
  facts therefore stand as written; nothing needed re-verifying.
- Kernel `6.18.0-ge66bc2ca6f8c`, SteamOS "holo".

**Quest: on the RE build (CONFIRMED).** `ro.build.version.incremental = 52433670048800520`, fingerprint
`oculus/eureka/eureka:14/UP1A.231005.007.A1/52433670048800520`, built Thu Sep 24 2026,
`ro.vros.build.version = 207`.

**Touch Plus firmware (CONFIRMED):** `dumpsys OVRRemoteService`:
```
Paired device: 4e0704337945489d, Type:  Right, Model: RUBY, HardwareRev: 0x10, Firmware: 207.5.0, ImuModel: ICM42686, ...
Paired device: 36300ad79a66d60f, Type:   Left, Model: RUBY, HardwareRev: 0x10, Firmware: 207.5.0, ImuModel: ICM42686, ...
Firmware update record: -- (last modified: --)
```
The controller log also prints `{MAIN}: v207.5.0`. The OTA images' `dAeH` header field at 0x1c is
`cf 05 00 00` = **207.5.0** (major 0xcf, minor 0x05, patch 0) in both `fw/ruby/*-app.bin` and
`fw/ruby_prq/*-app.bin`. So the controllers run the OTA's version (CONFIRMED). *Which* of the two
images (ruby git `40a8700a2733` vs ruby_prq `edbf4671d29b`, the one RE used) is on these HardwareRev
0x10 units isn't visible from the shell (UNKNOWN). The on-device archives `/odm/firmware/ruby_archive.bin`
and `ruby_prq_archive.bin` can't be stat'ed as shell.

**Quest auto-updates:** the user turned them off (2026-10-04).

### Bonus: the Quest's Touch Plus LED cadence (CONFIRMED, from logcat)
```
SyncBossHAL: pulsar_manager.c(179): Setting controller ID 4e0704337945489d LED config to period: 66664us, on-time: 19us, delay: 26453us
SyncBossInput: [ruby (right) ...] {IRLD}: IR LED configured: p=66664, ot=19, d=26453
SyncBossFW: {NCM }: Sending constellation cadence: [P: 66664us, D: 26466us]
```
In the relay setup the Touch Plus LEDs flash **once every 66.664 ms (15 Hz) for 19 µs**. That is far
sparser than the "~15–100 µs" in MASTER-PLAN §3.2. The chance that a flash lands inside a short Frame
controller-frame exposure is tiny, so the relay Gate B was expected to be negative. For RE-2 (G-LED):
`p`/`ot`/`d` are the host-set fields of the IR LED config, and 19 µs / 15 Hz is what Meta itself uses.

## 2. G-Touch-only (frame.lock)

**Experiment code** (committed, off by default), in `driver/src/cv_tracker.*` and `cv_clone.cpp`:
- `driver_touchframe.cv_create_shared_queues = true`: when `Connect` returns QueueNotFound (2),
  CvTracker `Create`s `/xrservice/controller/event` (0x6010, 0x200, 4, 0) and `/data`
  (0x30, 0x200, 4, 0), i.e. driver_cv's parameters. It destroys them in `Stop()`.
- `cv_clone_imu = "static"`: pushes a resting IMU (+g on +Y, zero gyro) at 240 Hz with no SteamVR
  device needed. `cv_clone_serial` must still be non-empty (any value).
- Config: `tools/touchplus_config.py` output (`touchplus_left.json`, 8 LEDs, role left_hand), device id 41.

### Run A: experiment ON, both Frame controllers off since SteamVR start (CONFIRMED)
vrserver:
```
10:41:06.899 cvclone: created /xrservice/controller_41/pose (handle 0xa00000001)
10:41:06.900 cvclone: experiment: Create /xrservice/controller/event -> err 0
10:41:06.901 cvclone: experiment: Create /xrservice/controller/data -> err 0
10:41:08.402 cvclone: sent connect for device 41 (hardware id 0x5446000000000029, 1433-byte config)
10:41:09.093 cvclone: first pose block: device 41, t -1.0000 (now 13894.9661), valid 0
then: imu sent +480 / clone poses 480 every 2 s
```
XRService:
```
10:41:07.141 setControllerTrackingStreamingMode() streamingMode: 4
10:41:08.085 [DeckardCaptureSource] Connected to controller data block queue at /xrservice/controller/data
10:41:08.086 [DeckardCaptureSource] Connected to controller event block queue at /xrservice/controller/event
10:41:09.089 Received controller Connection event for device 41
10:41:09.090 Received controller config event after a connection event, as expected. Now we will start tracking controller 41
10:41:09.090 [ControllerTracking] Connecting to the controller pose block queue at path /xrservice/controller_41/pose
10:41:09.091 [ControllerTracking]: initializing controller 0, serial number: tfclone_tftouchplus_left
10:41:09.093 [ControllerTracking 0]: Received first IMU sample: ... accel: 0.000000, 9.806650, 0.000000. gyr: 0, 0, 0
10:41:09.107 [XRService] Setting camera streaming mode for controller tracking to 4
10:41:11.366 [ControllerTracking 0]: Trying to track first LED frame with timestamp: 13897.229567
```
- **G-Touch-only passes (CONFIRMED):** neither driver_cv nor a Frame controller is needed for the
  queues. XRService connects to whichever queues exist, at startup (run A) or as soon as they appear
  (run B: it connected 18 ms after driver_cv created them, 50 s after XRService started).
- XRService pauses controller processing while the headset isn't worn (`[UserPresence] Not Detected`
  → `[ControllerTracking] Disable processing`); it resumes on wear.
- vrserver logs `cv: Requested controller brightness change does not match any QpdPoseTracker with SN =
  tfclone_tftouchplus_left` ~4×/s. **XRService requests LED brightness changes for our device**, and they go
  to driver_cv, which ignores them (CONFIRMED). A real Touch Plus backend will have to drive brightness
  itself; RE-3 could find the request's format.

**A3 – right Frame controller powered on after our Create (CONFIRMED, broken for that instance):**
```
cv: CCvControllerDriver hwid 1008010000030002 fw 1789082792
cv: Error: Failed to connect to controller data block queue /xrservice/controller/data: 1
cv: Error: Failed to connect to controller event block queue /xrservice/controller/event: 1
cv: Connected to controller pose block queue: /xrservice/controller_1/pose
cv: [CCVTrackedControllerDriver] WriteConnectionOrDisconnectionInBQ was not sent because no handle was found
```
Error 1 = QueueAlreadyExists, so the INFERRED code in FRAME-TRACKER §8.2 is now CONFIRMED. The user saw
no right controller pose, but buttons and haptics worked. **Power-cycling it doesn't help:** the reconnect
reuses the same driver instance (`Peripheral disconnected` → `Sent controller connected …` → `…no handle
was found`), with no new Create or Connect.

**A3b – then the LEFT Frame controller (a new driver_cv instance) (CONFIRMED, works):**
```
cv: Creating new driver for controller 8d59320477d2
cv: Connected to controller data block queue: /xrservice/controller/data
cv: Connected to controller event block queue: /xrservice/controller/event
XRService: Received controller Connection event for device 2 ... initializing controller 1, serial number: 8d59320477d2
```
It tracked (user confirmed; 67 `[ContrLedsStats 1]` lines). This matches driver_cv's `first ^ 1`:
**only the first controller driver instance created in the vrserver process Creates; later instances
Connect.** Our Create therefore costs exactly one Frame controller (the first one seen in the session)
until SteamVR restarts (INFERRED for other orderings; observed for right-first then left).

### Run B: experiment OFF; do driver_cv's queues outlive its last controller? (CONFIRMED: yes)
```
10:50:02 cvclone: waiting for a Steam Frame controller to create the shared queues (connect event err 2, data err 2)
10:50:52.349 cv: Connected to controller data block queue: /xrservice/controller/data    (driver_cv's Create)
10:50:52.528 cvclone: connected /xrservice/controller/event and /xrservice/controller/data
10:50:52.528 cvclone: sent connect for device 41
10:51:06.575 cv: Peripheral disconnected: 483c39e041f4      (the user switched the only Frame controller off)
XRService 10:51:07.370 Received controller Disconnection event for device 1 / Disconnecting controller 0
10:52:10.518 cvclone: imu sent 18718 ... | clone poses 480 (valid 0) in 2 s     (65 s later: still flowing)
```
No `event queue went away` / `data queue went away` lines. QueueHasReader stays true and pose blocks
keep coming. **driver_cv doesn't destroy the shared queues when its last controller disconnects**; they
live until vrserver exits (FRAME-TRACKER §9.1).

**What this means for the Touch-only design (INFERRED):**
- "Power a Frame controller on once per boot" is a valid workaround: after that, the queues stay
  for the whole SteamVR session, and the controller can go back off.
- "Create if missing" works with no user action, but costs the first Frame controller enrolled in that
  session (no pose until a SteamVR restart). A middle ground for BUILD-2: Create only after a grace
  period with no Frame controller, and log that the first Frame controller turned on later will need
  a SteamVR restart. Don't Destroy and re-Create: driver_cv's failed instance never retries.
- At SteamVR stop, vrserver exited before our `Stop()` logged anything. The shared memory goes with
  the process, so a missing Destroy is harmless.

## 3. Relay Gate B (frame.lock + quest.lock)

Setup: `tools/quest.sh start`, `tools/frame.sh gateb on left` (device 41, synth IMU from the relay
pose, `touchplus_left.json`). Left Frame controller OFF, right Frame controller ON (it creates the
queues). The user wore the Frame and moved the left Touch Plus, holding the controls so the Quest
kept it. Run window: 10:54:25 → ~10:59 (**~4.5 min, short of the 10 min asked**). The user stopped
there, and the relay feed was the limiting factor, not the user's handling.

Tracker mapping: `initializing controller 0, serial number: 483c39e041f4` (right Frame controller) and
`initializing controller 1, serial number: tfclone_tftouchplus_left` (relay Touch Plus). **Gate B hits are
`[ContrLedsStats 1]` lines.** The stats are labelled by tracker index, not deviceId 41.

| Metric | Value |
|---|---|
| `[ContrLedsStats 1]` (Touch Plus LED matches) | **0** |
| `[ContrLedsStats 0]` (Frame controller, reference) | 64 |
| `[ContrBlobStats]` | 2 (7 blobs cam 0 at 10:53:59, 8 blobs cam 1 at 10:55:54) |
| Valid clone poses (CSV `clone` rows with valid=1) | **0** of 33 616 |
| Synth IMU samples sent | 33 616 ≈ 140 s at 240 Hz |
| cvclone 2 s reports with the relay Touch Plus tracked | 66 of 214 (31%) |
| `Resetting controller tracker 1, because there was a long time without IMU data` | 7 |
| `Not having enough IMU data for controller frame` | 13 |
| "Couldn't find any neighbor" errors | 35 866 |

- The relay kept dropping the left Touch Plus: the Quest flipped it to hand tracking
  (`TouchBridge: left hand profile: none` ↔ `/interaction_profiles/oculus/touch_controller`, ~every
  5–50 s). With no relay pose there is no synth IMU, so XRService resets tracker 1. Each reset restarts
  PnP bootstrapping, which makes the already tiny chance of catching a 19 µs flash (§1 bonus) smaller still.
- Pose error vs the relay: **not measurable**, because there were no valid clone poses.
- **Verdict: no early yes.** Per §3.2 this proves nothing. Combined with the 15 Hz × 19 µs cadence, a
  longer relay run isn't worth repeating. The real Gate B stays with HW-3 (dongle-held LEDs).
- Afterwards: `gateb` settings removed, cvclone CSV kept on the Frame (`~/touchframe-cv/gateb_left.csv`).

### New risk: "Couldn't find any neighbor" flood with the Touch Plus model
```
ERROR: Couldn't find any neighbor for pair {N, N}     (565 in run A's first ~3 s of processing)
ERROR: Couldn't find any neighbor for index N          (284)
```
- CONFIRMED: 0 in every 2026-10-03 log (Frame controller and Frame-clone configs, 18 LEDs). 849 in
  run A (only our device present), 35 866 in the Gate B run. It appears whenever processing is active
  with the Touch Plus config loaded, even with no Touch Plus LEDs lit.
- CONFIRMED **not caused by `model_number`**: a third run with `model_number: TouchFrame_TouchPlus_Left`
  (instead of `Steam_Frame_Controller_Left`) gave 881 errors in its ~3 s of processing.
- INFERRED cause: the 8-LED Meta nominal model is sparse (nearest-LED distance median 19.7 mm, max
  62.3 mm, vs 12.5 / 34.1 mm on the 18-LED Frame model), so XRService's LED neighbourhood graph leaves
  LEDs with no neighbours. If the blob matcher needs neighbours, PnP may never bootstrap on this
  model **even with LEDs held on**. For RE-3/RE-2: the strings are at XRService `0x914d1e` (pair) and
  `0xa0f246` (index); find the radius/angle rule; check whether the real Touch Plus has more than 8 LEDs
  and the OTA nominal is a subset.

## 4. Quest read-only probes

Shell user `uid=2000(shell) context=u:r:shell:s0`, SELinux Enforcing.

| Probe | Result |
|---|---|
| `cat /persist/pulsar/pulsar_host_address.bin` | `No such file or directory` (CONFIRMED). `ls /persist` → `Permission denied`, so ENOENT here may just mean the path isn't reachable from the shell's view (INFERRED). |
| `cat /data/misc/pulsar_aes_key.bin` | `No such file or directory` (CONFIRMED). `/data/misc` is `drwxrwx--t system misc`, so the lookup itself is allowed and the file **really isn't there** (INFERRED: SELinux would give EACCES). If syncboss reads that path, it should log `Failed to get pulsar aes key, error=%i` (libsyncboss string) and fall back to the default key. That makes MASTER-PLAN §3.1.10 (default key) more interesting. logcat no longer holds boot-time lines to check (uptime 15 h). |
| `getprop` `vendor.syncbosshal.*` / `persist.vendor.syncbosshal.*` | **None set** (CONFIRMED). Names known from libsyncboss: `persist.vendor.syncbosshal.{disable_pulsar_manager, disable_fw_version_check, log_telemetry, custom_camera_init}`. |
| Other paths from libsyncboss | `/mnt/vendor/syncboss/data/` and `/mnt/vendor/persist` → Permission denied. |

No key was readable, so nothing was stored. The netaddr isn't available from adb shell; hardware day
needs the address-search route (HARDWARE-DAY §4).

## 5. Dongle readiness on the Frame (read-only)

| Check | Result |
|---|---|
| `cdc_acm` | **Not available** (CONFIRMED): `modinfo: Module cdc_acm not found`, `/proc/config.gz`: `# CONFIG_USB_ACM is not set`, and there are no usb-serial modules. **`/dev/ttyACM*` can never appear**, so link v3 over CDC-ACM won't work on the Frame. |
| HID | `CONFIG_USB_HID=y`, `CONFIG_HIDRAW=y`, `CONFIG_USB_HIDDEV=y` (CONFIRMED). `/usr/lib/udev/rules.d/99-hidraw-permissions.rules`: `KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0664", GROUP="input"`, and `steamos` is in `input` (CONFIRMED). **A vendor-defined HID dongle is read/write for steamos out of the box.** |
| Other built-ins | `CONFIG_USB_XHCI_HCD=y`, `USB_STORAGE=y`, `USB_NET_CDCETHER/CDC_NCM=y`, `USB_DWC3_DUAL_ROLE=y`, Type-C/UCSI/TCPM. Raw libusb via usbfs would also work, but `/dev/bus/usb` nodes would need a uaccess/udev rule. |
| Default ttyACM group | `50-udev-default.rules`: `tty[A-Z]*[0-9]` → `GROUP="uucp"`; steamos isn't in uucp (CONFIRMED; moot without cdc_acm). steamos groups: `steamos tty leds steamos-log-submitter video render input audio wheel cdsp spidev perf gpiod fpga`. |
| `/etc` writable for a udev rule? | `/etc` is an **overlay** (`upperdir=/var/lib/overlays/etc/upper`), rw for root. `steamos` gets `Permission denied`, and `sudo` needs a password (CONFIRMED). `/` is btrfs mounted `rw` (CONFIRMED). A rule is possible with the user's sudo password, but **the HID route needs no rule at all**. |
| USB-C ports | **One** (user, and sysfs shows only `typec/port0`). It currently holds a charger (`data_role host [device]`, `power_role source [sink]`). **A USB-C hub with PD pass-through is needed** to charge while the dongle is in. Note `/dev/bus/usb` is absent while the port is in device role; the dongle needs the port in host role, which the hub or OTG adapter triggers (INFERRED). |

**Recommendation for BUILD-1/BUILD-2 (INFERRED, the planner's call):** give the dongle a USB-HID
transport (64-byte vendor reports at 1 ms = 64 KB/s each way is plenty for 2 × 240 Hz IMU + input)
instead of, or in addition to, CDC-ACM, and have RadioSource open `/dev/hidraw*` by VID:PID
(`1209:0001`). CDC can stay for the PC tools.

## 6. State left behind

- Lock files: none (`C:\Users\kaibo\Desktop\Echo\.locks\` is empty).
- Frame: `driver_touchframe` settings back to exactly the pre-session section (only `calib_*`;
  checked against `~/touchframe-cv/steamvr.vrsettings.dev1-backup`); SteamVR restarted clean. The
  installed driver is this branch's build (main + the experiment, off by default, so the relay
  behaves the same).
- Quest: found with the bridge **not running** and an old watchdog running (pid 26774). Left with
  the bridge **and watchdog stopped**: after a bridge-only force-stop, the watchdog relaunched the
  bridge right away because the home was in front, so stopping both was the only way to leave the bridge
  stopped. `tools/quest.sh start` brings both back. The Quest's own auto-updates are off.
- On-Frame evidence: `~/touchframe-cv/dev1_runA_{vrserver,xrservice}.txt`,
  `dev1_gateb_{vrserver,xrservice}.txt`, `dev1_modelnum_xrservice.txt`, `gateb_left.csv`,
  `touchonly*.csv`.

## 7. Suggested next steps (for the planner)

1. **BUILD-1/BUILD-2:** switch the dongle-to-Frame transport to HID (§5). This is a blocker for hardware day as planned.
2. **RE-3:** the neighbor-graph rule behind `0x914d1e`/`0xa0f246`, and the brightness-request path
   (`Requested controller brightness change`), before HW-3.
3. **RE-2:** is the Touch Plus LED model really 8 LEDs? Meta's cadence 66 664 / 19 / 26 453 µs is a
   known-good IR LED config to start G-LED from.
4. **BUILD-2 Touch-only:** "Create after a grace period" plus the documented one-controller cost (§2), or
   the "power one Frame controller on once per session" workaround; both are now proven.
