# Feasibility: Quest 3 Touch Plus as native Steam Frame controllers

Goal: Touch Plus controllers working on a standalone Steam Frame like first-party controllers:
- full 6DoF tracking by the Frame's own cameras;
- every button, stick, trigger and capacitive touch;
- haptics;
- no Quest headset and no PC in the loop.

Status (2026-10-04): **Phase 1 (relay) done. Phase 0 static RE done for a listening host. Phase 2
dongle tooling ready, dongle not arrived. Phase 3 injection proven, Gate B open.** The plan of
record, with what's left and how it's split into sessions, is
**[MASTER-PLAN.md](MASTER-PLAN.md)**. The "Log" at the end is the history.

## Verdict so far

| Piece | Status | Why |
|---|---|---|
| SteamVR side (bindings, models, haptics) | **Easy, built** | Third-party aarch64 OpenVR drivers load on the Frame. SteamVR there already ships the Touch input schema and `oculus_quest_plus_controller_*` render models. Games fall back to Touch bindings. |
| Radio: buttons, IMU, haptics without a Quest | **Likely** | Touch Plus and Quest radio firmware are plaintext ARM images inside the Quest OTA, so the protocol can be read statically. A Nordic nRF52840 USB dongle on the Frame plays the "Quest". Gate A passed (no host auth). PHY, hop, pairing and cipher structure are pinned. The post-pairing command layer (register access, LED, IMU, haptics) is still to RE (MASTER-PLAN §3.1). |
| 6DoF from the Frame's cameras | **Driver route proven; LED blobs (Gate B) open** | No camera hook needed: driver_touchframe injects a controller into Valve's XRService tracker through vrserver block queues. A cloned Frame controller tracked at 2.3 mm / 0.64° median (docs/FRAME-TRACKER.md §9). Still open: whether Touch Plus LEDs, kept always on by our radio, produce blobs XRService matches, and whether the controller *allows* always-on (its IR LED config is validated; if it isn't allowed, we strobe in sync with the Frame's exposures). Constraints: one tracked controller per hand; the shared queues have so far only existed after a Frame controller connected. |

## Hardware facts

**Touch Plus (Quest 3)**
- Chips: nRF52820 radio MCU ("elk" firmware), a Renesas RA2E1 input co-processor ("deerfly" firmware, built with Renesas FSP 4.2.0), and a TDK ICM-42686 IMU.
- Link: proprietary Nordic 2 Mbit mode, not BLE. No whitening, CRC-24 poly 0x108421 init 0xFFFFFF. Discovery access address 0xAA + 0xFACEB00C on 2402 MHz, pairing on 2426 MHz. X25519 key exchange during pairing.
  - Source: https://diary-of-a-wimpy-researcher.org/posts/decoding-the-oculus-controller-protocol/
  - Live input protocol: not public; that's our Phase 0 work.
- LEDs strobe on radio beacons, timed to the headset's camera exposure (~15–100 µs). Patents US10532277, US10819926.
- Board and chips: https://www.ifixit.com/Guide/Meta+Quest+3+Chip+ID/165932, https://diary-of-a-wimpy-researcher.org/posts/oculus3-inside-the-controller/

**Quest 3 headset (build 52433670048800520, odm partition)**
- `/odm/firmware/`:
  - `syncboss.bin` / `syncboss-app.bin`: the headset's controller radio MCU (nRF52833), plain Cortex-M image.
  - `ruby_prq_archive.bin` (Touch Plus, "RUBYPRQ"): a tar of `elk-app.bin`, `elk-spl-updater.bin`, `deerfly-app.bin`, `deerfly-spl-updater.bin`.
  - `ruby_archive.bin`: an earlier controller variant.
  - The headset pushes these to the controllers as firmware updates.
- Image header: magic `dAeH`, header size 0x2e, then plaintext Thumb code. Strings are present, e.g. `wireless_device.c`, "Device is unpaired", "Invalid host Pulsar version detected".
- `/odm/lib64/libsyncboss.so`, `libsyncbossmanager.so`, `libclocksync.so`: the host side.
- `/odm/etc/input_tracking/runtime/eureka/ruby/`: Meta's Touch Plus tracking models.
  - `direct_pose_regression` (ExecuTorch/TorchScript)
  - `extended_volume_pose_regression`
  - `imu_only_tracker` per hand
  - Meta tracks Touch Plus with a learned pose regressor, not only classic LED PnP.
- Getting them: SELinux blocks reading `/odm/firmware` over adb. We extract them from the matching full OTA instead:
  - archive: https://cocaine.trade/Quest_3_firmware, SHA-256 verified
  - extractor: `tools/payload_extract.py`
  - **Never commit or redistribute these files.** `artifacts/` is gitignored.

**Steam Frame** (probed over SSH)
- **Platform:** SteamOS aarch64, kernel 6.18, SM8650. SteamVR in `/opt/steamvr`, binaries in `bin/linuxarm64`. gcc, clang, cmake and ninja are on the device, so we build natively.
- **Cameras** (i2c / v4l-subdev names):
  - 2x `arcimx616`: colour/passthrough
  - 2x `og01a1b` and 2x `og0ve10`: OmniVision global-shutter mono
- **XRService** (`/opt/steamvr/drivers/cv/bin/linuxarm64/XRService`, Arcturus) holds `/dev/media0`, `/dev/video0,3,9,13` and the sensor subdevs exclusively.
  - `/dev/video99` is only a v4l2loopback RGB 1920x1080 passthrough feed from `steamvr-v4l2cam.service`.
- **Controller tracking** (`driver_cv.so`, "vortex", lighthouse-derived):
  - LED models come from each controller's JSON `lighthouse_config.modelPoints/modelNormals`.
  - `ITrackedControllerLedControl` and "First LED frame scheduled" mean LED frames are interleaved and timed over the radio.
  - A DSP NN `getControllerLEDAndPalmJointsPosAndNormals`.
  - Per-controller models in `resources/dipr_models` (dipr_v2/v3_controller, ev1, index).
  - Closed source; Valve said it won't open its tracking (FOSDEM 2026).
- **Frame controller radio:** the internal "Roy dongle" on `/dev/spidev0.1`, held by vrserver. It runs a BLE stack with Valve firmware and is separate from the WCN7850 Bluetooth (hci0). **Don't touch it.** Reflashing would break the Frame controllers.
- **USB-C** data role is `host [device]`, so a radio dongle can plug in.
- **Third-party drivers:** `vrpathreg adddriver` works (precedents: SlimeVR, frame-unboundedMouse). A PSVR2 Sense controller driver tracked by the Frame cameras was reported around 2026-10-02 (https://www.pcguide.com/news/modder-makes-steam-frame-compatible-with-psvr-2-controllers-with-quest-3-controller-support-planned-soon/). Code not public yet; watch it for how it reaches the cameras.

## Prior art to reuse
- **Monado Rift S driver + Jan Schmidt's constellation tracker** (BSL-1.0): blob detection, LED model matching, PnP, IMU fusion; controller calibration JSON read over the radio. https://gitlab.freedesktop.org/thaytan/monado/-/commits/dev-constellation-controller-tracking
- **PSVR2Toolkit `libpad_hooks.cpp`** (MIT, non-commercial): driver-side LED phase scheduling against camera exposure. https://github.com/BnuuySolutions/PSVR2Toolkit
- **sc26re** (Steam Controller 2026 firmware reimplementation on nRF52833, ESB/BLE). Shows Valve's radio stack conventions. https://github.com/mwdmwd/sc26re
- **Touch3-on-Quest-2:** Touch Plus pairs through the headset radio MCU and `libsyncboss`. https://github.com/mlsplays/Touch3-on-Quest-2

## Plan (phases and gates)
0. **Firmware and protocol.**
   - Disassemble elk-app (controller radio), syncboss (headset radio) and libsyncboss.
   - Document pairing, live input packets, haptics, LED beacon timing, the post-pairing cipher, and any host authentication → docs/PROTOCOL.md.
   - **Gate A:** can a non-Meta host pair? If not, fall back to reflashing the controller's nRF52820.
1. **Relay milestone.**
   - The Quest 3 headset sits on a shelf as radio and tracker. A bridge APK sends `tf::StatePacket` over UDP to `driver_touchframe` on the Frame.
   - Proves the whole SteamVR side.
2. **Native radio.** nRF52840 dongle firmware: sniffer mode first, then host mode. The driver gets a `radio` backend.
3. **Frame cameras.** *Revised 2026-10-03:* no LD_PRELOAD shim. The driver injects the controller into XRService through block queues (FRAME-TRACKER §6, §9), and XRService does blob detection, PnP and IMU fusion itself.
   - Drive the Touch Plus LEDs always-on (or strobe in sync with the Frame's exposure schedule if always-on is rejected).
   - **Gate B:** if no blobs appear, 6DoF is a NO-GO; ship 3DoF plus Frame hand tracking for position.
4. ~~**Tracker.** Port the Monado constellation tracker.~~ Superseded by phase 3: XRService is the tracker. What's left is our IMU feed (rectified, 240 Hz, CLOCK_MONOTONIC_RAW) and the Touch Plus LED model.
5. **Polish.** Pairing UI, battery, skeleton input, auto-start, install docs. Relay versions of skeleton input, auto-start and install docs are done (log, 2026-10-03; [INSTALL.md](INSTALL.md)).

Sessions, gates and fallbacks for phases 2–5: [MASTER-PLAN.md](MASTER-PLAN.md).

## Log
- **2026-10-03:**
  - Research and Frame probe done.
  - Quest OTA extracted; firmware confirmed plaintext.
  - Relay driver (`driver/`) builds natively on the Frame: `driver_touchframe.so`, aarch64, exports `HmdDriverFactory`.
  - **Driver verified on the Frame with `tools/sim_sender.py`:**
    - `vrpathreg adddriver` plus a SteamVR restart loads it ("Loaded server driver touchframe"). It stays inert until UDP packets arrive.
    - On the first packet, TouchFrame_Left/Right are added and activated as devices 1 and 2.
    - `vrcmd --pollposes` shows poses streaming, including the openxr_grip→raw offset (20.6° pitch).
    - `vrcmd --pollcontrollers` shows sticks, trigger, grip, buttons, touches and battery 80%. SteamVR applied Valve's `{oculus}` legacy Touch bindings by itself.
    - `vrcmd --spamhaptics`: 383 haptic packets came back to the sender.
  - **Relay works end to end with real Quest 3 controllers:**
    - `quest-bridge` (`tools/build_bridge.py`) runs on the Quest and reaches a FOCUSED OpenXR session in STAGE space, unworn after the `prox_close` broadcast.
    - Its stream reaches the Frame driver.
    - `vrcmd` on the Frame showed live Touch poses and touches (X, trigger).
  - **Next:** calibration to align the Quest stage space with the Frame world; battery passthrough.
  - (Build note: the Quest-side bridge APK needs Android build-tools (aapt2/zipalign/apksigner); the NDK 27 and OpenXR loader in `C:\Android` are present.)
  - Calibration tool `tf_calibrate` built (yaw + translation from rotation deltas plus least squares; the driver reloads `calib_*` live). First real run (right Touch + Frame controller held together, 25 s): 746 samples, yaw 86.2°, translation (1.217, -1.290, 0.349) m, grip offset 65 mm, **RMS 7.6 mm**. The driver reloaded it live. The Frame only tracks its own controllers while worn; in standby it turns their LEDs off.
- **Relay polish** (everyday use; guide in [INSTALL.md](INSTALL.md)):
  - **One-command install:**
    - `tools/install.sh [frame|quest]` and `tools/install.sh uninstall`.
    - `tools/quest.sh install|start|stop|status|log`.
    - `FRAME_HOST=local` runs `frame.sh` on the Frame itself.
  - **Unworn Quest stays awake.**
    - Cause, from `dumpsys vrpowermanager`: `prox_close` is sticky (virtual proximity CLOSE), but an `automation_disable` broadcast or a standby/wake cycle clears it. The real sensor then reads "unworn" and the headset sleeps at once.
    - Fix: a shell-user watchdog (`tools/quest-watchdog.sh`, started detached by `quest.sh start`) checks every 10 s. It wakes the headset, re-asserts `prox_close` only when it's not CLOSE, and relaunches a dead bridge only while the Horizon home is in front.
    - Tested: after `automation_disable` the headset went to STANDBY and was awake again with CLOSE about 10 s later. The bridge kept running and re-linked by itself. A force-stopped bridge came back within 10 s.
  - **Bridge:**
    - The manifest declares optional hand tracking, so Horizon's "controllers required" launch check no longer blocks the bridge while the shelf controllers sleep.
    - Status line in logcat every 5 s.
    - Send errors are retried and a lost OpenXR session is rebuilt.
    - The driver now sends a 1 Hz heartbeat (`HeartbeatPacket`, echoes seq + source time). The bridge shows "driver linked" and the RTT (about 14 ms over Wi-Fi).
  - **Hand skeleton:**
    - `/input/skeleton/left|right`, `VRSkeletalTracking_Estimated`, both motion ranges.
    - Finger curl comes from trigger and its touch sensor (index), grip (middle/ring/pinky) and the thumb touch sensors.
    - Poses come from SteamVR's `resources/anims/hand_right_closeanim.glb`, read at runtime (no Valve data in the repo), converted to OpenVR bone space and mirrored for the left hand.
    - `tf_skeldump ref` checks the result against SteamVR's own reference poses: open hand exact, fist within 3.3° (one bone). `tf_skeldump watch` showed live curl following sim input on the TouchFrame devices.
    - The tool must be an overlay app: background apps get no action input.
    - Fixed an activation race: input was updated before the component handles existed.
- **2026-10-03 (evening): camera-tracker injection works on device** (docs/FRAME-TRACKER.md §9).
  - New in `driver/src`:
    - `cv_tracker`: block-queue injection into XRService.
    - `cv_clone`: validation harness, off unless `cv_clone_serial` is set.
    - `cv_source`: step-2 `CvTouchSource` for a future radio feed; not wired into the Provider yet.
  - **Clone test, run 3:**
    - Setup: right Frame controller cloned as deviceId 40, role left_hand, left Frame controller off. The IMU was synthesized at 240 Hz from the real controller's SteamVR pose.
    - XRService created its own tracker for the clone and matched up to 9 LEDs to it (reprojection 0.07–0.8 px).
    - Valid poses came back on our queue with **2.9 ms latency**.
    - Over 1 017 valid poses: **2.3 mm median (p90 26 mm), 0.64° median** vs XRService's own pose for the real controller.
    - Same numbers against the real controller's SteamVR pose (2.1 mm median).
  - **Measured facts:**
    - The XRService clock is **CLOCK_MONOTONIC_RAW**; it was 214 ms off CLOCK_MONOTONIC after 2 h of uptime.
    - IMU block = specific force (m/s²) + gyro (rad/s) in the config's imu frame. The synthesized IMU matched the real one with 0 ms lag; gyro error 0.33 rad/s mean.
    - The pose block has model axes at the IMU origin. With `HeadFromPoseBlock`, it matches driver_cv's SteamVR pose to 0.85 mm / 0.32°.
    - Pose angular velocity is body-frame.
  - **Constraints found:**
    - XRService has one tracking slot per hand. A same-role second device corrupts the real controller: 10 573 SimplePoseHistory errors in run 1, 112 rebootstraps in run 2.
    - Two trackers on the same LEDs alternate ownership (`filterTrackedLedsForOtherControllers`). This only affects the clone, not distinct Touch Plus LEDs.
    - The shared queues exist only after a Frame controller has connected.
  - **Gate B is now the only 6DoF unknown.** The clone is disabled again on the Frame (`cv_clone_serial` = "").
  - **Real-controller check:**
    - With real Touch Plus, `tf_skeldump watch` showed curl following the hands: index 0→1 with the trigger, middle/ring/pinky ~0.05→1 with grip, thumb ~0.4–0.6 while touching a surface, both hands independently.
    - Two fixes came out of it:
      - (a) The driver dropped every packet after the bridge's activity was recreated in the same process (seq restarted at 1 from the same ip:port), so there was no input and no heartbeat. A big jump back or a 0.5 s gap now resyncs.
      - (b) Side effect of declaring optional hand tracking: controllers set down make the Quest switch to hands. The OpenXR profile goes `none` and the bridge reports `off` until they're picked up. The bridge now logs the profile changes.
- **2026-10-03 (night): radio-fw sniffer ready for the dongle** (phase 2, before hardware).
  - `radio-fw/`: bare-metal nRF52840 Dongle firmware (nrfx MDK + TinyUSB CDC). Raw RADIO RX into a 64-slot DMA ring, TIMER0 µs stamps at ADDRESS (PPI 26), RSSI, CRC status, channel hopping, and an RSSI sweep of 2400–2500 MHz. Links at 0x1000 so the stock MBR and USB bootloader stay. `build.sh` builds it, and `build.sh flash` reboots the dongle into DFU (GPREGRET 0xB1) and flashes it.
  - `tools/radio.py`: ports / dfu / status / sweep / sniff, plus JSONL capture.
  - Discovery preset confirmed in syncboss: logical address 7 = BASE1 `0xFACEB00C` + AP7 `0xAA` (`FUN_0001bb78`, `FUN_0001bb90`), 2402 MHz (`FUN_0001bcf0(2)`). The test path's PCNF1 is `0x030400FF` (MAXLEN 255, BALEN 4, big-endian).
  - Verified without hardware: clean build with no warnings, vector table at 0x1000 with our RADIO/USBD/POWER/SysTick handlers, struct sizes asserted on both sides, the C COBS code transcribed and fuzzed against the Python side (20k frames), and every `radio.py` command run against a fake dongle. Not yet run on a dongle.
- **2026-10-04: static RE for pairing done; offline host tools** (PROTOCOL.md Q2–Q6, open items 1, 4, 5, 6).
  - Pairing pinned: `SetupX25519Keys` 0x12, then `PairingData` 0x11 carrying `[base addr][link key]`, CCM-wrapped under the first 16 bytes of the X25519 secret. The link key is host-chosen. Host Pulsar version `0x1701`.
  - Input is host-registers fed from a 61-byte deerfly sample, not a HID report.
  - New offline tools, all with selftests: `tools/pulsar_host.py` (pairing packets), `tools/pulsar_input.py` (input decode), and `pulsar_crypto.py scan --iv`.
- **2026-10-04: planning pass** ([MASTER-PLAN.md](MASTER-PLAN.md)).
  - The code audit found that the dongle firmware has no transmit path yet, and the post-pairing command layer (register access, LED, IMU, haptics) isn't RE'd.
  - The deerfly firmware *is* in the dumps (Cortex-M23). PROTOCOL said otherwise.
  - The relay-based Gate B can only give an early positive, never a negative, because the Quest strobes the LEDs on its own camera schedule.
  - Work is split into RE, build, audit and hardware sessions.
- **2026-10-04: first session results** (reports in [docs/re/](re/), folded into PROTOCOL / FRAME-TRACKER):
  - **RE-2:** the Touch Plus LEDs **can't stay on**. cmd 0x28 clamps the on-time to 75 µs, and the pulse phase is set on the host clock, so 6DoF needs the dongle to flash inside the Frame's camera exposures. Also pinned: the IMU (ntf 1, 500 Hz, ±32 g / ±4000 dps), the input map, haptics, and the per-unit cal read (cmd 0x2b). Several Q4 claims were corrected.
  - **AUDIT-1:** the 0x47604 question is settled (pairing wrap only). CCM runs on **uplink only**. The negotiation and steady-state nonces are pinned. The on-air SPL command byte is `(num<<1)|read`. A real Quest uses per-device keys (0x1d), so its sessions can't be decrypted by sniffing.
  - **DEV-1 (on device):** Touch-only **works**: our driver can create the tracker queues itself. Relay Gate B: 0 hits, as expected. No version drift. **The Frame has no CDC ACM**, so the dongle talks over USB HID (hidraw). It has one USB-C port. With the 8-LED model, XRService logs ~300 "neighbor" errors/s; RE-3b is investigating.
  - RE-3 was stopped by a safety check; its exposure-hook goal is replaced by a closed-loop LED phase sweep in BUILD-2.
