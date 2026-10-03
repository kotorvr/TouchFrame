# Frame tracker: can Valve's camera tracker 6DoF-track a foreign LED controller?

**Short answer: yes, and the driver half is now proven on device (§9, 2026-10-03):** a clone of a
Frame controller injected by driver_touchframe was LED-tracked by XRService, 2.3 mm / 0.64° median
from the real controller. No XRService patch, no Roy radio.
Remaining risk is Gate B, i.e. whether Touch Plus LEDs blob, plus one constraint: one tracked
controller per hand, so the same-hand Frame controller must be off (§9.3).
Controllers reach Valve's camera tracker (XRService) through three named OpenVR **block queues**
(shared-memory ring buffers owned by vrserver). Any driver loaded into vrserver can obtain the
block-queue interface and open those queues by name. A third-party driver that writes the same
blocks — a connect event carrying a `lighthouse_config` LED model, then a ~240 Hz IMU stream —
should be tracked by XRService exactly like a first-party Steam Frame controller, and 6DoF poses
come back on a per-device pose queue. The one thing *not* exposed over the block queues is **LED
strobe sync**: the camera exposure schedule is sent only to driver_cv over XRIPC, and driver_cv
relays it to the controller over the Roy radio. Our options for the LED problem are in §3 — the
cleanest is to not strobe at all and run the Touch Plus LEDs continuously.

Evidence is from the Frame binaries and logs (SteamVR on device dated 2026-10-01; XRService build
`2026-09-23 23:30:05 64f342ccba`), copied read-only to `artifacts/frame/` (gitignored). Tags:
**CONFIRMED** = seen directly in logs or decompiled code; **INFERRED** = strongly implied but not
yet tested on device; **UNKNOWN** = still open.

Address conventions:
- `driver_cv.so` addresses are Ghidra addresses, image base `0x100000` (ELF vaddr + 0x100000).
- `XRService` (non-PIE, base `0x200000`) and `libArcturusPerception.so` are ELF vaddrs.

Reusable tools written for this (in `tools/ghidra/`): `DumpByStrings.java` (decompile every
function that references a string),  `DecompileAt.java` (decompile a list of addresses in a
no-analysis import of a huge binary), `xref_scan.py` (find string xrefs by ADRP/ADD scan without
Ghidra), `annotate_strings.py` (annotate a no-analysis decompile with the strings its constants
point at), `run_frame.sh` (driver for the above).

---

## 0. Architecture (CONFIRMED)

```
 Roy radio (spidev0.1) ─► driver_cv.so (in vrserver) ──IVRBlockQueue_005──► XRService (owns cameras)
                          CRoyController                /xrservice/controller/event  (connect/disconnect + config JSON)
                          CCVTrackedControllerDriver    /xrservice/controller/data   (IMU samples)
                                 ▲                       /xrservice/controller_<id>/pose (6DoF poses back)
                                 └── XRIPC (/dev/shm/XR_*, /run/user/1000/xrservice-ipc) ──►
                                        AddFutureControllerCameraExposureTimings (exposure sched → LED sync),
                                        UploadControllerConfig, Set LED brightness, pose/relocalization, …
```

- XRService links `/usr/lib/libopenvr_api.so` (→ `/opt/steamvr/bin/linuxarm64/libopenvr_api.so`)
  and connects to the queues as an OpenVR client: logs `[ControllerTracking] Connected to
  IVRBlockQueue successfully`, `[DeckardCaptureSource] Connected to controller data/event block
  queue at /xrservice/controller/{data,event}` (XRService `FUN_00f298f0`, string xrefs at
  `0xeb68e0`, `0xf298f0`).
- driver_cv gets `IVRBlockQueue_005` through the normal driver context
  (`IVRDriverContext::GetGenericInterface`), in its one-shot interface-table init
  `FUN_00253190` (requests `IVRBlockQueue_005`, `IVRPaths_002`, `IVRProperties_001`,
  `IVRDriverInput_005`, `IVRIOBuffer`-free). The cached getter is `FUN_00252690`
  (`return DAT_005afd38`).
- The queues are **plain vrserver IVRBlockQueue objects addressed by string name**
  (`CVRBlockQueueManager`, `vrcommon/blockqueue.cpp`; shm files `/dev/shm/u1000-Shm_*` plus
  `BlockQueueHeader_<name>` / `BlockQueueHeaderMutex_<name>`). vrserver create path
  `FUN_0035ff28(this, name, dataSize, headerSize, count, flags)` validates `1 <= count <= 128`,
  `dataSize != 0` and `headerSize >= 0x10` (argument names corrected in §8). This is the same
  interface any third-party driver in vrserver already uses for its own queues.
- Connect→track log sequence (vrserver.txt then XRService log, 2026-10-02 23:26:46):
  `CCvControllerDriver Activate` → `Connected to controller data block queue:
  /xrservice/controller/data` → `… event …` → `… pose block queue: /xrservice/controller_1/pose`
  → `Sent controller connected to controller event block queue` → XRService `Received controller
  Connection event for device 1` → `Received controller configuration for device 1: {default,
  onboard}` → `Now we will start tracking controller 1` → `Received first IMU sample` → `Setting
  camera streaming mode for controller tracking to 4` → `Trying to track first LED frame` →
  `[ContrLedsStats 0]: Observed LED n …` → poses stream back.

---

## 1. How XRService decides which devices it tracks (Q1)

- **CONFIRMED: only via the event block queue, and only driver_cv writes it.** XRService's
  `DeckardCaptureSource` connects to `/xrservice/controller/event` and `/data` and processes a
  Connection event followed by a config event (XRService `FUN_00eb0b00`, strings `Received
  controller config event after a connection event…`, `Received controller config event, but no
  controller connection event…`, `Received a duplicated controller config event…`). The device is
  a `uint deviceId`; there is **no** code path in XRService or driver_cv that scans the vrserver
  tracked-device list, reads another driver's `Prop_*`, `Prop_RegisteredDeviceType`,
  `Prop_DriverProvidedChaperone`, or a third-party driver's resource JSON. XRService never calls
  back into OpenVR to enumerate devices; it only reads these three shm queues.
- **CONFIRMED: on the driver_cv side, enrollment is gated to Roy-radio peripherals.** driver_cv
  creates a `CCvControllerDriver` only when a controller connects on its Roy BLE dongle
  (`Creating new driver for controller <sn>`, `CRoyController::OnConnectOrReconnect`,
  `CRoyPairing`). So **a stock third-party OpenVR driver that merely adds a tracked device with a
  `lighthouse_config` property will NOT be picked up by the camera tracker.** The tracker is not
  property-driven or resource-driven; it is block-queue-driven.
- **CONFIRMED: the gate is a shared-memory message, not a radio secret.** The enrollment message is
  just a block written to `/xrservice/controller/event` by `FUN_001dfe78`
  (`WriteConnectionOrDisconnectionInBQ`; callers `FUN_001e0570` connect / `FUN_001e0538`
  disconnect). The block carries `deviceId (u32)`, an event type (connect=1, disconnect=0), and two
  JSON strings copied with `strncpy(…, 0x2fff)` into the block: the **working ("default") config**
  and the **onboard config**. Property keys written alongside, **on the block handle** via
  `IVRPaths_002`: `/controllerConfigData/deviceSerialNumber`,
  `/controllerDefaultConfigData/blockDataSize`, `/controllerOnboardConfigData/blockDataSize`. The
  two `blockDataSize` values are **required**: XRService takes each JSON string's length from them
  (§8). Max JSON length 0x3000 each (`config string length was too long` guard). The queue is
  created with data size `0x6010`, header size `0x200`, block count 4 (corrected in §8; `0x200` is
  the header size, not the count).
- **INFERRED (this is the opening):** because IVRBlockQueue is a vrserver-process singleton keyed by
  string name, and our driver loads into the **same** vrserver process as driver_cv, our driver can
  call `GetGenericInterface("IVRBlockQueue_005")` and `Connect`/`Create` the exact same
  `/xrservice/controller/{event,data}` and `/xrservice/controller_<id>/pose` names, then write a
  synthetic connect event + Touch Plus config with a *new, non-colliding deviceId*. XRService does
  not authenticate the writer. This is standard OpenVR interface use, in-process, no patching.

### Config format (CONFIRMED — captured live)

The config strings are a two-key JSON object `{ "default": {...}, "onboard": {...} }`. The
**default** object is the one the camera tracker uses; `onboard` is the controller's own copy. The
default object captured from a real Frame controller (XRService log 2026-10-02 23:26:46, device 1):

```json
{
  "device_class": "controller",
  "device_serial_number": "483c39e041f4",
  "head":  { "plus_x":[…], "plus_z":[…], "position":[…] },          // grip/openxr frame
  "imu":   { "plus_x":[…], "plus_z":[…], "position":[…] },          // IMU extrinsics in controller frame
  "lighthouse_config": { "modelNormals": [[…]×N], "modelPoints": [[…]×N] },  // LED geometry (meters)
  "manufacturer": "Valve",
  "model_number": "Steam_Frame_Controller_Right",
  "revision": 1,
  "tracked_controller_role": "right_hand"
}
```

- `modelPoints`/`modelNormals` are the per-LED 3D positions (m) and outward normals in the
  controller frame — exactly the constellation model a PnP tracker needs. Count = number of LEDs
  (18 on the Frame controller; LED indices 0–17 appear in `[ContrLedsStats]`). The base template is
  loaded from `{frame_controller}/config/frame_controller_right_base.json` and the per-unit model is
  overlaid from the controller's flash (`Overwriting model point hash`).
- Optional camera-tracker extras parsed by libArcturusPerception (`FUN_0263af50`/`FUN_0263acc0`,
  "led_type"/"has_retro_reflectors"/"led_nominal_brightness" xrefs near `0x263a*`):
  - `cv.has_retro_reflectors` (bool) — marks passive retroreflective markers vs active LEDs.
  - `led_type` — enum `ir_everlight` (2) / `ir_vishay` (1) / `unknown` (0); only affects default
    brightness (0.75 unknown, {0.75,0.4,0.75} table at `0xa507c0` for everlight by channel).
  - `led_nominal_brightness` (double) — optional.
  - `channelMap` — maps LED index → hardware channel (seen in on-device `roy/*.json`).
- A second, fully worked example is **embedded in the XRService binary** as a peripheral/sim config
  `device_serial_number:"SteamDeck"`, `model_number:"Roy_K2C_Left_CV"`, 9 LEDs all `normal [0,0,1]`,
  with `"cv": { "has_retro_reflectors": true }` (XRService `0xc9f590`). This is a ready-made minimal
  template to copy for our own device.

---

## 2. How IMU samples reach XRService (Q2)

- **CONFIRMED: over `/xrservice/controller/data`, not IVRDriverInput and not IVRIOBuffer.**
  driver_cv writes one IMU sample per block with `FUN_001d44d8` (acquire-write-block → fill →
  submit; strings `Failed to aquire write block`, `[LargeGapControllerImuAndPose] not
  bQueueHasReaders …`). Queue created data size `0x30`, header size `0x200`, count 4, in
  `FUN_001d9a40`.
- **CONFIRMED: source is radio, but the transport to XRService is generic.** driver_cv receives IMU
  from the Roy controller radio, but `FUN_001d44d8` just copies it into the data queue. XRService
  reads it in `FUN_00eb6f30` / warns `We are receiving IMU sample for controller with deviceId %d
  in the past`, `Controller IMU latency is suspiciously high … sync issue`, `Waiting for missing
  IMU samples to track a frame`.
- **Sample block layout (CONFIRMED size and offsets from writer `FUN_001d44d8` and XRService
  reader `0xf2a460`; corrected 2026-10-03, the earlier 0x14/0x20 offsets were wrong):**
  ```
  offset 0x00  uint32  deviceId          (= the config's deviceId)
  offset 0x08  double  timestamp_seconds (same clock as poses; see below)
  offset 0x10  float×3 accel  (m/s^2)    offsets CONFIRMED; accel/gyro order INFERRED
  offset 0x1c  float×3 gyro   (rad/s)    (XRService negates the 0x10 vector on read)
  offset 0x28  uint32  flags             INFERRED off-scale flags; 0x04 and 0x2c unused
  ```
  The caller `FUN_001d46c0` time-stamps with `param2 + (int64 at PTR_DAT_005a1950) *
  (double at PTR_DAT_005a1c78)` — a tick→seconds conversion shared with pose reads.
- **Rate / clock (CONFIRMED):** XRService's controller tracker config uses `imuFrequency: 240`
  (embedded options JSON, XRService `0xa250d3`). The ICM-42688/42686 on the controller streams at
  240 Hz. The IMU clock must match the camera/exposure timebase: the timestamp field is seconds on
  the same monotonic clock XRService stamps camera frames with. The Roy dongle maintains this via a
  1 µs timesync (driver_cv `Initializing Timesync GPIO`, `FUN_001f9478`: libgpiod `gpiochip9`
  line 11, `roy_dongle_driver`; device-tree `imu_sync_clk`) and `Controller <sn> timesync
  converged`. **For an injected device we must put our Touch Plus IMU on the same clock** (convert
  our radio timestamps to XRService's `ST::getTimestampNow()` = `oc::now_seconds()`, which is
  `clock_gettime(4)`, i.e. **CLOCK_MONOTONIC_RAW** seconds, libArcturusPerception `0x322070`:
  `mov w0,#4; bl clock_gettime`). **Corrected 2026-10-03, CONFIRMED on device (§9):** a real
  controller's IMU block read live was 5.2 ms old on CLOCK_MONOTONIC_RAW and −214 ms "old" on
  CLOCK_MONOTONIC. The two clocks drift apart by ~0.1 s per hour of uptime.
- **No alternate IVRDriverInput/IVRIOBuffer path:** driver_cv does request `IVRDriverInput_005`
  (used for the HMD/skeletal/`CHandAnimEvaluator`), but the camera tracker never reads controller
  IMU from it — only from the data block queue. There is no `/proc/<id>/imu` IVRIOBuffer path in
  driver_cv or XRService.

---

## 3. LED sync / strobe (Q3)

- **CONFIRMED: the exposure schedule is pushed from XRService to the driver, not published on a
  queue.** XRService calls its OpenVR *client* back over XRIPC with
  `XRIPCServer::callClient_AddFutureControllerCameraExposureTimings(double startExposure, double
  endExposure, uint32, bool)` (libArcturusPerception `0x1b33d0`, client function id 20 in the
  reverse dispatcher `XRIPCClient::That::processClientFunction` at `0x1a8590`, case `0x1a8b44`
  unpacks two doubles). It lands in driver_cv `onAddFutureControllerCameraExposureTimings`
  (`FUN_001d1b90`, `cv_trackedhmddriver_shared.cpp:1865`).
- **CONFIRMED: driver_cv turns exposure timings into an LED period/on-time/phase and sends it over
  the radio.** `FUN_001f54c8` (`%s - First LED frame scheduled`, then `P%d: exposure first/update/
  repeat/backwards`) tracks successive exposure timestamps; first period defaults to
  `0.03333s` (30 Hz). `FUN_001f4b78` computes the schedule and sends it to the controller with
  `FUN_001fafd8(dongle, dongle2, 0x66, 0xe, &buf)` where the 0xe-byte `buf` =
  `{ uint32 delay(≈phase, ×16e6 units), int32 period_ns, int32 ontime_ns, uint16 count }`. LED
  brightness is a separate radio command, `FUN_001f47f8` / `Set LED brightness for controller %d ->
  %d` and `LED VCC` (`FUN_001f5660`). The on-device strobe matches `docs/PROTOCOL.md` §Q4
  (`pulsar_manager_set_led_timing`, p/ot/d = period/on-time/delay).
- **CONFIRMED: cameras run a dedicated short-exposure controller frame interleaved into SLAM.**
  `setControllerTrackingStreamingMode() streamingMode: 4`, `Setting camera streaming mode for
  controller tracking to 4`, `Controller (30Hz, Manual exposure)`,
  `setControllerTrackingFrameExposureTimeInMsAndGain`. Guards:
  `Found controller tracking frame with exposure of %f. Dropping frame.` and `Controller frame
  exposure time is less than 1us. This can lead to LEDs not flashing.` So XRService emits ~30 Hz
  manual-exposure controller frames and expects the LEDs lit during each.
- **CONFIRMED: an always-on / passive path exists.** `has_retro_reflectors` + `Using retroreflector
  controller on a HMD without IR illuminators. Tracking will not work.` plus the Frame's own IR
  illuminator (`/sys/class/leds/mp3317-scene-illum-ir`) prove XRService can track **continuously
  lit / passively reflective** markers with no per-exposure strobe — that is how a retroreflector
  controller works. There are also adaptive-threshold options (`useAdaptiveThresholdForLEDs`,
  `useAdaptiveThresholdForRetroreflectors`) and a few-/one-LED path (`FEW_LED_TRACKING`,
  `enableFewLedTrackingMode: true`, `estimateYawFor1LEDControllers: true`) — the one-IR-LED Steam
  Controller rides this.
- **Conclusion for LED sync (INFERRED):** we do **not** need to reproduce Valve's strobe. If we keep
  the Touch Plus LEDs **continuously on** (we drive them over our own nRF dongle, per
  `docs/PROTOCOL.md`), they are lit during every controller-frame exposure and XRService's blob
  detector + PnP will see the full constellation. We lose strobe-coded disambiguation and spend
  more controller battery, but 6DoF PnP from always-on LEDs is exactly the retroreflector case.
  Risk: XRService may auto-tune the controller-frame exposure assuming strobed LEDs; if blobs
  saturate or wash out we tune via the exposure/threshold options. Getting the real strobe is only
  possible by also reading the exposure schedule (we don't have it — it goes to driver_cv), so
  continuous-on is the pragmatic route; strobing is a later optimization if we can snoop the
  schedule.

---

## 4. Could our own client use the XRService IPC directly? (Q4)

- **CONFIRMED and NOT recommended as the control channel.** The driver↔XRService control link is
  `PE::XRIPCSession`/`XRIPCClient` over `/run/user/1000/xrservice-ipc` + `/dev/shm/XR_{Client,
  Server}{Request,Response}_*` ring buffers (`createXRIPCSession`, `XRIPCSession::startSession`,
  `call_Start`, `storeRoyDongleSerial`, pose/chaperone calls). XRService enforces a **single
  session**: `isThereASessionRunningInAnotherProcess` / `…InAnyProcess`,
  `shouldAutoRestartService`. A second XRIPCClient would collide with driver_cv's session. So we do
  **not** open a second XRIPC session.
- **Poses come back on a block queue, which is the clean integration point (CONFIRMED).** XRService
  writes 6DoF poses to `/xrservice/controller_<id>/pose` (data size `0x90`, header `0x200`, count
  4, flag `OwnerIsReader`, created by driver_cv in `FUN_001d9a40`; XRService connects). driver_cv
  reads them in `FUN_001d4760` (WaitAndAcquireReadOnlyBlock, read type New, 100 ms timeout,
  `memcpy 0x90`, release) from its `readControllerPosesThread` (`FUN_001d9e60`), then transforms
  grip↔IMU↔head and reports to OpenVR. The 0x90 pose block holds deviceId, timestamp (`-1.0` ⇒
  invalid), orientation quaternion, position, linear and angular velocity, at the same clock as
  the IMU. Exact field offsets in §8.
- **So the whole loop for an injected device is block-queue only:** we `Create`/`Connect` the three
  queues by name, write connect-event+config, stream IMU on `/data`, and **read our device's poses
  back on `/xrservice/controller_<ourId>/pose`**, which our driver_touchframe then reports as the
  OpenVR controller pose. No XRIPC, no XRService patch.

---

## 5. Steam Controller / external-tracker / generic paths (Q5)

- **CONFIRMED generic camera-tracking knobs** (XRService embedded options JSON `0xa250d3`, and
  on-device `cv/resources/settings/default.vrsettings`): `enableFewLedTrackingMode`,
  `estimateYawFor1LEDControllers`, `ledPositionStdCm` (0.03), `filterTrackedLedsForOtherControllers`,
  `useAdaptiveThresholdForLEDs`, `minControllerFeatureNNModel` (palm/grip NN fallback),
  per-controller DIPr ONNX models keyed by `model_number`. The one-IR-LED Steam Controller and the
  18-LED Frame controller both flow through the same block-queue + `lighthouse_config` mechanism;
  the only per-device specialization is the model JSON and (optionally) a DIPr/feature NN model.
- **`WifiSync` (CONFIRMED, informative):** `oc::WifiSync` server/client (`Starting WifiSync in
  SERVER/CLIENT mode`, `AddMultiDeckardChildRoyDongleSerial`, `Server controller frame end …
  frame period …`, `getServerFrameTimeForLocalTime`, NRF timestamp round-trips) is Valve's
  multi-headset shared controller tracking: it ships camera-frame exposure timing and dongle serial
  between headsets over the network. It confirms the exposure schedule is transportable and gives a
  reference for how phase is carried if we ever want true strobing.
- **"external tracker" in driver_cv is lighthouse-only (CONFIRMED, not our path):**
  `trackRefFromHead`, `sensorsFromLighthouse`, `Could add as alternate, but disallowed by
  LighthouseDB` are all SteamVR *lighthouse base-station* tracking, not the camera tracker. Not
  applicable.

---

## 6. Recommended integration route for Touch Plus

**Route: in-process block-queue injection from `driver_touchframe`, LEDs continuous-on.**
driver_touchframe already loads into vrserver and presents the OpenVR controllers. Add a
"camera-tracked" backend to it:

1. **Get the block-queue interface.** `VRDriverContext()->GetGenericInterface("IVRBlockQueue_005")`
   (the version string is present in both driver_cv and vrserver; confirm `_005` is current at
   runtime). It is **not** in the public `openvr_driver.h`, but its C function table is published in
   `openvr_capi.h`; the verified C++ declaration is `driver/src/blockqueue.h` (§8).
2. **Create/connect the three queues by exact name** (all with header size 0x200, count 4):
   `/xrservice/controller/event` (data 0x6010, flags 0), `/xrservice/controller/data` (0x30, 0),
   and our own `/xrservice/controller_<id>/pose` (0x90, `OwnerIsReader`), created *before* the
   connect event. For the shared event/data queues prefer **Connect**: driver_cv's first
   controller *Creates* them and has no fallback to Connect, so if we create them first a real
   Frame controller that activates later would fail to open them (§8). Use a `deviceId` that does
   not collide with any Roy controller (they start at 1). Keep it small (e.g. 16–63): XRService
   sizes a per-device table to `deviceId+1` entries.
3. **Write the connect event + config.** One `event` block: `deviceId`, type=connect(1), a 64-bit
   hardware id, and the two JSON strings at 0x10 (onboard) and 0x3010 (default), **plus the two
   `blockDataSize` uint64 properties on the block handle** before releasing it (§8). Our driver
   must provide:
   - **LED model JSON** (`lighthouse_config.modelPoints` = per-LED xyz in meters in the controller
     frame, `modelNormals` = per-LED unit outward normals). Source: Meta's Touch Plus LED geometry.
     If not recoverable from the controller, calibrate it with the Monado constellation tooling
     (`docs/FEASIBILITY.md` prior-art) or measure it. Format matches §1 exactly.
   - **`imu`** extrinsics (IMU pose in the controller frame) and **`head`** (grip/openxr frame).
     Start from the Touch Plus CAD; refine with XRService's own `controllerCalibration` history
     (it auto-refines `controllerFromImu`).
   - `model_number` (pick our own, e.g. `TouchFrame_Right`), `tracked_controller_role`,
     `manufacturer`, `device_serial_number`. Optionally `cv.has_retro_reflectors:false`,
     `led_type:"unknown"`.
4. **Stream IMU** on `/data` at 240 Hz: one 0x30 block per sample, `{deviceId, timestamp_s (CLOCK_
   MONOTONIC_RAW seconds, same clock XRService uses) @0x08, accel m/s² @0x10, gyro rad/s @0x1c,
   flags @0x28}`. Timestamp
   fidelity vs the camera clock is the single most important correctness factor (XRService rejects
   past/late samples and warns on latency).
5. **Drive the LEDs continuously on** over our nRF dongle (per `docs/PROTOCOL.md`
   `set_led_ontime_us`/period), bright enough to blob during the ~30 Hz manual-exposure controller
   frames. No strobe sync required for first light (Gate B). Tune brightness/exposure if blobs
   saturate.
6. **Read poses back** from `/xrservice/controller_<id>/pose` (0x90 blocks), apply the grip↔imu↔head
   transforms, and report the pose on our OpenVR controller. Fuse with our IMU for prediction as
   driver_cv does.

**What our driver must provide, summarized:**
- *LED model JSON:* `lighthouse_config.modelPoints` (N×[x,y,z] m) + `modelNormals` (N×[nx,ny,nz]
  unit), controller frame. Plus `imu`/`head` extrinsics, `model_number`, role, serial.
- *IMU:* 240 Hz, per-sample 0x30 block `{u32 deviceId @0, double t_sec @8, f32×3 accel @0x10,
  f32×3 gyro @0x1c, u32 flags @0x28}`, timestamps on XRService's clock (CLOCK_MONOTONIC_RAW s).
- *LEDs:* continuous-on during capture (period/on-time set so the LED is lit across the controller-
  frame exposure); brightness ~ `led_nominal_brightness` default. Strobe sync is optional/later.

**Why not a stock third-party driver with a `lighthouse_config` property:** CONFIRMED there is no
property/resource/device-list path into the camera tracker (§1). The block queue is the only door.

**Gate B (unchanged):** this is all contingent on Touch Plus LEDs actually producing blobs in the
Frame's controller-tracking frames. The injection above is the fastest way to *test* that — once
the config+IMU are accepted, `[ContrLedsStats]` lines in the XRService log will immediately tell us
whether our LEDs are seen and PnP initializes, exactly as they did for the real controller.

---

## 7. Open items / to verify on device (UNKNOWN)

- ~~IVRBlockQueue vtable ordinals~~ — **resolved statically (§8) and CONFIRMED on device (§9):**
  `GetGenericInterface` returns `IVRBlockQueue_005` and `IVRPaths_002`, and every slot we call works.
- ~~Exact event-block field layout~~ — **resolved, §8** (deviceId, type, hardware id, two JSON
  strings; lengths travel as block properties).
- **Pose block (0x90)** — offsets resolved (§8); units and frames CONFIRMED live (§9.4): metres,
  model axes at the IMU origin, body-frame angular velocity. Still UNKNOWN: the byte at 0x04 and the
  3-vector at 0x78.
- ~~Concurrent controllers~~ — **CONFIRMED (§9.3): XRService tracks one controller per hand
  role** (two tracker slots). A third device shares a slot and corrupts that controller's tracking.
- **deviceId room** — id 40 works (§9). Whether XRService caps concurrent controllers (`Too many
  controllers to record, max is 4` is a recorder cap, not necessarily a tracker cap) and whether an
  out-of-range id is accepted. Seen so far: XRService's pose-queue handle table is a vector grown to
  `deviceId+1` (XRService `0xeb69f0`), so large ids work but cost memory; ids are formatted as
  signed decimal in the queue name.
- **Exposure interaction** — whether continuous-on LEDs survive XRService's auto-exposure for
  controller frames, or whether we must pin a manual exposure/gain (the settings exist:
  `setControllerTrackingFrameExposureTimeInMsAndGain`, `ActiveExposureController`).
- **Partly answered (§9.1): the shared queues exist only while a Frame controller is connected**
  (`Connect` returns 2 QueueNotFound before that; they vanished, handle error 4, when SteamVR shut
  down). Open: whether driver_cv destroys them when the last Frame controller disconnects
  while vrserver keeps running. That matters for a Touch-only setup.
- **Whether driver_cv must be present at all** — i.e. can our driver `Create` the queues when no Roy
  controller has ever connected, and will XRService's `DeckardCaptureSource` connect to queues it
  did not create. (XRService connects lazily on controller events, so likely yes; verify.) Note the
  trade-off in §8: if we Create the shared event/data queues, a Frame controller that activates
  later cannot open them, because driver_cv's first controller always Creates and never falls back
  to Connect.

---

## 8. IVRBlockQueue interface (verified)

Static verification of everything our driver will call, done 2026-10-03 against the Frame's
`vrserver`, `driver_cv.so` and `XRService` (copies in `artifacts/frame/`). The declaration we
compile against is `driver/src/blockqueue.h` (written from scratch; each slot cites its evidence).
vrserver addresses below are **ELF vaddrs** (Ghidra = vaddr + 0x100000); driver_cv addresses
follow the Ghidra convention above; XRService addresses are ELF vaddrs.

### 8.1 Where the declaration comes from

- **CONFIRMED: Valve publishes this interface, just not in `openvr_driver.h`.** `openvr_capi.h` and
  `openvr_api.json` carry `VR_IVRBlockQueue_FnTable`, `EBlockQueueError`, `EBlockQueueReadType`,
  `EBlockQueueCreationFlag` and `IVRBlockQueue_Version`: `_004` in v1.12–v1.16, `_005` from v1.23
  through master (v2.15.6). The only `_004`→`_005` change is the extra `unFlags` argument to
  `Create` plus the `OwnerIsReader` flag. Several open-source drivers declare the same C++ class
  (e.g. Pimax-Native-SteamVR, PSVR2Toolkit, openvr_camera_sim), which matches.
- **CONFIRMED: the Frame's vrserver implements exactly that order.** RTTI: `20CVRBlockQueueManager`
  (typeinfo `0x5d0a38`, single-inherits `N2vr13IVRBlockQueueE`) has a 9-slot vtable at `0x5c35e8`.
  There is **no virtual destructor** in the interface. Compatibility wrappers `CVRBlockQueue_004`
  (vtable `0x5c0ec0`, 9 slots), `_003` (`0x5c0f48`, 8), `_002` (`0x5c0fc8`, 7), `_001` (`0x5c1040`,
  6) are tail-call thunks into the `_005` object, and each thunk uses the first unused argument
  register as scratch, which shows its argument count.

### 8.2 IVRBlockQueue_005 slots (all CONFIRMED)

| off | method | args after `this` | vrserver impl | evidence |
|-----|--------|-------------------|---------------|----------|
| 0x00 | `Create(u64* hQueue, const char* path, u32 dataSize, u32 headerSize, u32 count, u32 flags)` | x1 x2 w3 w4 w5 w6 | `0x260820` | `_004` thunk sets `w6=0` then jumps to slot 0; driver_cv call `(…, 0x30, 0x200, 4, 0)` |
| 0x08 | `Connect(u64* hQueue, const char* path)` | x1 x2 | `0x261af8` | driver_cv `FUN_001d9a40`; XRService `0xeb69f0` |
| 0x10 | `Destroy(u64 hQueue)` | x1 | `0x25fc08` | absent from `_003` thunks |
| 0x18 | `AcquireWriteOnlyBlock(u64 hQueue, u64* hBlock, void** ppBuf)` | x1 x2 x3 | `0x25f5b0` | driver_cv `FUN_001d44d8`/`FUN_001dfe78`; XRService `0xeb36f0` |
| 0x20 | `ReleaseWriteOnlyBlock(u64 hQueue, u64 hBlock)` | x1 x2 | `0x2611e0` | same writers |
| 0x28 | `WaitAndAcquireReadOnlyBlock(u64 hQueue, u64* hBlock, void** ppBuf, EBlockQueueReadType, u32 timeoutMs)` | x1 x2 x3 w4 w5 | `0x25fa30` | driver_cv `FUN_001d4760` (New, 100 ms); XRService `0xf29b20`/`0xf29cf0` (Next, 1 ms) |
| 0x30 | `AcquireReadOnlyBlock(u64 hQueue, u64* hBlock, void** ppBuf, EBlockQueueReadType)` | x1 x2 x3 w4 | `0x25f930` | thunks only |
| 0x38 | `ReleaseReadOnlyBlock(u64 hQueue, u64 hBlock)` | x1 x2 | `0x25eec8` | same readers |
| 0x40 | `QueueHasReader(u64 hQueue, bool* pbHasReaders)` | x1 x2 | `0x25ec28` | driver_cv `FUN_001d44d8`; XRService `0xeb36f0` |

All methods return `EBlockQueueError` (32-bit, `w0`). Handles are 64-bit
`PropertyContainerHandle_t`.

- **Versions (CONFIRMED):** `_004` = same 9 slots, `Create` without `flags`. `_003` = `_004`
  without `Destroy` (8 slots). `_002` additionally lacks `QueueHasReader`; `_001` additionally lacks
  `WaitAndAcquireReadOnlyBlock`. vrserver registers `IVRBlockQueue_001`…`_005`; driver_cv and
  XRService both request `_005`.
- **Create rules (CONFIRMED, CBlockQueue init `0x25ff28`):** `1 <= count <= 128`, `dataSize != 0`,
  `headerSize >= 16`, else `InvalidParam (5)`; `AlreadyInitialized (8)`; `InternalError (7)` when
  the shared-memory setup fails; `OperationIsServerOnly (9)` outside vrserver.
- **Error enum (CONFIRMED values in use, names from `openvr_capi.h`):** 0 None, 1
  QueueAlreadyExists, 2 QueueNotFound, 3 BlockNotAvailable, 4 InvalidHandle, 5 InvalidParam, 6
  ParamMismatch, 7 InternalError, 8 AlreadyInitialized, 9 OperationIsServerOnly, 10
  TooManyConnections.
- **Read types:** 0 Latest, 1 New, 2 Next (values CONFIRMED in use; semantics INFERRED from names:
  Latest = newest, may repeat; New = newest only if unread; Next = FIFO).
- **Creation flags:** `OwnerIsReader = 1` (CONFIRMED: the pose queue, whose creator reads).
- **Who creates what (CONFIRMED, driver_cv `FUN_001d9a40` called with `first ^ 1`):** the first
  controller driver instance *Creates* `/controller/{data,event}`; later ones *Connect*. Every
  instance *Creates* its own `/controller_<id>/pose` with `OwnerIsReader`. XRService only ever
  Connects. Creating a name that already exists fails (exact code INFERRED: QueueAlreadyExists).
- **Writers gate on readers (CONFIRMED):** driver_cv writes IMU only while `QueueHasReader(data)`;
  XRService writes a pose only while `QueueHasReader(pose)` is true.

### 8.3 IVRPaths_002 (needed for the event block)

- **CONFIRMED:** event-block metadata is attached to the **block handle** as properties through
  `IVRPaths_002` (both driver_cv and XRService request `IVRPaths_002`). Slots: `ReadPathBatch(root,
  PathRead_t*, n)` +0x00, `WritePathBatch(root, PathWrite_t*, n)` +0x08, `StringToHandle(u64*,
  const char*)` +0x10, `HandleToString(u64, char*, u32, u32*)` +0x18, checked against vrserver's
  `CVRPaths_001` thunks (vtable `0x5c0df8`). `PathWrite_t` is 0x38 bytes in `_002` (`bPostEvents`
  @0x30, `bValueChanged` @0x31; driver_cv sets `bPostEvents=1`); `PathRead_t` is 0x28 bytes. Both
  match `openvr_capi.h` master.

### 8.4 Event block (`/xrservice/controller/event`, 0x6010 bytes)

Writer driver_cv `FUN_001dfe78`, reader XRService `0xf29cf0` (consumer `0xf2d650`).

| off | type | field | tag |
|-----|------|-------|-----|
| 0x00 | u32 | deviceId | CONFIRMED |
| 0x04 | u32 | event type: 1 connect, 0 disconnect; configs parsed only for 1 | CONFIRMED |
| 0x08 | u64 | controller hardware id (XRService logs `Controller %d's hardware ID is 0x%016lx`) | CONFIRMED |
| 0x10 | char[0x3000] | JSON, length = block property `/controllerOnboardConfigData/blockDataSize` | CONFIRMED |
| 0x3010 | char[0x3000] | JSON, length = block property `/controllerDefaultConfigData/blockDataSize` | CONFIRMED |

- **The lengths are mandatory (CONFIRMED).** Between `AcquireWriteOnlyBlock` and
  `ReleaseWriteOnlyBlock`, driver_cv writes both `blockDataSize` paths with `WritePathBatch(hBlock,
  …)`, type `uint64` (tag 3, 8 bytes). XRService reads them with `ReadPathBatch(hBlock, …)` and
  builds each string from exactly that many bytes; if a read fails or the tag is not 3 it uses
  length 0. A block without these properties therefore delivers empty configs.
- `/controllerConfigData/deviceSerialNumber` (string, tag 5) is also written by driver_cv when
  known; XRService has no reference to it (optional).
- driver_cv copies each JSON with `strncpy(…, 0x2fff)`; the `>0x3000` length check only logs.
- Which JSON XRService treats as "default" vs "onboard" downstream is INFERRED from the property
  names. Sending the same full Touch Plus JSON in both slots is the safe choice.

### 8.5 IMU block (`/xrservice/controller/data`, 0x30 bytes)

Layout in §2 (corrected): `u32 deviceId @0`, `f64 time @8`, `f32×3 @0x10`, `f32×3 @0x1c`,
`u32 @0x28`. Offsets CONFIRMED from driver_cv's writer and XRService's reader (`0xf29b20` reads with
Next, 1 ms, then `0xf2a460` decodes). Accel-then-gyro order and the flags meaning are INFERRED
(public `vr::ImuSample_t` uses the same order and an off-scale flags word; XRService negates the
first vector, as one does for accelerometer sign conventions).

### 8.6 Pose block (`/xrservice/controller_<id>/pose`, 0x90 bytes)

Writer XRService `0xeb36f0` (filled in `0xeb3880`), reader driver_cv `FUN_001d4760` →
`FUN_001d9e60`.

| off | type | field | tag |
|-----|------|-------|-----|
| 0x00 | u32 | deviceId | CONFIRMED |
| 0x04 | u8 | flag byte copied from a tracker global; driver_cv ignores it | UNKNOWN |
| 0x08 | f64 | timestamp, seconds on the IMU clock; `-1.0` = no valid pose | CONFIRMED |
| 0x10 | f64×4 | orientation quaternion **w, x, y, z** | CONFIRMED (writer copies an x,y,z,w quaternion into w,x,y,z order; reader's quaternion product agrees) |
| 0x30 | f64×3 | position | CONFIRMED offset; metres INFERRED |
| 0x48 | f64×3 | linear velocity | CONFIRMED offset; m/s INFERRED |
| 0x60 | f64×3 | angular velocity (NaN replaced by 0 by the writer) | CONFIRMED offset; rad/s, body frame INFERRED |
| 0x78 | f64×3 | another 3-vector; driver_cv ignores it | UNKNOWN |

- Invalid-pose writers (`0xeb2170`, `0xec0d30`, `0xec1640`) set only deviceId and `timestamp =
  -1.0`; everything else in such a block is garbage.
- driver_cv applies a fixed rotation to the pose whose quaternion is (x=1, y=0, z=0, w=0),
  i.e. 180° about X, with zero translation (constant at driver_cv `0x4a4db0`), and rotates position
  and linear velocity but not angular velocity. CONFIRMED arithmetic; INFERRED meaning:
  XRService's tracking frame to SteamVR's (y-up) frame. Our driver must apply the same conversion.
- **Frames, CONFIRMED live (§9.4):** the block pose has the LED model's *axes* at the *IMU's
  origin*. SteamVR's raw device pose = flip(block) ∘ {model_from_head rotation, head.position −
  imu.position} (`cv::HeadFromPoseBlock`), residual 0.85 mm / 0.32°, world offset identity. Angular
  velocity at 0x60 is body-frame. Position is in metres.
- XRService *Connects* to the pose queue when it starts tracking the device and writes only while
  someone reads it, so our driver must `Create` it (`OwnerIsReader`) and keep a reader on it
  **before** sending the connect event.

---

## 9. On-device validation: a cloned Frame controller injected through the block queues (2026-10-03)

**Verdict: the route works end to end.** driver_touchframe registered a second device with
XRService through the `/xrservice/controller/{event,data}` queues. The device was a clone of the
user's real right Frame controller (`483c39e041f4`) under deviceId 40, with that controller's own
config and an IMU stream synthesized from its SteamVR pose. XRService started a tracker for it,
matched LED blobs to its model (`[ContrLedsStats]` for the clone's tracker) and wrote valid 6DoF
poses into our pose queue. Those poses matched XRService's own pose for the real controller to
**2.3 mm median / 0.64° median**.

Code: `driver/src/cv_tracker.{h,cpp}` (generic injection), `driver/src/cv_clone.{h,cpp}` (this
test), `driver/src/cv_source.{h,cpp}` (step 2, an ITouchSource for future feeds). All of it is off
unless `driver_touchframe.cv_clone_serial` is set.

### 9.1 What was confirmed live

- `GetGenericInterface("IVRBlockQueue_005")` and `("IVRPaths_002")` return non-null. Every slot in
  `blockqueue.h` that we call works: Create, Connect, Destroy, Acquire/ReleaseWriteOnlyBlock,
  WaitAndAcquireReadOnlyBlock, AcquireReadOnlyBlock, ReleaseReadOnlyBlock, QueueHasReader, plus
  IVRPaths StringToHandle/WritePathBatch.
- Our pose queue `/xrservice/controller_40/pose` (0x90, 0x200, 4, OwnerIsReader) is created at
  driver init. `Connect` to the shared queues returns **2 (QueueNotFound)** until a Frame
  controller connects. After that, Connect succeeds and XRService is already reading the event
  queue. On SteamVR shutdown the shared handles go invalid (error 4) once driver_cv tears down;
  we then destroy our pose queue.
- One connect event (deviceId, type 1, hardware id `0x5446…0028`, the same 2.9 KB JSON in both
  slots, both `blockDataSize` u64 properties written on the block) produced, within 1 ms:
  `Received controller Connection event for device 40` → `Received controller configuration for
  device 40` (the full JSON echoed back) → `Now we will start tracking controller 40` →
  `Connecting to the controller pose block queue at path /xrservice/controller_40/pose` →
  `initializing controller 1, serial number: tfclone_483c39e041f4`.
- XRService writes one pose block per IMU sample: 240 blocks/s, `timestamp = -1` until tracked.
  Pose latency (our read time minus block time) is **2.9 ms median**.
- **Clock: CLOCK_MONOTONIC_RAW** (corrects §2). The real controller's IMU blocks, read live, were
  5–14 ms old on MONOTONIC_RAW and −214 ms "old" on CLOCK_MONOTONIC.
- **IMU block semantics** (§8.5 INFERRED → CONFIRMED): 0x10 is accelerometer **specific force**
  (+g up at rest, m/s²); 0x1c is gyro in rad/s; both are in the config's `imu` frame; flags are 0
  in normal use. Our synthesized IMU vs the real controller's samples over 29 s: gyro error 0.33
  rad/s mean, no bias, **0 ms best-fit lag**; accel bias ~0.3 m/s², mean |error| 2.7 m/s²
  (dominated by the differentiated SteamVR velocity). XRService's first-sample log line prints the
  values exactly as written.

### 9.2 Runs

| Run | Clone role | Other controllers on | Result |
|---|---|---|---|
| 1 | right_hand | right (real), left (idle) | Clone got its own tracker but never a valid pose: 0 LED stats, 102 `shock` + 51 `Inflated covariance` logs, and **10 573 `[SimplePoseHistory] New pose timestamp … must be greater` errors** interleaving the real controller's and our timestamps. |
| 2 | left_hand | right (real), left (real, streaming) | No tracker created for the clone (left slot taken). "Valid" clone poses were the left controller's (~300 mm off), and our IMU corrupted the real left controller's filter: **112 rebootstraps**, 71 shocks. |
| 3 | left_hand | right (real) only, left switched off | **Clean.** Own tracker (`initializing controller 1, serial number: tfclone_…`), first LED frame tried at +0.3 s, LEDs matched at +8 s (`[ContrLedsStats 1]`, up to 9 LEDs, reprojection 0.07–0.8 px). 0 shocks, 0 inflations, 0 rebootstraps, 0 SimplePoseHistory errors. Real controller unaffected. |

Run 3 accuracy (clone CSV, 1 017 valid clone poses = 4.2 s in two segments of 3.3 s and 0.9 s):

| Comparison | Position | Angle |
|---|---|---|
| clone block vs XRService's own block for the real controller (same frame) | median 2.3 mm, mean 9.2, p90 26.4, max 33.1 | median 0.64°, p90 0.82° |
| clone → SteamVR (`HeadFromPoseBlock`) vs the real controller's SteamVR pose | median 2.1 mm, mean 9.5, p90 26.8 | median 0.64° |

The tails are probably the reference drifting rather than the clone: whenever the clone holds the
LEDs, the real tracker has none (§9.3) and runs on IMU alone. The constant ~0.6° matches the real
controller using its refined `controllerFromImuHistory/483c39e041f4.json` while the clone starts
from defaults (`History file … tfclone_….json does not exist`).

### 9.3 Constraints learned

- **One tracked controller per hand.** XRService accepts only `left_hand`/`right_hand`, and has
  two controller-tracking slots. A device whose role matches a live controller's shares that
  controller's per-role state (`SimplePoseHistory`, the filter) and wrecks it (runs 1 and 2).
  **For Touch Plus: the Frame controller of the same hand must be off** (or never connected)
  while its Touch Plus is camera-tracked. The two cannot run side by side.
- **A device connected while its slot is held does not get the slot when it frees up.** After the
  left controller disconnected in run 2, the clone stayed untracked until it was announced again.
  A real feed should re-send its connect event when the competing controller disconnects. Today
  CvTracker re-announces only after an XRService restart or when no pose block arrives at all.
- **LED ownership (`filterTrackedLedsForOtherControllers`, default true).** With two trackers on
  the same physical LEDs, observations go to one tracker at a time, never both
  (run-3 timeline: real 49:36–49:41 → clone 49:45–49:46 → real 49:51–50:03 → clone 50:10–50:11
  → real 50:17–…). The clone acquires only after the real tracker loses lock, then gives the LEDs
  back. This is an artifact of cloning; distinct Touch Plus LEDs won't collide.
- **The shared queues need a Frame controller to have connected since SteamVR started.** With
  no Frame controller, a Touch-only setup has no queues to connect to (see §7).
- `shock`/`Inflated covariance` in runs 1–2 came from the slot collision, not from synthetic-IMU
  spikes. Run 3 had none with the same synthesis.

### 9.4 Pose-block frame (CONFIRMED from run-1 data)

Fitting XRService's block pose for the real controller against driver_cv's SteamVR pose for it
(817 samples):
- with "block = LED model frame": 37.9 mm, 0.32°;
- with "block = IMU frame": 1.4 mm, 0.83°;
- with **model axes at the IMU origin: 0.85 mm, 0.32°**. The world offset is identity (±0.3 mm).

So SteamVR pose = flip(block) ∘ `{model_from_head.q, head.position − imu.position}`. driver_cv's
onboard IMU extrinsic has identity rotation, which is why only the origin moves. Angular velocity
at 0x60 is body-frame: relative error 0.00 as body frame vs 1.14 as world frame. Implemented as
`cv::HeadFromPoseBlock`; CvTouchSource rotates ω into world for SteamVR.

### 9.5 Reproducing

1. Put a controller config on the Frame, e.g. the XRService log excerpt with its
   `{"default":…,"onboard":…}` JSON. Never commit it.
   `~/touchframe-cv/clone_config.txt` is the default path (`cv_clone_config`).
2. With SteamVR stopped, set `driver_touchframe.cv_clone_serial` (substring of the real
   controller's SteamVR serial) and optionally `cv_clone_role` (opposite hand), `cv_clone_csv`
   (240 Hz log: steam/imu/rimu/ref/clone rows) in `~/.config/openvr/config/steamvr.vrsettings`.
   Then start SteamVR.
3. Switch the other-hand Frame controller off. Wear the headset; move the cloned controller.
4. `grep cvclone ~/.local/share/Steam/logs/vrserver.txt` shows the 2 s reports (clone vs real
   error, IMU comparison); the XRService log shows `[ContrLedsStats N]` for the clone's slot.

### 9.6 Next

- Gate B is unchanged and still the real question: do Touch Plus LEDs (driven always-on by our
  radio) produce blobs XRService matches to a Touch Plus LED model? Everything on the
  driver side of that is now proven.
- Touch Plus LED model JSON: positions/normals in metres plus `imu`/`head` extrinsics, in the same
  format as `clone_config.txt`. `head` should be the OpenXR grip frame.
- Feed CvTouchSource from the radio (`PushImu` at 240 Hz on `cv::NowSeconds()`, `PushInputs`),
  wire it into the Provider without the relay calibration (poses are already in SteamVR space),
  and re-announce on competing-controller disconnects.
