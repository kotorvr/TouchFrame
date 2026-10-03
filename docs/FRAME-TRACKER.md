# Frame tracker: can Valve's camera tracker 6DoF-track a foreign LED controller?

**Short answer: yes, very probably, and without patching XRService or touching the Roy radio.**
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
  `FUN_0035ff28(this, nameptr, blockSize, blockCount, flags, createFlag)` validates
  `blockCount-1 < 0x80` and `blockSize >= 0x10`. This is the same interface any third-party driver
  in vrserver already uses for its own queues.
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
  and the **onboard config**. Property keys written alongside:
  `/controllerConfigData/deviceSerialNumber`, `/controllerDefaultConfigData/blockDataSize`,
  `/controllerOnboardConfigData/blockDataSize`. Max JSON length 0x3000 each (`config string length
  was too long` guard). The queue is created with blockSize `0x6010`, count `0x200`.
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
  bQueueHasReaders …`). Queue created blockSize `0x30`, count `0x200`, in `FUN_001d9a40`.
- **CONFIRMED: source is radio, but the transport to XRService is generic.** driver_cv receives IMU
  from the Roy controller radio, but `FUN_001d44d8` just copies it into the data queue. XRService
  reads it in `FUN_00eb6f30` / warns `We are receiving IMU sample for controller with deviceId %d
  in the past`, `Controller IMU latency is suspiciously high … sync issue`, `Waiting for missing
  IMU samples to track a frame`.
- **Sample block layout (CONFIRMED size 0x30; field offsets INFERRED from `FUN_001d44d8`/
  `FUN_001d46c0`):**
  ```
  offset 0x00  uint32  deviceId          (= the config's deviceId)
  offset 0x08  double  timestamp_seconds (same clock as poses; see below)
  offset 0x14  float×3 accel  (m/s^2)    ┐ copied as two memcpys (0xc + 0xc) + 1 u32 at 0x18
  offset 0x20  float×3 gyro   (rad/s)    ┘ from a 0x18-byte source record
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
  `clock(4)` i.e. CLOCK_MONOTONIC seconds, read at `0x322070`).
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
  writes 6DoF poses to `/xrservice/controller_<id>/pose` (blockSize `0x90`, count `0x200`, flag
  reader=1, created in `FUN_001d9a40`). driver_cv reads them in `FUN_001d4760` (wait-latest block,
  `memcpy 0x90`, release) from its `readControllerPosesThread` (`FUN_001d9e60`), then transforms
  grip↔IMU↔head and reports to OpenVR. The 0x90 pose block holds position + orientation
  quaternion + linear/angular velocity + a validity/timestamp (`local_168 == -1.0` ⇒ invalid), at
  the same tick→seconds clock as the IMU.
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
   runtime, fall back to `_004`/`_003`). This needs a vendored `IVRBlockQueue` header — it is **not**
   in the public `openvr_driver.h` (checked v1.10–v2.15). We reconstruct the vtable from driver_cv:
   ordinals seen — create `*vtbl`, connect `*(vtbl+8)`, acquire-write `*(vtbl+0x18)`, submit-write
   `*(vtbl+0x20)`, wait-read-latest `*(vtbl+0x28)`, release-read `*(vtbl+0x38)`, has-reader
   `*(vtbl+0x40)`. (Reverse these offsets against the live lib before trusting them; §7.)
2. **Create/connect the three queues by exact name:** `/xrservice/controller/event`
   (blockSize 0x6010, count 0x200), `/xrservice/controller/data` (0x30, 0x200),
   `/xrservice/controller_<id>/pose` (0x90, 0x200, reader flag). If driver_cv already created
   `/controller/{event,data}` (a real Frame controller present), **connect**; else **create**. Use a
   `deviceId` that does not collide with any Roy controller (they start at 1; pick e.g. 0x100+).
3. **Write the connect event + config.** One `event` block: `deviceId`, type=connect(1), and the
   two JSON strings (`default` = our Touch Plus config, `onboard` = same or minimal). Our driver
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
   MONOTONIC seconds, same clock XRService uses), accel m/s² @0x14, gyro rad/s @0x20}`. Timestamp
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
- *IMU:* 240 Hz, per-sample 0x30 block `{u32 deviceId, double t_sec(CLOCK_MONOTONIC), f32×3 accel,
  f32×3 gyro}`, timestamps on XRService's monotonic-seconds clock.
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

- **IVRBlockQueue vtable ordinals** (step 1/6 above) — reconstructed from driver_cv call sites;
  confirm acquire/submit/wait/release/create/connect ordinals against the live `libopenvr_api.so`
  before writing blocks, and confirm `_005` is the loaded version.
- **Exact event-block field layout** beyond deviceId/type + the two JSON strings (the
  `/controllerConfigData/*` property writes suggest a small structured header before the strings).
- **Pose block (0x90) exact field offsets/units** — position, quaternion, velocities, validity,
  timestamp; map precisely by capturing a live pose block or finishing `FUN_001d4760`/`FUN_001d9e60`
  analysis.
- **deviceId collision/room** — whether XRService caps concurrent controllers (`Too many
  controllers to record, max is 4` is a recorder cap, not necessarily a tracker cap) and whether an
  out-of-range id is accepted.
- **Exposure interaction** — whether continuous-on LEDs survive XRService's auto-exposure for
  controller frames, or whether we must pin a manual exposure/gain (the settings exist:
  `setControllerTrackingFrameExposureTimeInMsAndGain`, `ActiveExposureController`).
- **Whether driver_cv must be present at all** — i.e. can our driver `Create` the queues when no Roy
  controller has ever connected, and will XRService's `DeckardCaptureSource` connect to queues it
  did not create. (XRService connects lazily on controller events, so likely yes; verify.)
