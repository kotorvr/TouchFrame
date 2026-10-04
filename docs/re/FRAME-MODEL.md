# FRAME-MODEL (RE-3b): how XRService uses a controller's LED model, and its own settings

Session RE-3b, 2026-10-04. Static analysis only, of the `artifacts/frame` copies (XRService, its
strings and decomp dumps, the shipped `config/*.json`, the 2026-10-03 XRService logs). DEV-1 showed
the device files are byte-identical to these copies. No device access. Scope is limited to how
XRService consumes a controller's LED model and its own documented settings. Nothing here hooks
another driver or XRService's IPC.

Tags: **CONFIRMED** = read directly in code, data or a captured log. **INFERRED** = strongly implied,
not seen working. **UNKNOWN** = open.

**Addresses.** XRService is non-PIE. Rodata vaddr = file offset + `0x200000`; `.text` vaddr = file
offset + `0x210000`. All addresses below are vaddrs. **DEV-1 quoted the two neighbor strings by
file offset** (`0x914d1e`, `0xa0f246`, the `XRService.strings` column). Their vaddrs are
`0xb14d1e` and `0xc0f246`.

## 0. Answers first

| Q | Answer |
|---|---|
| 1. What computes "Couldn't find any neighbor"? | The **P3P-bootstrap cluster-candidate sampler** `FUN_025b1a10`, called on every bootstrap controller frame. It draws LED-neighbor pairs from **hard-coded 18-LED likelihood tables** that XRService picks from `model_number`. With an 8-LED model the 18-wide tables are indexed as if they were 8-wide, so draws fall off the end of a row. That is the error (CONFIRMED). Geometry, normals and spacing play no part. A simulation using XRService's own tables gives 4 "index" + 9 "pair" errors per call at n=8 (DEV-1: 284 : 565) and **0 at n=18**. |
| 1. Fatal? | **Not fatal by itself, but it must be fixed before Gate B** (INFERRED). Bootstrap candidates then come from Frame-controller adjacency applied to unrelated Touch Plus indices. An out-of-range LED index is **not rejected** (CONFIRMED, `0x25b2be4`), so some candidates point past the 8-LED array. On top of that, ~300 log lines/s. |
| 1. Fix | **Use a `model_number` containing `Roy` and `EV1.5`** (we use `TouchFrame_TouchPlus_<Hand>_Roy_EV1.5`). That is XRService type "EV1.5", which loads **no** tables, so the sampler uses neighbors computed from our own geometry. Valve ships 18-LED `Roy_EV1.5_*_CV` and 17-LED `Roy_K2V3_*_CV` configs that take this path. The Touch Plus model already meets the geometric rule: every LED has 7 neighbors. No extra points, normals or fields are needed. **Done in `tools/touchplus_config.py`.** |
| 2. Few-LED paths | `enableFewLedTrackingMode` is a runtime tracker-logic state (FEW_LED_TRACKING) that keys on how many LEDs are *visible*, not the model size. Default on; keep it. `estimateYawFor1LEDControllers` is part of the NN-fallback params for 1-LED controllers and doesn't apply. `ledPositionStdCm` is offline calibration only. `minControllerFeatureNNModel` is the K2V3 feature NN, used only by fallbacks that are off by default. Controller DIPr models are **per hand, not per `model_number`**. Nothing needs setting beyond the `model_number` fix. |
| 3. Exposure / gain / detection | The controller-frame exposure comes from the **camera streaming mode**. The default, **mode 4 "Controller (30Hz, 0.010ms)" = 10 µs exposure, gain 1.0** (CONFIRMED). Modes 2/3 are retroreflector modes with **0.25 / 0.75 ms**; 5/6 are manual with a default of 0.01 ms. The mode is the key `captureSessionSettings.trackingCameras.streamingMode` in XRService's own `XRServiceSettings.json`. LED detection thresholds are embedded and can't be changed, except that `cv.has_retro_reflectors` drops the per-model blob threshold from 170 to 60. With 10 µs, **a 75 µs pulse must be centred within ±32.5 µs** of the exposure (±42.5 µs for any light). |
| 4. What XRService reveals | The exposure length follows from the mode it logs at startup (`setControllerTrackingStreamingMode() streamingMode: 4`). The period follows from `Setting camera FPS: 60` with controller frames at 30 Hz (33.33 ms nominal). For phase, XRService logs controller-frame timestamps only in `Trying to track first LED frame with timestamp:` and `Not having enough IMU data for controller frame … Current timestamp:`. Test T3 uses the second one deliberately. |

## 1. "Couldn't find any neighbor"

### 1.1 Where (CONFIRMED)
- Both strings (`0xb14d1e` pair, `0xc0f246` index) are referenced only in **`FUN_025b1a10`** (size
  0x19b8): `0x25b2bf8` (index) and `0x25b2f10` (pair). `tools/ghidra/xref_scan.py` finds them.
- Callers (BL scan): `FUN_025d8c20` at `0x25d9620` and `FUN_027999b0` at `0x2799f50`.
  `FUN_025d8c20` times itself as `trackWithBootstrapOnControllerFrameTimeInMs`. It calls
  `FUN_025b1a10(model, !flag)` once per controller per bootstrap controller frame.
- `FUN_025b1a10` belongs to the same unit as the model JSON parser `FUN_025aa440`
  (`model_number`, `lighthouse_config`, `modelPoints`/`modelNormals`, `imu`, role). It is a
  **method of the controller LED model**: `this+8` is the per-LED array, 0x98 bytes per LED.

### 1.2 What it computes (CONFIRMED unless noted)
It builds **cluster candidates for P3P bootstrapping**: for each model LED `i`, a few `(j, k)` LED
pairs to try against a cluster of 3 nearby image blobs (`p3pBootstrapping.maxClosestNeighborsToAnalyzeInImage: 3`).
It has two paths.

1. **Likelihood path.** Taken when `ControllerTrackerParams.useLikelihoodToComputeClusterCandidates`
   is true (embedded default `true`, read at the top of the function) **and** the model's table
   vector `+0x1a8` is non-empty.
   - `+0x1a8` is an n×n table of row CDFs P(j | i). `+0x1c0` is an n×n×n table of CDFs
     P(k | i, j). n = the model's LED count (`(+0x10 − +8)/0x98`).
   - For each LED `i`: draw u uniform in [0.001, 1.0). The constants are `0xada698` = 0.001 and
     `0xad8c80` = 0.999, and the generator is an mt19937 (`0x9908b0df`). Then
     `j = upper_bound(row_i, u)`, and **if `j ≥ n`, log "…for index %d"**. Next
     `k = upper_bound(row_(i·n+j), u')`, and **if `k ≥ n`, log "…for pair {i, j}"**.
   - Accepted `(j, k)` are de-duplicated in a set and stored as triplets `{i, j, k}`. Each LED
     wants `A+B−2 = 3` candidates and gets up to `5·3 = 15` attempts (`A = +0x1d8 = 3`,
     `B = +0x1dc = 2`, defaults from `0xad59e0`).
   - The candidates are **re-sampled on every bootstrap frame** (`param_2 = !flag`), so the error
     repeats per frame.
   - **The out-of-range case is not handled.** At `0x25b2be4` the `j ≥ n` test only skips the log
     call. Execution continues into the pair draw with `j = n` and can store a triplet holding
     LED index n (CONFIRMED in the disassembly). INFERRED: downstream reads LED `n`, one past the
     end of the 8-entry array.
2. **Geometric path.** Taken when the table vector is empty. The candidates come from each
   LED's own neighbor list (the vector at LED `+0`). An LED seeds candidates only if that list
   holds **≥ 2 entries** (`4 < bytes`). The lists are built by `FUN_025a7680` at the end of the
   JSON parse (§1.6).

### 1.3 Where the tables come from: `model_number` → XRService "type" (CONFIRMED, `FUN_025af580`)
The parser stores `model_number` (`+0xb8`) and calls `FUN_025af580`. That function sets defaults
(normal thresholds 85°/130° at `+0x198/+0x1a0`, type 5, LED radius 0.002 m and `led_type` 2 in
the `+0x1f0` object), then classifies with case-sensitive substring tests:

| `model_number` contains | Type (`+0x190`) | Likelihood tables | Other differences |
|---|---|---|---|
| `Roy` or `Steam_Frame_Controller`, plus `K2V3` | 1 "K2V3" | none (cleared) | `led_type` 1 (vishay) |
| (`Roy` or `Steam_Frame_Controller`) plus `EV1.5` | **4 "EV1.5"** | **none (cleared)** | none, except a nominal-brightness default of 0.4 |
| (`Roy` or `Steam_Frame_Controller`) plus `EV1` | 3 "EV1" | 18×18 + 18³ from `0xa37960` / `0xa38380` | `led_type` 1 |
| `Roy` / `Steam_Frame_Controller` + `EV2`, `DV1` or nothing else | 5 default | 18×18 + 18³ from `0xa439c0` / `0xa443e0` | none |
| `ibex_ev1` (without the above) | 2 "ibex_ev1" | none | `led_type` 0 (unknown, one ERROR banner), blob thresholds 100, radius 0.004 |
| **anything else, including empty** | **5 default** | **18-LED tables** | none |

- The tables are fixed 0xa20- and 0xb640-byte blobs (= 18² and 18³ doubles). Each row is a CDF
  ending at 1.0 with a zero step on the diagonal.
- Valve's shipped configs confirm the pattern. Every model on the 18-LED type 3/5 path
  (`Steam_Frame_Controller_*`, `Roy_DV1`, `Roy_EV1`, `Roy_EV2*`) has 18 LEDs.
  `Roy_EV1.5_*_CV` (18 LEDs) and `Roy_K2V3_*_CV` (17 LEDs) have no tables.
- So **DEV-1's third run** (`TouchFrame_TouchPlus_Left`) was still type 5, which explains why
  changing the name didn't help. `model_number` *is* the cause; only the specific names matter.
- `channelMap` (present in some Roy configs) is **not read by XRService**. The string's only
  occurrence is inside an embedded sample controller JSON (vaddr `0xbe8aeb`, in its
  `lighthouse_config`), and the parser never asks for it. Only driver_cv uses it.

### 1.4 Why 8 LEDs flood and 18 don't (CONFIRMED mechanism; rates INFERRED by simulation)
With n = 8 the sampler reads row `i` as `table[8i … 8i+7]`: a slice of an 18-wide CDF row, or of
two rows. Unless the slice happens to reach 1.0, a draw above its last value returns `j = 8`.

I re-ran the loop in Python on XRService's own tables (scratch only, no table bytes committed):

| Tables | n | index errors / call | pair errors / call | accepted candidates / call |
|---|---|---|---|---|
| type 5 (Frame) | 8 | 3.95 | 8.87 | 19.2 |
| type 5 (Frame) | 18 | 0 | 0 | 54 |
| type 3 (EV1) | 8 | 6.7 | 13.9 | 18.4 |

- The 1 : 2.2 index : pair ratio matches DEV-1 (284 : 565).
- 849 errors in about 3 s of processing ≈ 22 calls/s, consistent with one call per processed
  30 Hz controller frame while bootstrapping.
- The errors appear with no Touch Plus LEDs lit because the sampler runs on the **model**, not on
  blobs (CONFIRMED).

### 1.5 Fatal or noise? (INFERRED)
- **Not a hard stop.** The error is logged, the attempt is counted, and ~19 candidates per frame
  still come out.
- **It does break the bootstrap's prior.** The candidates encode which *Frame-controller* LEDs
  tend to be seen together, applied to unrelated Touch Plus indices. Whether a real Touch Plus
  triplet is among them is luck. Some LED orderings get zero probability.
- **Some candidates contain index n** (§1.2), which is undefined behavior downstream.
- **It logs about 300 lines/s.**
- Gate B on the old config would therefore be a weak test. Fix the name first.

### 1.6 What a model needs on the geometric path (CONFIRMED, `FUN_025a7680`)
- For each LED `i`, every other LED `j` whose **normal is within 130°** (`acos(n_i·n_j) ≤ +0x1a0`
  = 2.2689 rad) is a candidate neighbor. There is **no distance radius**.
- Candidates are sorted with those **≤ 85°** (`+0x198` = 1.4835 rad) first, then by distance.
  INFERRED: a mutual-neighbor pass over each neighbor's first 5 entries then trims and orders the
  list.
- The per-LED `+0x30` flag bypasses the angle test. It is 0 for parsed models.
- The Touch Plus model (Meta's 8-LED nominal, both hands) passes easily:
  - every LED has **7** neighbors within 130° and 5–7 within 85°;
  - the largest pairwise normal angle is 101°;
  - nearest-LED distances run from 16 to 62 mm.
- So **no extra points, spacing changes, normals or fields are needed.**
- Don't pad to 18 LEDs. It would silence the error but feed Frame-controller priors and phantom
  LEDs to P3P.
- The settings route is closed. `useLikelihoodToComputeClusterCandidates` is read from the
  embedded options singleton `FUN_02693840`, which is parsed only from the embedded JSON (vaddr
  `0xc250d3`). The only code touching its storage `0x3416a50` is that getter (CONFIRMED by a data
  xref scan). INFERRED: no settings file can override it.

### 1.7 Recommendation (done in this branch)
- `model_number = "TouchFrame_TouchPlus_<Hand>_Roy_EV1.5"` gives type 4.
- `cv.led_nominal_brightness = 0.75` keeps the brightness default the old type-5 config had.
  Type 4's default would be 0.4: everlight table `0xa507c0` = {0.75, 0.4, 0.75} for types 3/4/5.
- Everything else on type 4 (radius 0.002 m, blob thresholds 170, normal thresholds, `led_type`
  everlight) equals type 5 (CONFIRMED).
- **The only intended change versus the DEV-1 runs is "no likelihood tables".**
- Not recommended:
  - `K2V3` (type 1): vishay `led_type`, and its feature-NN pairing is unclear.
  - `ibex_ev1` (type 2): unknown `led_type` with an ERROR banner, different thresholds and radius.

## 2. Few-LED and model-specific paths (Q2)

| Option (embedded default) | What it is | Applies to an 8-LED unknown model? | Our setting |
|---|---|---|---|
| `ControllerTrackerLogic.enableFewLedTrackingMode` (true) | A tracker-logic state `FEW_LED_TRACKING`, alongside `ATTACHED`, `TRACKING_GRIPNET` and `STILL_ON_DESK_LEDS_ON/OFF` (state names in `FUN_0278d650`). INFERRED: it keys on the number of LEDs currently visible, not the model size. It can be overridden at runtime through XRServiceSettings `…controllerTrackingOptions.configGlobal.ControllerTrackerLogic.enableFewLedTrackingMode` (CONFIRMED key in the whitelist reader `FUN_027824a0`). | yes, generic | leave **true** |
| `minControllerSettings.estimateYawFor1LEDControllers` (true) | One field of the NN-fallback parameter block (`NNParams{…}` printer `FUN_0261f9f0`), next to `useHandDataForFallback`, `useControllerPointNN*` and `estimateGrip`. INFERRED: for 1-LED controllers in hand-data fallback. | no | leave |
| `offlineCalibration.initParams.ledPositionStdCm` (0.03) | A prior for the **offline** controller calibration (`offlineCalibration.enable: false`). INFERRED: not used live. | no | leave |
| `featureExtractorNN` / `minControllerFeatureNNModel` | The default feature NN is the **K2V3** stereo model plus `k2v3Right.json` (`FUN_02d78fc0`). It is used by the NN fallbacks (`useControllerPointNNFor{Fallback,Bootstrap,PalmFallback,GripEstimation}`, all **false** by default) and chosen per controller as `featureNNModelIdx`. "Two controllers connected that need different FeatureNN models" is at `FUN_00ec3cb0`. How the index is picked: UNKNOWN. | fallback only | leave |
| DIPr | Controller DIPr: `DIPr.modelPathLeftController` / `…RightController` (the same v2 file) plus `DIPr3.modelPath`. That is **per hand, not per `model_number`** (CONFIRMED in the options JSON). The log line `DIPr: using per-device model …/ev1/…titan…onnx` is the **headset's** DIPr, logged at startup before any controller. | per hand | leave. FRAME-TRACKER §5's "keyed by model_number" should be dropped |
| `controllerFromImuHistory/<serial>.json` | XRService saves a live controller↔IMU calibration **per serial** (`[AppDocuments]/controllerCalibration/…`, files seen for both Frame controllers). | yes | **keep `device_serial_number` stable per hand** (the tool does: `tftouchplus_<hand>`) |

## 3. Exposure, gain and LED detection settings (Q3)

### 3.1 Controller streaming modes (CONFIRMED: `FUN_00f62650` `setControllerTrackingStreamingMode`, name table `0x316af88`)

| Mode | Dashboard name | Gain, exposure set by the mode | Camera FPS (`+0x85c`) |
|---|---|---|---|
| 0 | SLAM Only | controller frames off | 45 |
| 1 | Controller (30Hz, Auto) | not set here (auto) | 60 |
| 2 | Controller (30Hz, Retroreflector 0.25ms) | 1.0, **0.25 ms** | 60 |
| 3 | Controller (30Hz, Retroreflector 0.75ms) | 1.0, **0.75 ms** | 60 |
| **4** | **Controller (30Hz, 0.010ms)** | **1.0, 0.010 ms = 10 µs** | **60** |
| 5 | Controller (30Hz, Manual exposure) | stays as set (initialized to 1.0, 0.01 ms when NaN) | 60 |
| 6 | Controller (30Hz, Timing Sync Slave) | like 5, and starts WifiSync CLIENT | 60 |

- **The Frame runs mode 4.** XRService logs `setControllerTrackingStreamingMode() streamingMode: 4`
  at startup in every captured log, before any controller connects (CONFIRMED), and DEV-1 saw it
  with our device. FRAME-TRACKER §3's "Manual exposure" is the dashboard name of mode 5, not what
  runs.
- Exposure floats are in ms. `onTrackingCameraFrameComplete` (`FUN_00f67790`) warns `Controller
  frame exposure time is less than 1us` when the value is below 0.001 (CONFIRMED).
- INFERRED: modes 2/3 also switch the IR flood emitters on. `FUN_00cab840` passes `on` for
  `mode & ~1 == 2` on hardware-revision-gated devices.
- Controller frames: 30 Hz, interleaved in the 60 FPS camera stream (FPS CONFIRMED by code and by
  the log line `[DeckardCaptureSource] Setting camera FPS: 60`; the interleave is INFERRED from
  the mode names and 45 → 60).

### 3.2 How the mode is chosen, and what can be set
- **Key:** `captureSessionSettings.trackingCameras.streamingMode` (int). CONFIRMED path: the
  CaptureSession settings reader `FUN_00e1e2f0` builds `{"captureSessionSettings",
  "trackingCameras", "streamingMode"}` at `0xe1e330`/`0xe1e490`/`0xe1e498`. The dashboard combo
  writes the same path (`FUN_00c54ed0` @ `0xc5d234`) through `FUN_00cab840(mode, persist=1)`.
- **File:** `[AppDocuments]/XRServiceSettings.json` (`FUN_00e58220`). `[AppDocuments]` on the Frame
  is `/home/steamos/.config/openvr/config/cv/xrservice/`: an XRService log line opens
  `…/cv/xrservice/colorPassthroughCalibrationHistory.json` there (CONFIRMED). The captured copy
  holds only `xrSessionSettings.lightSourceFrequencyEstimate: 50`, so **mode 4 is the built-in
  default** (CONFIRMED by the logs).
- **Per-controller arbitration.** `FUN_00ec6c90` keeps a required mode per tracking slot
  (`app+0x580` / `app+0x58c`). It logs `Two connected controllers that require different gain and
  exposure. Try using similar controllers` when they differ. What sets a slot's requirement is
  UNKNOWN. INFERRED: `has_retro_reflectors`, given the retroreflector modes and the dashboard's
  `Force has_retro_reflectors=true` checkbox. A hand-set `streamingMode` may therefore be
  overridden once a controller connects.
- **Other CaptureSession keys** (CONFIRMED names, parsed in `FUN_00e1e2f0`):
  - `controllerFramesGainMultiplier`: a double. Exact parent path and default UNKNOWN; it sits
    after `automaticStreamingControl` in the reader.
  - `automaticStreamingControl`: a bool, effect UNKNOWN.
  - `slamFrameFPSMode` (SLAM rate only).
  - `trackingCameras.useAutoExposure` and `initialExposure` / `initialGain` (SLAM auto-exposure,
    not controller frames).
  - IR flood: `maxIrEmitterPulseWidth`, `cameraSyncedIREmitterMode`.
  - No persisted key for the **manual** controller exposure was found. Mode 5's value comes from
    the dashboard slider (`##ControllerExposureSlider` → `FUN_00cabeb0` →
    `setControllerTrackingFrameExposureTimeInMsAndGain`) (UNKNOWN whether it persists).
- **LED detection (`blobDetector`, embedded):**
  - Values: `useAdaptiveThresholdForLEDs: true`, `thresholdStep: 250`, `maxThreshold: 255`,
    `filterByInertia` (0.02), `filterByConvexity` (0.7), `maxArea: 10000`,
    `ledDiameterForAutomaticMaxArea: 0.008`, the `outdoorsParams` thresholds 250/230/70, and
    `fineLedDetectorParams`.
  - They are read through the embedded singleton (`FUN_025b4090` and others), so **no settings
    override** applies (INFERRED, §1.6).
  - The one per-controller lever is `cv.has_retro_reflectors` (CONFIRMED, `FUN_025b4090`): it
    sets the model's blob thresholds `+0x1e0/+0x1e4` from **170 to 60**, the marker radius from
    0.002 to 0.004 m, and switches to `useAdaptiveThresholdForRetroreflectors`.
- **`cv` object** (CONFIRMED, `FUN_0263af50`): `led_type`, `led_nominal_brightness` and
  `has_retro_reflectors` are read **from the `"cv"` object**. A top-level `led_type` is read only
  when there is no `"cv"`, and `led_nominal_brightness` only inside `"cv"`. Enum: 0 `unknown`,
  1 `ir_vishay`, 2 `ir_everlight`.
- **Runtime tracker options.** XRServiceSettings `xrSessionSettings.controllerTrackingOptions.configGlobal`
  can override only a whitelist (`FUN_027824a0`): `DIPr3.enable`, a few DIPr/FeatureNN fields,
  `ControllerTrackerLogic.{enableFewLedTrackingMode, enableOcclusionAttachment, enableJumpHiding,
  enableJumpHidingForLogic, releaseJumpOverSeconds, debugModeLong6DoF}` and `ImuHapticsFilter.*`.
  Neither `useLikelihoodToComputeClusterCandidates` nor any blob/exposure key is on it.

### 3.3 Would any of it help a ≤ 75 µs pulse? (INFERRED arithmetic)
- **Mode 4 (10 µs)**:
  - Full exposure inside the pulse when |pulse centre − exposure centre| ≤ (75 − 10)/2 =
    **±32.5 µs**; some light up to ±42.5 µs.
  - The LED contributes 10 µs of light per frame. MASTER-PLAN's "±37 µs" should become ±32.5 µs.
- **Modes 2/3 (250/750 µs)**:
  - The whole pulse fits for ±87.5 / ±337.5 µs, and the LED delivers its full 75 µs (7.5× mode 4).
  - Ambient light integrates 25×/75× longer, and the IR flood is probably on.
  - The slot arbitration (§3.2) may pull the mode back to 4 while any LED controller is
    connected.
  - Only worth testing if sync can't hold ±30 µs (test T5/T6).
- **Gain multiplier**: brightness only, no timing slack.
- **Drift** (this, not the window, is the real constraint):
  - `p` is an integer number of µs (cmd 0x28, PERIPHERALS §2.1). At exactly 60.000 FPS the
    controller period is 33 333.33 µs, so `p = 33333` slips 0.33 µs per frame and leaves the
    ±32.5 µs window in about 100 frames (3.3 s).
  - A 20 ppm crystal mismatch adds 0.67 µs per frame.
  - **The driver must re-phase `d` continuously** (≥ 1 Hz) from a live controller-frame phase
    estimate.
  - `p = 100000` (3 frames) removes the quantization error but lights only every third controller
    frame.

## 4. What XRService itself logs about exposure length and period (Q4)

| Log line / setting | Gives | Status |
|---|---|---|
| `setControllerTrackingStreamingMode() streamingMode: %d` (`FUN_00f62650`, at startup) | the mode, hence the exposure (§3.1) | CONFIRMED |
| `[XRService] Setting camera streaming mode for controller tracking to %d` (`FUN_00cab840`) | mode changes at runtime | CONFIRMED string |
| `[DeckardCaptureSource] Setting camera FPS: 60` | camera rate, so a 33.33 ms controller period (nominal) | CONFIRMED log; period INFERRED |
| `[ControllerTracking N]: Trying to track first LED frame with timestamp: %f` | one controller-frame timestamp per bootstrap start, µs resolution | CONFIRMED (DEV-1 run A: `13897.229567`) |
| `Not having enough IMU data for controller frame, skipping processing it. Current timestamp: %f, got state timestamp: %f` | **one line per controller frame** while our IMU feed lags | CONFIRMED string; DEV-1 saw 13 |
| `Controller frame exposure time is less than 1us…` | only a warning | CONFIRMED |
| `[WifiSync] Server controller frame end: %.6f, Server frame period: %.6f` | end and period, **only in WifiSync modes** | CONFIRMED string |
| Dashboard overlay `Controller frame exposure: %5.3fms, gain: %5.2f` | ImGui text, not a log line | CONFIRMED |
| `Dropped a frame due because cameras were %.2f ms out of sync.` | camera skew above 3 ms (`0xad97c0` = 0.003) | CONFIRMED |

Exposure window, computed but never logged (CONFIRMED, `FUN_00f67790`):
`end = t_frame(+0x728) + offset_ms/1000` and `start = end − 0.001·exposure_ms`. These go to a client
callback. INFERRED: the timestamps share CLOCK_MONOTONIC_RAW with the IMU and pose blocks
(FRAME-TRACKER §9.1). UNKNOWN: whether the logged `timestamp` is that `end`, the exposure middle,
or something else. Test T3 measures it.

## 5. Changes to `tools/touchplus_config.py` (this branch)
- **Default `model_number`**: changed from `Steam_Frame_Controller_<Hand>` to
  **`TouchFrame_TouchPlus_<Hand>_Roy_EV1.5`** (type 4, no tables). `--model-number` still overrides
  it.
- **`"cv": {"led_nominal_brightness": 0.75}`** is now added. `--led-nominal-brightness 0` leaves it
  out.
- **`--retro-reflectors`** (experiment only, test T5) adds `cv.has_retro_reflectors: true`.
- **`xrservice_model_type()`** reproduces §1.3, and **`check_config()`** reports:
  - a table type combined with an LED count other than 18;
  - any LED with fewer than 2 neighbors within 130°.
- Generation prints these warnings and the resulting type. **`--check FILE…`** runs them on any
  config: our output, a `{"default":…}` pair, or a log excerpt.
- `--selftest` covers the classifier on every shipped Valve `model_number` plus ours, the `cv`
  block, `check_config` and `--check` parsing.
- Verified: `--selftest` passes. Our new output for both hands passes `--check`. The old output
  fails it (type default, 8 LEDs). The real Frame capture and the `Roy_EV1.5` / `Roy_K2V3` bases
  pass. `driver/test` `parse_config_test` accepts the new output (8 LEDs, 1470/1451 bytes,
  `cv` kept).
- `artifacts/touchplus/` was **not** regenerated; that is the planner's call (it is shared and
  gitignored). Run `python tools/touchplus_config.py` before the next on-device run.

## 6. On-device test plan (planner; needs `frame.lock`; no dongle needed for T1–T3)
Before each run: back up `~/.config/openvr/config/steamvr.vrsettings` and
`~/.config/openvr/config/cv/xrservice/XRServiceSettings.json`, and restore both afterwards. The
Frame is shared with the Echo project, and XRServiceSettings also drives Frame controllers.

- **T1. Neighbor flood is gone** (DEV-1 run A setup: Touch-only experiment, static IMU, device 41):
  - Run the new `touchplus_left.json`, then the old one.
  - `grep -c "Couldn't find any neighbor"` in the XRService log over the same ~60 s of worn
    processing. Expect **0 vs ~300/s**.
  - Also check: `Received controller configuration … "model_number":"TouchFrame_TouchPlus_Left_Roy_EV1.5"`,
    no `led_type`/brightness ERROR banner, and `Trying to track first LED frame`.
- **T2. Settings readback** (read-only):
  - `grep "streamingMode\|Setting camera FPS\|Setting camera streaming mode"` in the XRService log.
  - `cat` `XRServiceSettings.json`.
  - Expect mode 4 and 60 FPS, which confirms 10 µs.
- **T3. Controller-frame clock from XRService's own log** (T1 setup):
  - Have `cv_clone_imu=static` pause the IMU feed for ~0.5 s every 10 s. Keep pauses short,
    because XRService resets after a "long time without IMU".
  - Each pause should produce `Not having enough IMU data for controller frame … Current timestamp: T`
    lines, one per controller frame.
  - Fit T over 10 minutes. Get the period to ppm, the phase stability, and the frame-to-frame
    spacing (expect 33.33 ms).
  - Compare with `Trying to track first LED frame` values.
  - This gives the period and phase a strobe scheduler needs, from XRService's documented log
    alone. A hardware day (HW-3) can then cross-check against the closed loop.
- **T4. (HW-3, dongle) Strobe-sync window**:
  - Set p = 33333 and ot = 75, start `d` from T3's phase, and step `d` in 20 µs increments.
  - Log `[ContrLedsStats N]` hits per step to map the visible window. Expect about 65–85 µs wide.
  - Then run with continuous `d` correction and check how long tracking holds.
- **T5. (only if T4 can't hold ±30 µs) Retroreflector flag**:
  - Generate with `--retro-reflectors`.
  - Watch for `Setting camera streaming mode for controller tracking to 2|3`, IR emitter lines and
    `[ContrLedsStats]`. This answers the §3.2 UNKNOWN (what sets a slot's mode).
  - If the mode doesn't change, the flag only lowers the blob threshold to 60.
- **T6. (last resort) `streamingMode` override**:
  - Set `captureSessionSettings.trackingCameras.streamingMode` to 2 or 3 in XRServiceSettings.json
    with SteamVR stopped.
  - Check whether it survives a controller connecting (arbitration) and whether Touch Plus blobs
    appear under the IR flood.
  - Restore the file. It changes Frame-controller tracking for everyone.

## 7. Corrections for the planner to fold in
- DEV-1 §3 and FRAME-TRACKER §9.6: the neighbor strings are at vaddr `0xb14d1e` / `0xc0f246`
  (DEV-1 quoted file offsets).
- The flood **is** caused by `model_number`, through the type classifier. Any name without `Roy`
  or `Steam_Frame_Controller` plus `EV1.5`/`K2V3` gets the 18-LED tables.
- FRAME-TRACKER §1 "Config format":
  - `led_type`, `led_nominal_brightness` and `has_retro_reflectors` live under `"cv"`.
  - `channelMap` is not read by XRService.
  - Add `model_number` → type (§1.3).
- FRAME-TRACKER §3: the controller frame runs mode 4, **10 µs**, gain 1.0, 30 Hz in a 60 FPS
  stream. "Manual exposure" is mode 5. MASTER-PLAN §6 G-LED: the window is ±32.5 µs, and re-phasing
  must be continuous (§3.3).
- FRAME-TRACKER §5: DIPr is per hand, and "per-device model" is the headset's.
  `minControllerFeatureNNModel` is the K2V3 feature NN, used only by fallbacks that are off by
  default.
- FRAME-TRACKER §6 step 3: recommend `TouchFrame_TouchPlus_<Hand>_Roy_EV1.5`, not
  `TouchFrame_Right`.

## 8. Open items
- What sets each slot's required streaming mode (`app+0x580/+0x58c`). Is it `has_retro_reflectors`? (T5)
- The JSON path and default of `controllerFramesGainMultiplier`; what `automaticStreamingControl`
  does.
- Which exposure point the logged controller-frame timestamps mark (T3, then T4).
- How `featureNNModelIdx` is chosen per controller (matters only for NN fallbacks).
- Whether P3P bootstrap actually locks onto Touch Plus blobs on the geometric path. That is Gate B
  itself (HW-3).
- Whether the real Touch Plus has more IR LEDs than the 8 in Meta's nominal model (RE-2 area).

## Reproduce
```
# string -> function (vaddrs), then decompile without analysis
python tools/ghidra/xref_scan.py artifacts/frame/XRService "Couldn't find any neighbor" \
    "useLikelihoodToComputeClusterCandidates" "setControllerTrackingStreamingMode() streamingMode"
# DecompileAt on a scratch copy of artifacts/ghidra_proj_frame (avoids project locks):
#   analyzeHeadless <copy> XRService -process XRService -noanalysis -readOnly \
#     -scriptPath tools/ghidra -postScript DecompileAt.java out.c addrs.txt
#   addrs: 0x25b1a10 0x25af580 0x25a7680 0x25aa440 0x25d8c20 0x263af50 0x25b4090
#          0xf62650 0xf67790 0xec6c90 0xcab840 0xe1e2f0 0x27824a0 0x2693840
python tools/ghidra/annotate_strings.py artifacts/frame/XRService out.c out_ann.c
# callers: scan .text (file offset = vaddr - 0x210000) for BL/B imm26 to the target
# tables: 18x18 doubles at vaddr 0xa439c0 / 0xa37960, 18^3 at 0xa443e0 / 0xa38380 (file = vaddr - 0x200000)
# mode names: pointer table at vaddr 0x316af88 (file = vaddr - 0x220000), {char*, int} pairs
python tools/touchplus_config.py --selftest
python tools/touchplus_config.py --check artifacts/touchplus/touchplus_left.json   # old output: PROBLEMS
```
