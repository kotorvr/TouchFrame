# FRAME-TIMING (RE-3c): the Frame's controller-camera exposure schedule, and how we could tap it

Session RE-3c, 2026-10-04. Static analysis only, of the `artifacts/frame` copies (XRService,
`libArcturusPerception.so`, `driver_cv.so`, their strings/syms and the decomp dumps, plus the
2026-10-02/03 logs). No device access (the Frame is in use by another project). DEV-1 confirmed the
on-device binaries are byte-identical to these copies. Scope is the single question the planner left
open: **how does driver_cv learn the controller-frame exposure schedule, and can driver_touchframe
get the same thing?** Nothing here modifies Valve's files, bypasses any check, or leaves the
vrserver process our driver already runs in.

Tags: **CONFIRMED** = read directly in code/data/log. **INFERRED** = strongly implied, not seen
running. **UNKNOWN** = open.

**Addresses.** driver_cv and libArcturusPerception are both analysed at Ghidra image base
`0x100000` (so a `FUN_001…`/`0x1…` address = file vaddr + `0x100000`; data constants below were read
at file vaddr = Ghidra addr − `0x100000`). XRService is non-PIE: rodata vaddr = file offset +
`0x200000` (as in [FRAME-MODEL.md](FRAME-MODEL.md)). `.strings` columns are file offsets.

---

## 0. Answers first

| Q | Answer | Tag |
|---|---|---|
| How does driver_cv learn the schedule? | XRService (its perception lib) computes each **controller camera frame's exposure window** `(start, end)` as it completes the frame, and pushes the two timestamps to its OpenVR client (driver_cv) over the private **XRIPC** shared-memory call `callClient_AddFutureControllerCameraExposureTimings(double start, double end, u32, bool)` (libArc `0x1b33d0`, client function id **20**). driver_cv's `onAddFutureControllerCameraExposureTimings` (`FUN_001d1b90`) receives the two doubles. | CONFIRMED (chain); callback↔AddFuture binding INFERRED |
| Units / clock of start, end | **seconds**, on the **same monotonic timebase as the IMU and pose blocks** = `CLOCK_MONOTONIC_RAW` (`ST::getTimestampNow`). driver_cv subtracts them against its own `now` built from the identical tick→seconds globals it uses for IMU/pose. | units CONFIRMED; clock = MONOTONIC_RAW CONFIRMED live (FRAME-TRACKER §9), camera-frame = same clock INFERRED |
| What is `end − start`? | the **exposure duration** (mode 4 → 0.010 ms = 10 µs). XRService builds `end = t_frame + rolling_offset`, `start = end − 0.001·exposure_ms`. | CONFIRMED (`FUN_00f67790`) |
| What is the spacing of successive `start`s? | the **controller-frame period**, ~**33.333 ms** (30 Hz controller frames in a 60 FPS stream). driver_cv infers it as Δ`start`; first-frame default is `0.03333333333333333 s`. | CONFIRMED (driver default + period math); 33.33 ms = FRAME-MODEL §3 |
| How far ahead is it announced? | **Not ahead.** The window is the frame that *just completed*; it reaches driver_cv slightly in the past. The driver extrapolates forward by whole periods and arms a **free-running** strobe on the controller (`count ≈ 2 s`), re-phased on each report. Actual age/lead is not derivable statically. | mechanism CONFIRMED; lead time UNKNOWN (measure T3/HW) |
| What changes the schedule? | **period** ← camera FPS / streaming mode (60 FPS → 33.33 ms; SLAM-only would be different); **exposure length** ← `streamingMode` (mode 4 = 10 µs; modes 2/3 = 250/750 µs; FRAME-MODEL §3.1); **phase** ← the camera's own frame clock; WifiSync modes re-source the clock. | CONFIRMED mapping (FRAME-MODEL §3) |
| Can driver_touchframe get the same schedule? | **(a) No public OpenVR interface carries it.** It travels on XRService's private XRIPC, not on any block queue, property or event. **(b)** XRService *logs* individual controller-frame timestamps (the current seed). **(c)** Our driver, in vrserver, could **read-only-snoop the XRIPC `XR_ServerRequest_*` ring** and decode function 20 for the exact `(start,end)`. Recommended: keep the closed loop + log seed as the robust base, add the snoop as an optional *fast-lock* source behind validation, never hooking or consuming. | see §4–§5 |

---

## 1. The call path (CONFIRMED unless noted)

```
XRService / libArcturusPerception (owns cameras)
  PE::DeckardCaptureSource::onTrackingCameraFrameComplete      FUN_00f67790 @ 0xf67790 (XRService)
    end   = t_frame(+0x728) + rolling_shutter_offset/1000      // seconds
    start = end + (-0.001)*exposure_ms(float +0x740)           // = end - exposure_seconds
    if (this[0xe]) (*this[0xf])(this+0xc, &start, &end);        // 2-double client callback
        │  INFERRED: this[0xf] is bound to ↓ (only 2-double exposure callback; data shapes match)
        ▼
  PE::XRIPCServer::callClient_AddFutureControllerCameraExposureTimings(d start, d end, u32, bool)
                                                                libArc 0x1b33d0  (fn id 20, 16-byte payload)
        │  XRIPC shared-memory ring  (XR_ServerRequest_{Low,VLow} → XR_ClientResponse_*)
        ▼
driver_cv.so  (in vrserver, the OpenVR client)
  PE::XRIPCClient::That::processClientFunction(id=20, buf, len)  libArc 0x1a8590  (unpacks 2 doubles)
        ▼
  onAddFutureControllerCameraExposureTimings                    FUN_001d1b90 @ 0x1d1b90
        → FUN_001d1af8 → FUN_001f54c8(start, end, ctrl+0x18)    FUN_001f54c8 @ 0x1f54c8
             records start@+0x288, (end-start)@+0x290, period@+0x298; logs "… exposure first/update"
        → FUN_001f4b78(ctrl+0x18)                               FUN_001f4b78 @ 0x1f4b78
             extrapolate + convert to dongle clock → radio cmd 0x64 (14-byte LED-timing buf)
```

- **The server marshaller is confirmed by disassembly** (`llvm-objdump` of libArc `0x1b33d0`): it
  `stp d0, d1, [sp,#8]` and calls `XRIPCServer::callClient(id=0x14=20, buf=sp+8, size=0x10=16, …)`.
  So the payload the client receives is exactly **two little-endian doubles** `start, end`; the
  `u32`/`bool` from the C++ signature are `callClient` routing flags, **not** data for the driver
  (confirmed: `w3=16` byte size covers only the two doubles). CONFIRMED.
- `[AddFutureControllerCameraExposureTimings] Client failed to fetch the call from the shared memory
  buffer` (XRService.strings `0x9f2631`) confirms the transport is a shared-memory ring, and that
  the *client* (driver_cv) pulls the call. CONFIRMED.
- The callback↔AddFuture binding is **INFERRED**: `callClient_AddFuture` has no direct `bl` caller in
  libArc (it is reached through a function pointer / dispatch slot), and `onTrackingCameraFrameComplete`
  invokes `this[0xf](this+0xc,&start,&end)` indirectly. It is the only 2-double exposure callback in
  the capture source, and its `(start = end − 0.001·exposure_ms, end = t_frame + offset)` shape is
  exactly what driver_cv's `FUN_001f54c8` consumes (end>start, end−start = exposure). No *predictive*
  (look-ahead) caller was found; "Future" names what the **driver** does with the value (schedule a
  future pulse), not a prediction by XRService.

### 1.1 The XRService side that computes the window (CONFIRMED, `FUN_00f67790`)
`onTrackingCameraFrameComplete`, after the camera-sync and ISP-metadata guards:
```
dVar17 = *(float*)(frame+0x740);                       // controller-frame exposure, ms
if (dVar17 < 0.001) warn "Controller frame exposure time is less than 1us…";   // 0xada698 = 0.001
dStack_1b8 = rolling_offset/1000.0 + *(double*)(frame+0x728);   // END   (t_frame + offset, s)
dStack_4d0 = dStack_1b8 + (-0.001)*dVar17;                      // START (END − exposure_s); 0xadac80 = -0.001
if (this[0xe]) (*this[0xf])(this+0xc, &dStack_4d0, &dStack_1b8);// callback(this, &START, &END)
```
- `frame+0x728` is the camera frame timestamp (same field the function diffs camera-0 vs camera-1
  against the **3 ms** out-of-sync threshold `0xad97c0 = 0.003`). CONFIRMED.
- Constants read from XRService rodata: `0xadac80 = −0.001`, `0xada698 = 0.001` (= 1 µs),
  `0xad97c0 = 0.003` (= 3 ms). CONFIRMED.
- So **`end − start` is the mode's exposure length** (10 µs on mode 4), and **`end` is the frame
  timestamp plus the rolling-shutter offset**, both in seconds. CONFIRMED.

### 1.2 The driver side that records it (CONFIRMED, `FUN_001f54c8`)
Per-controller state object at `CCvControllerDriver+0x18`:
- `+0x288` = last `start`. New `start == +0x288` → logs `P%d: exposure repeat`; `start < +0x288` →
  `exposure backwards` and resets; else period `= start − +0x288`.
- `+0x290` = `end − start` (exposure length). `+0x298` = period (default `0.03333…` on the first
  frame, when it also logs `%s - First LED frame scheduled` and `P%d: exposure first`).
- Then `FUN_001f4b78`. These are the only writers of `+0x288/+0x290/+0x298`. CONFIRMED.
- The `exposure first/update/repeat/backwards` lines come from `FUN_00201860`, a **verbose** logger;
  they do **not** appear at the captured log level (only the plain `First LED frame scheduled` from
  `FUN_002d9b00` does). So the raw `(start,end)` numbers are not in any captured log. CONFIRMED.

### 1.3 How the driver turns it into a strobe (CONFIRMED, `FUN_001f4b78`)
- `now` = `FUN_0035eb20()` ticks × `PTR_DAT_005a1c78` scale, offset `PTR_DAT_005a1950` — the **same
  two globals** `FUN_001d46c0` uses to timestamp IMU blocks, so exposure/IMU/pose/`now` are one
  clock. CONFIRMED.
- Re-send is rate-limited to once per `0xada… 0x4a8f98 = 0.01 s` (10 ms), i.e. it can re-phase up to
  **100 Hz** (in practice once per 30 Hz report). CONFIRMED. This satisfies MASTER-PLAN's
  "re-phase continuously".
- Predicts the current cycle's start: `aligned = last + floor((now − last)/period)·period`, pulse
  centre `= aligned + ontime/2`, with small `±2 µs`/`4 µs` guard terms
  (`0x4b4058=−2e-6`, `0x4b4060=2e-6`, `0x4b4050=4e-6`). CONFIRMED.
- Converts to the dongle's 16 MHz "translator" clock via `FUN_001f9b98` (the timesync fit) and emits
  radio **cmd `0x64`**, 14-byte buffer
  `{ u32 delay = pulse_centre×16e6, i32 period_ns, i32 ontime_ns, u16 count = (int)(2/period)+1 }`
  through `FUN_001fafd8(dongle, dongle2, 0x64, 0xe, &buf)`. CONFIRMED.
  - `count ≈ 61` at 30 Hz ⇒ the controller free-runs ~**2 s** of pulses per message (matches
    PERIPHERALS §2.3: the firmware re-arms at `period` autonomously; cmd 0x28 `d` is the pulse
    centre). The driver must refresh before the count expires; the 10 ms re-send floor guarantees it.
  - **Correction for the planner:** FRAME-TRACKER §3 says the LED-timing buffer is sent with command
    `0x66`; the decomp shows **`0x64`** for LED timing (`FUN_001f4b78`). `0x66` is the separate **LED
    brightness** command (`FUN_001f5660`, `FUN_001fafd8(…,0x66,2,…)`).

---

## 2. The data, summarised

| Quantity | Value / meaning | Source | Tag |
|---|---|---|---|
| `start`, `end` | two doubles, **seconds**, exposure window of one controller camera frame | XRIPC fn 20 payload | CONFIRMED |
| clock | `CLOCK_MONOTONIC_RAW` (`clock_gettime(4)`), shared with IMU + pose blocks | FRAME-TRACKER §2/§9; driver uses identical tick globals | CONFIRMED live; camera-frame = same clock INFERRED |
| `end − start` | exposure duration = **10 µs** (mode 4); 250/750 µs on modes 2/3 | `FUN_00f67790` + FRAME-MODEL §3.1 | CONFIRMED |
| period (Δ`start`) | **~33.333 ms** (30 Hz controller frames, 60 FPS cameras); default `0.03333…` | driver + FRAME-MODEL §3 | CONFIRMED |
| `end` composition | `t_frame(+0x728) + rolling_shutter_offset` | `FUN_00f67790` | CONFIRMED |
| look-ahead | ≈0 (the just-completed frame); driver free-runs + re-phases | §1, §1.3 | mechanism CONFIRMED; magnitude UNKNOWN |
| cadence | one call per controller frame (~30 Hz) | §1.1 (per frame-complete) | INFERRED |
| changes it | FPS/streaming mode (period), `streamingMode` (exposure), camera clock (phase), WifiSync (clock source) | FRAME-MODEL §3 | CONFIRMED mapping |

This is **exactly** the triple the strobe scheduler needs: period `p`, on-time window, and the
phase `d` (pulse centre) on a clock we can relate to the dongle.

---

## 3. Is there a documented/public path that already carries it? (option a)

**No.** Searched the OpenVR interfaces our driver and driver_cv use, plus properties/events:

- **Block queues** (`IVRBlockQueue_005`) carry only `/xrservice/controller/{event,data}` (connect +
  config + IMU) and `/xrservice/controller_<id>/pose` (poses). None carries exposure timings. The
  pose block's timestamp is the **IMU-sample** time (240 Hz), not the 30 Hz controller-frame time, so
  it does **not** expose the schedule. CONFIRMED (FRAME-TRACKER §8).
- The exposure schedule is a **server→client XRIPC call**, a private `PE::XRIPC*` protocol over
  `/run/user/1000/xrservice-ipc` + `/dev/shm` rings, **not** OpenVR. It is not a property, not an
  event, not a block queue. CONFIRMED.
- `Prop_CameraExposureTime_Float` exists in vrserver's property enum, but that is an **HMD
  tracked-camera** property, a single scalar, not a per-controller-frame future schedule, and not on
  the controller tracker path. INFERRED not useful; UNKNOWN whether it is even populated on the
  Frame. Not a route.
- A second XRIPC client session is explicitly **rejected** by XRService
  (`isThereASessionRunningInAnotherProcess`, single-session), so we cannot *ask* XRService for the
  schedule over XRIPC either. CONFIRMED (FRAME-TRACKER §4).

So there is nothing to subscribe to. The schedule must be either **observed** (b/c) or
**reconstructed** from feedback (the current loop).

---

## 4. Ways driver_touchframe could obtain the schedule, ranked

### (b) Data XRService already publishes/logs — the current seed. **Robust, coarse.**
- XRService logs individual controller-frame timestamps:
  `[ControllerTracking N]: Trying to track first LED frame with timestamp: %f` (one at bootstrap) and
  `Not having enough IMU data for controller frame … Current timestamp: %f` (one **per controller
  frame** while our IMU feed lags). CONFIRMED (FRAME-MODEL §4; DEV-1 saw both).
- This is what BUILD-2's loop already seeds from (`radio_xrservice_logs`, `led_phase.h`).
- Pros: public text, survives SteamVR updates, no process poking. Cons: the useful per-frame line
  only streams under an induced IMU-starvation condition (test T3), it is one timestamp (phase) with
  the **period** inferred from spacing, and it says nothing about which point of the exposure the
  stamp marks (T3 open question). Good for **seeding/holding**, not for instant lock on a mode
  change.

### (c) Observe it inside vrserver. Two sub-options, very different risk.
Our driver is a legitimate OpenVR driver in the **same vrserver process** as driver_cv, which is
where the XRIPC *client* lives and where the rings are mapped.

- **(c1) Read-only snoop of the XRIPC ring. RECOMMENDED as the direct source.**
  The server→client calls ride named shared-memory rings `XR_ServerRequest_Low` / `XR_ServerRequest_VLow`
  (with `XR_ClientResponse_*` and `XR_FunctionCall_Lock_*`), all CONFIRMED strings in libArc. Our
  driver can `shm_open`/`mmap` the request ring **`O_RDONLY`**, follow the producer cursor, and
  decode frames whose `XRIPCFunctionId == 20` into the two doubles — the exact `(start,end)`
  driver_cv gets.
  - Mechanism: open the ring read-only; on each poll read the header's write index; for each new
    record whose id is 20, copy the 16-byte payload; **never** take `XR_FunctionCall_Lock_*`, never
    advance any cursor, never write. driver_cv remains the sole consumer.
  - Fail-safe: treat every decoded value as a *hint*, validated before use (`end>start`,
    `end−start ∈ [1,1000] µs`, `Δstart ∈ [25,45] ms`, timestamps within a few seconds of our `now`).
    Any failure → silently fall back to (b)+loop. Guard the whole reader behind a setting
    (`radio_led_xripc_snoop`, default off) and a one-shot "layout looks sane" check at open.
  - Robustness to SteamVR updates: **medium**. The ring *names* and the function id are stable
    across the openvr versions we checked, but the ring record framing is private `PE` ABI and could
    change; the validation above makes a format change degrade to "no hint", not a fault.
  - Risks and mitigations: (i) *torn reads* without the lock — mitigated by re-reading the record and
    requiring two identical decodes, plus the value validation; a torn read that passes validation is
    at worst one bad phase sample the loop rejects. (ii) *stealing/!blocking the real client* —
    avoided by read-only mapping and never touching locks or cursors (the single hard rule). (iii)
    *crashing vrserver* — the only shared state we touch is a read-only mapping; bound every access to
    the mapped length and never dereference ring-supplied offsets without range-checking them against
    the mapping. (iv) *interfering with Frame controllers* — none: we don't write, and the schedule we
    read is the same one the Frame controller already follows.
  - This makes lock **immediate** and **automatically correct on a camera-mode change**, because we
    read the new `(start,end)` the instant XRService emits it — which is the whole point of the
    request.

- **(c2) Hook driver_cv's `onAddFutureControllerCameraExposureTimings` (or the dispatch slot).
  NOT recommended.** It would give the cleanest data (the decoded doubles, in-process), but it
  requires patching another driver's function pointer or code in memory. That is exactly the kind of
  integrity/anti-tamper-adjacent move this session is told to avoid, it can crash vrserver or corrupt
  Frame-controller strobing if driver_cv's layout shifts by one build, and it is far more fragile
  across updates than (c1). Rejected.

---

## 5. Recommendation

1. **Keep the closed loop as the backbone** (BUILD-2 `led_phase.h`): it needs no private ABI and is
   the only thing that works if the ring format ever changes. It already seeds from (b).
2. **Strengthen the (b) seed**: parse both `Trying to track first LED frame` and the per-frame
   `Not having enough IMU data … Current timestamp` lines for phase, and derive the period from their
   spacing; this is the update RE-3b's test T3 validates.
3. **Add the (c1) read-only XRIPC snoop as an optional fast-lock source**, default **off**, behind
   value-validation and a fallback to the loop. When it is on and sane, feed its `(start, end)`
   straight into the same phase/period state the loop maintains (set `d` = pulse centre at
   `start + (end−start)/2` on our dongle clock, `p` = Δ`start`), so a camera-mode change re-locks in
   one frame instead of a probe sweep.
4. **Do not** hook driver_cv (c2), open a second XRIPC session, or touch any lock/cursor.

This is strictly additive: no driver code is changed in this session (design only), and the snoop,
if later built, is a read-only observer that cannot alter what XRService or the Frame controllers do.

---

## 6. On-device test plan (planner; needs `frame.lock`; no dongle needed for T-A/T-B/T-C)

Compares a tapped schedule against the current log-seeded loop. Back up and restore
`~/.config/openvr/config/cv/xrservice/XRServiceSettings.json` and `steamvr.vrsettings` around each
run (the Frame is shared with Echo; these also drive Frame controllers).

- **T-A. Confirm the clock and the window numbers (read-only).** With a cloned/real Frame controller
  tracking (FRAME-TRACKER §9 setup), raise driver_cv's log level if possible to capture `P%d:
  exposure first/update` lines, **or** run the (c1) snoop in a logging-only build. Record
  `(start,end)` for ~5 min. Expect `end−start ≈ 10 µs`, `Δstart ≈ 33.333 ms`, and `start`/`end` within
  a few ms of a `clock_gettime(CLOCK_MONOTONIC_RAW)` read taken alongside. Confirms units + clock.
- **T-B. Snoop vs log seed.** Run (c1) and the (b) log parser simultaneously, logging both phase
  estimates. Expect them to agree to within the rolling-shutter offset. Measures the snoop's accuracy
  and how much sooner it locks after `streamingMode`/FPS changes (toggle a retroreflector mode via
  T6 to force a change and time re-lock for each source).
- **T-C. Robustness/fail-safe.** Deliberately feed the snoop a wrong ring name / corrupt the header
  in a test and verify it degrades to the loop with no fault, and that driver_cv keeps tracking
  (confirm no change in `[ContrLedsStats]` cadence for a real Frame controller while the snoop runs).
- **T-D. (HW-3, dongle) End-to-end.** With the dongle driving Touch Plus LEDs, seed `d` from the
  snoop (or T-B's winner) and compare lock time and hold against the pure closed-loop sweep (T4 in
  FRAME-MODEL §6). Success = immediate lock and sustained `[ContrLedsStats]` hits, better than the
  blind P/16 search.

---

## 7. Corrections / open items for the planner

- **FRAME-TRACKER §3**: the LED-timing radio command is **`0x64`** (`FUN_001f4b78`), not `0x66`.
  `0x66` is LED brightness (`FUN_001f5660`). The 14-byte buffer and field order it lists are correct.
- **FRAME-TRACKER §3 / MASTER-PLAN §6 (G-LED)**: the exposure schedule XRService pushes to driver_cv
  is the **just-completed** controller frame's window, not a look-ahead; the strobe is a free-running
  PLL the driver re-phases every frame (≤10 ms re-send floor). Record this where §3 describes the
  schedule as "pushed … future".
- **Open (UNKNOWN):** the exact age/lead of `end` relative to driver processing (T-A); which point of
  the exposure XRService's logged controller-frame `timestamp` marks vs this `end` (shared with
  FRAME-MODEL T3); and the precise XRIPC ring record framing (needed only to *build* c1, not to
  decide it — decoding it is a small follow-up if the snoop is approved).
- No change to `driver/` in this session (design only).

---

## Reproduce
```
# server marshaller: confirms fn id 20 and the 16-byte (2 doubles) payload
llvm-objdump -d --start-address=0x1b33d0 --stop-address=0x1b3418 artifacts/frame/libArcturusPerception.so

# XRService exposure-window math (annotated decomp)
sed -n '27979,28210p' artifacts/frame/xr_decomp_ann.c         # FUN_00f67790, lines ~28175-28184
# constants (XRService rodata, file off = vaddr - 0x200000): -0.001, 0.001, 0.003
python - <<'PY'
import struct; d=open("artifacts/frame/XRService","rb").read()
for v in (0xadac80,0xada698,0xad97c0): print(hex(v),struct.unpack_from("<d",d,v-0x200000)[0])
PY

# driver_cv handler + scheduler
sed -n '559,609p'  artifacts/frame/dcv_decomp3.c              # FUN_001f54c8 (records start/exp/period)
sed -n '671,820p'  artifacts/frame/dcv_decomp3.c              # FUN_001f4b78 (-> radio cmd 0x64)
# driver_cv constants (file off via PT_LOAD; Ghidra base 0x100000): 0.01, 4e-6, -2e-6, 2e-6
#   DAT_004a8f98 (re-send floor 10 ms), DAT_004b4050/58/60 (guard terms)

# XRIPC ring + lock names, and the fetch-failure string
grep -nE "XR_ServerRequest_|XR_ClientResponse_|XR_FunctionCall_Lock_|/xrservice-ipc" artifacts/frame/libArcturusPerception.so.strings
grep -n "Client failed to fetch the call from the shared memory buffer" artifacts/frame/XRService.strings
```
