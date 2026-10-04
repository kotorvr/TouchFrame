# TouchFrame master plan

Written 2026-10-04 by the planning session, from a pass over the docs **and** the code. This is the
file every work session starts from. The other docs are evidence and runbooks:
[FEASIBILITY.md](FEASIBILITY.md) (findings + log), [PROTOCOL.md](PROTOCOL.md) (radio RE),
[FRAME-TRACKER.md](FRAME-TRACKER.md) (camera-tracker RE + injection), [HARDWARE-DAY.md](HARDWARE-DAY.md)
(dongle runbook), [INSTALL.md](INSTALL.md) (relay install).

## 1. Goal and "done"

Touch Plus controllers on a standalone Steam Frame, like first-party controllers, with **no Quest and
no PC in the loop**:

```
Touch Plus ──Pulsar radio──> nRF52840 dongle (host mode, on the Frame's USB)
        ──USB CDC──> driver_touchframe (vrserver) ──block queues──> XRService (Frame cameras, LED PnP)
        <── 6DoF pose ──                           ──> SteamVR games as oculus_touch
```

Done means:
1. A Touch Plus pairs to the dongle with a Frame-side command (no Quest).
2. All inputs, battery and haptics work over the dongle.
3. XRService tracks each Touch Plus in 6DoF from its LEDs, using our IMU feed, **with both Frame
   controllers off or absent**.
4. It starts with SteamVR, survives sleep and reconnects, and installs with one command.

**Fallback if Gate B fails** (the Frame cameras can't track Touch Plus LEDs): 3DoF from the radio IMU,
plus position from Frame hand tracking or the relay. Plan B is in §6.

## 2. Where we are (checked against the code, 2026-10-04)

| Piece | State | Evidence |
|---|---|---|
| SteamVR driver, bindings, render models, skeleton, haptics | **Done** (relay) | `driver/src/driver.cpp`, verified on the Frame |
| Relay (Quest bridge, watchdog, install, calibration) | **Done** | INSTALL.md, 7.6 mm calibration RMS |
| Camera-tracker injection (block queues) | **Proven with a cloned Frame controller** | FRAME-TRACKER §9: 2.3 mm / 0.64° |
| `CvTouchSource` (camera poses + external feed) | Written, **not wired into the Provider**, no feed | `driver/src/cv_source.*`; the Provider only builds `UdpSource` |
| Radio RE: PHY, addresses, hop, beacon, timing, pairing, CCM structure, version, input sample | **Static RE done** | PROTOCOL.md Q1–Q6 |
| Radio RE: what the host *says* on the connected link | **Not done** (see §3.1) | PROTOCOL.md has no connection-negotiation, CL/TL or register-access layouts |
| Dongle firmware | Sniffer on main. **BUILD-1 in progress:** link v3, crypto, host core, fake controller and a C loopback simulator (branch `claude/exciting-bun-66e32e`). **Transport must become USB HID** (the Frame has no CDC ACM) | BUILD-1 report, DEV-1 |
| Offline host tools | Pairing packets, CCM decode, input decode | `tools/pulsar_{host,crypto,input}.py`, all selftests green |
| Gate B (do Frame cameras see Touch Plus LEDs?) | **Open.** Relay run: 0 hits in 4.5 min (expected: the Quest strobes 19 µs at 15 Hz). XRService logs ~300 "Couldn't find any neighbor" errors/s with the 8-LED model, which is a new risk. LEDs are strobe-only (RE-2), so the real test needs the dongle plus exposure sync | [re/DEV-1.md](re/DEV-1.md), [re/PERIPHERALS.md](re/PERIPHERALS.md) |
| Touch-only operation (no Frame controller ever connected) | **YES, CONFIRMED on device.** Our driver can Create the shared queues and XRService tracks the injected device. Cost: the first Frame controller of that SteamVR session then gets no pose. driver_cv's queues also survive its last controller disconnecting | [re/DEV-1.md](re/DEV-1.md) |

## 3. What's left, and what this pass found

### 3.1 Static RE still to do (none of it needs hardware)
The earlier "all statically RE-able items done" covered the six PROTOCOL open items. A host also
has to *talk* to the controller after pairing, and none of that is documented yet:

1. **Connected-link bring-up.** The controller seeks, the host answers, a slot is assigned and the
   link locks. That needs the connection-negotiation packet layouts in both directions, the endpoints
   (CONN_NEG=2, lock=3 are known from the accept handler), and what the host must put in beacons
   byte 14 and the CL data area.
2. **CL/TL framing and register access.** How the host reads and writes the controller's
   host-registers (hreg), and how it subscribes to streams (input, IMU) or receives notifications
   (`ntf_reg_irled_config_t` hints at a notify path). PROTOCOL Q4 lists *which* registers hold
   the data, but not *how to ask for them*.
3. ~~**Steady-state CCM nonce.**~~ **Mostly settled by AUDIT-1 (A2–A4):** CCM is **uplink only**, so the host never produces MICs; it only decrypts. The steady IV comes from the controller's connection request, with a per-slot counter. Left for RE-1: the IV's origin and the counter increment. Original text: A host must *produce* valid MICs, not just check them, so the
   per-packet counter/IV/direction packing must be pinned (elk-app's per-packet CCM writes).
4. ~~**Possible conflation to resolve.**~~ **RESOLVED by AUDIT-1 A1:** `FUN_00047604` is only the pairing wrap. Original text: `syncboss FUN_00047604` encrypts a 20-byte blob to 24 bytes
   with a random IV. That is exactly the `PairingData` 0x11 layout ([4-byte addr][16-byte key]).
   PROTOCOL Q2 says so, but Q3 and HARDWARE-DAY §5 call it the *connected-link* "connection
   negotiation" and tell you to grab the IV from the connected link. elk-app's "Must use legacy
   nonce for connection negotiation" is in the *connected* app, not the pairing SPL. These may be
   two different things. Until RE settles it, a sniffed Quest session's IV may only be on air
   during a **re-pair**.
5. **LED control: the riskiest unknown on the 6DoF path.** FRAME-TRACKER §3 plans to hold the LEDs
   "continuously on", but the controller validates its IR LED config (`"IR LED configuration
   rejected: p=%lu, ot=%lu, d=%li"`). If on-time or duty cycle is capped (eye safety or thermal),
   always-on is impossible and we must **strobe in sync with the Frame's controller-frame
   exposures**. That needs the exposure schedule (RE-3). We need the command layout and the
   validation limits.
6. **IMU.** The ICM-42686 full-scale range and output rate (from elk-app's IMU register writes),
   the reg 0x0b/0x16 layout, timestamps, and how to read the per-unit calibration over the radio.
   XRService needs 240 Hz in m/s² and rad/s on CLOCK_MONOTONIC_RAW (FRAME-TRACKER §9.1).
7. **The input map is RE-able after all.** PROTOCOL said the deerfly firmware is "not in these
   dumps" and "not ARM". Both are wrong: `artifacts/quest/fw/ruby_prq/deerfly-app.bin` is there
   (69 KB, `dAeH` header, Cortex-M vector table, reset `0x10919`; the RA2E1 is a Cortex-M23). Axis
   identity, button labels, touch flags and battery scale can be read statically.
8. **Haptics command format** (simple vs PCM `send_pcm_haptics`).
9. **Pairing link details still INFERRED:** how the host opens the 2426 MHz DM link with an
   advertising controller, the SPL-frame CRC byte order, and what the controller does after 0x11
   (reboot to app?).
10. **Mostly moot (AUDIT-1 A7):** a real Quest pairs with 0x1d (per-device key = X25519 secret[:16], never on air), so even the default key wouldn't decode its sessions. Original text: the *default* AES key in `libsyncboss.so` / syncboss. If a Quest runs on the
    default, its sessions can be decrypted without root.

**Best RE source not yet mined:** `artifacts/quest/odm/lib64/libsyncboss.so` (host Android
library, aarch64, with symbol names). It builds the very commands we need (hreg reads, LED
timing, haptics, pairing info).

### 3.2 Gate B via the relay can't give a clean answer
`frame.sh gateb` relays a Touch Plus from the Quest. **The Quest strobes those LEDs for ~15–100 µs
on its own camera schedule**, not the Frame's. The LEDs are lit during a Frame controller-frame
exposure only by chance (roughly 1% of frames, in bursts when the two frame rates beat). So:
- a **positive** (`[ContrLedsStats]` for device 41, even briefly) means the Frame *can* see and
  match Touch Plus LEDs. That is worth knowing early, so run it long (10+ min) and grep for any hit;
- a **negative** proves nothing. The real Gate B needs our dongle to hold the LEDs on (or strobe
  them in sync).

HARDWARE-DAY §6 and FEASIBILITY now say this.

### 3.3 Frame-side gaps
- **Touch-only.** The shared queues exist only after a Frame controller connected (FRAME-TRACKER
  §9.1). In the target setup both Frame controllers are off (one tracking slot per hand, §9.3). We
  need either "our driver Creates the queues and XRService connects" (test on device) or a
  documented "turn a Frame controller on once per boot" workaround.
- **Re-announce** when a competing Frame controller disconnects (§9.3; CvTracker doesn't yet).
- **Exposure schedule tap** (only needed if 3.1.5 says LEDs can't stay on). XRService sends it only
  to driver_cv over XRIPC, but driver_cv runs in the *same vrserver process* as our driver. RE the
  in-process hook point (`onAddFutureControllerCameraExposureTimings`, driver_cv `FUN_001d1b90`).

### 3.4 Build work (all offline-able, none started)
- **Dongle host firmware:** TX, the 2 ms beacon scheduler, CSA#1 (already in `pulsar_hop.c`),
  inline HW CCM, uplink slot RX, the pairing state machine, and link protocol v3 (pair / connect /
  register read-write / LED / haptics / IMU+input events / time sync).
- **Driver radio backend:** a `RadioSource` reading the dongle over **hidraw** (`/dev/hidraw*`, group input, steamos already a member, no udev rule. The Frame kernel has no CDC ACM: DEV-1),
  dongle-µs → CLOCK_MONOTONIC_RAW time sync, IMU rectification (raw → SI with per-unit cal) into
  `CvTouchSource`, a Provider mode switch (relay | radio+camera | radio 3DoF), a udev rule and
  install support.
- **Loopback test rig:** a second dongle as a fake controller (or a Python controller model), so
  host mode can be exercised without guessing on the real controller.

### 3.5 Doc fixes made in this pass
- PROTOCOL: deerfly correction; the 0x47604 conflation flagged; the stale "one prefix" sniffer note
  fixed; open items 7–10 added (the §3.1 list).
- FEASIBILITY: status, verdict and phase plan updated (the LD_PRELOAD shim and Monado tracker port
  are superseded by block-queue injection); log entry for 2026-10-04.
- HARDWARE-DAY: hardware checklist, the relay-Gate-B caveat, the §5 IV caveat.
- README: layout lists every tool and doc. `frame.sh` pointed at a nonexistent `docs/GATE-B.md`;
  it now points at HARDWARE-DAY §6.
- radio-fw/README: the first-session steps point at HARDWARE-DAY.

## 4. Are we just waiting on hardware? **No.**

Three separate things gate progress, and only one is shipping:
1. **The dongle** hasn't arrived. It gates sniffing, host bring-up and the real Gate B.
2. **The Quest and Frame are on loan** to the "Echo Combat Quest port feasibility" session (still
   running 2026-10-04). That session will message us when it's done. This gates every on-device
   test, including the dongle-free ones (Touch-only queues, relay Gate B, exposure-tap check).
3. **Critical-path work that needs neither.** Even with the dongle in hand today, host mode
   couldn't work: the firmware has no transmit path, and the post-pairing protocol (§3.1 items 1–3)
   isn't documented. That is RE + firmware + driver work, and it can start now.

### Hardware checklist (order now)
- [x] nRF52840 Dongle PCA10059: ordered.
- [x] **A second PCA10059** (ordered) (~$10). One is the host, one sniffs the host's own traffic or plays a
      fake controller for loopback tests. Debugging a transmitter you can't hear is slow.
- [x] **USB-C (male) to USB-A (female) OTG adapter** (ordered). The dongle is USB-A and the Frame is USB-C.
      If the Frame has one port, get a USB-C hub with PD pass-through so it can charge while the
      dongle is in.
- [x] **USB-C hub with PD pass-through** (ordered). DEV-1 found the Frame has one USB-C port, so the dongle and charging share it.
- [ ] Optional: a USB-A extension, to get the dongle away from the headset's own 2.4 GHz radios.
- [x] **Freeze Quest updates** (done 2026-10-04; controllers on fw 207.5.0 = the OTA build, DEV-1) (or at least note the build). The Quest pushes controller firmware;
      all RE is against OTA build 52433670048800520. Check that the controllers report that build
      before hardware day.

## 5. Sessions

Rules for every session:
- **Start by reading this file**, then the docs your session names.
- **File ownership** (so parallel chats don't collide):
  - RE sessions write **only** their own `docs/re/<NAME>.md` plus the tools they own.
  - The **planner** (this chat) folds RE results into PROTOCOL.md / FRAME-TRACKER.md.
  - Build sessions own their directories and work in a worktree on a branch.
  - Sessions started from chips run in a fresh worktree and commit on its branch; the planner merges.
    `artifacts/` (and `radio-fw/third_party/`) are gitignored, so they're missing there. Junction
    them from the main checkout: `cmd /c mklink /J artifacts C:\Users\kaibo\Desktop\Echo\TouchFrame\artifacts`.
- **Device lock:** the Quest 3 and Frame are shared with the EchoQuestCombat chats (up to 4 at once).
  Before you install, launch, stop, BT-scan, pair or restart SteamVR, **atomically create**
  `C:\Users\kaibo\Desktop\Echo\.locks\quest.lock` or `frame.lock`. It holds one line:
  `<chat> <purpose> <ISO expiry>`, with the expiry at most 30 min ahead. Renew it while in use,
  delete it when done, and treat an expired lock as free. Still message other sessions before
  launches and stops. The dongles are TouchFrame-only: one session drives them at a time,
  claimed in chat.
- Static RE tags stay **CONFIRMED / INFERRED / UNKNOWN**, with addresses. No Meta/Valve bytes in the
  repo (README "Legal").
- Commit small. Run `/code-review` on build branches before merging.
- **Report to the planner, always (mandatory).** The planner chat is named **"Touchframe project
  planning and roadmap"**. Every TouchFrame session must message it with `SendMessage` (load
  it with ToolSearch `select:SendMessage`; find the name with `ListAgents`):
  1. **when it finishes**: branch name, commits, a summary, what's still open, and what the
     planner must merge or fold into the docs;
  2. **at milestones others wait on** (e.g. BUILD-1's "link v3 committed");
  3. **when it's blocked** or needs a decision.

  A chat that ends without messaging the planner isn't finished: the planner only learns about
  work it's told about. Several Echo chats share name prefixes (e.g. "RE-2: …"), so address the
  planner by its exact name.

### Who starts sessions: the planner chips them

The **planner** (the "TouchFrame planning" chat) is the dispatcher, not the audit. It gets a
notification when each chipped session ends, so it is the one place that knows what finished. It:
1. merges the finished branch, folds RE results into PROTOCOL.md / FRAME-TRACKER.md, updates this
   plan and pushes;
2. **chips the next session** when its trigger below fires;
3. tells the user, who clicks the chip to start it.

AUDIT-1 / REVIEW-RE only *review*. They report to the planner and never start sessions.
Worker sessions don't chip follow-ups. They end with a summary of what's next, and the planner
decides.

| Next session | Chipped by the planner when… | Status |
|---|---|---|
| BUILD-1 | the plan was written | **done, merged 30824ad**: host firmware (pairing, connect, uplink CCM, HID, flash store, fake controller); build clean, sim tests pass. **Stub:** the TL header for register access and notifications, so a real controller gives no input, LED or haptics until it is pinned (REVIEW-RE statically, or the HW-1 capture) |
| RE-1 | the plan was written | **done, merged**: [re/LINK.md](re/LINK.md); tools fixed per AUDIT-1 |
| AUDIT-1 | the plan was written | **done, merged 82e938e**: [re/AUDIT.md](re/AUDIT.md), folded into the docs |
| RE-3 | the plan was written | **ended, blocked**: stopped by a safety check, nothing committed. Touch-only was answered live by DEV-1. The exposure-timing hook is dropped; BUILD-2's closed-loop LED phase sweep replaces it. |
| RE-3b Frame tracker vs Touch Plus model | DEV-1's error flood ("Couldn't find any neighbor", ~300/s) | **done, merged**: [re/FRAME-MODEL.md](re/FRAME-MODEL.md); flood fixed via model_number |
| RE-2 | the plan was written | **done, merged 31f35fd**: [re/PERIPHERALS.md](re/PERIPHERALS.md) |
| BUILD-2 Driver radio backend | BUILD-1 reports link v3 committed | **running (started 2026-10-04)** (base e430b12; hidraw transport) |
| REVIEW-RE | RE-1 and RE-2 are merged | **running (started 2026-10-04)**. Scope also covers: handedness (cmd 1 `device_desc`, "Input MCU handedness"), how many hosts a controller remembers and how it reconnects (if RE-1 leaves them open), and the flash-erase stall vs `PULSAR_DEVICE_MISSED_BEACONS_BEFORE_DC` |
| DEV-1 on-device bench | the Echo session releases the Quest + Frame | **done, merged 5a0b33d**: [re/DEV-1.md](re/DEV-1.md); devices handed back to Echo |
| HW-1 Sniff & validate | the dongles arrive (the user says so) | waiting |
| HW-2 Host bring-up | HW-1 done + BUILD-1 merged + REVIEW-RE has no blockers | waiting |
| HW-3 Gate B + tracking | HW-2 passes G-Link + BUILD-2 merged | waiting |
| HW-4 Integrate & ship | HW-3 decides G-B (6DoF or Plan B) | waiting |

If the planner chat is gone, any new chat can take the role: read this section, check the Status
column and `git log`, and carry on.

### Phase N: now (no devices, no dongle). Up to 4 at once.

| Session | Type | Goal | Owns | Parallel? |
|---|---|---|---|---|
| **RE-1 Pulsar link (host side)** | RE | §3.1 items 1–4, 9, 10: connected-link negotiation, CL/TL framing, hreg read/write/subscribe, steady-state nonce, pairing-link initiation | `docs/re/LINK.md`, `tools/pulsar_host.py` | yes |
| **RE-2 Controller peripherals** | RE | §3.1 items 5–8: LED config + limits, IMU scale/rate/layout + per-unit cal read, deerfly input map, haptics | `docs/re/PERIPHERALS.md`, `tools/pulsar_input.py`, `tools/touchplus_config.py` | yes |
| **RE-3 Frame camera side** | RE | §3.3: exposure-schedule tap, Touch-only queue creation, controller-frame exposure knobs, Plan B hand-tracking source | `docs/re/FRAME.md` | yes; start it after RE-1/RE-2 if RAM is tight (each runs Ghidra) |
| **BUILD-1 Dongle host firmware** | build | §3.4 firmware + link v3 + loopback rig, from the parts already pinned (beacon, hop, CCM, pairing) | `radio-fw/`, `tools/radio.py` | yes; **commits link v3 `link.h` first** |
| **AUDIT-1 RE audit** | audit | Adversarially re-verify PROTOCOL.md CONFIRMED claims against the decomp, check the tools match the docs, list contradictions (start with §3.1.4, §3.1.7) | `docs/re/AUDIT.md` (read-only elsewhere) | yes; read-only, so it can't collide |
| **BUILD-2 Driver radio backend** | build | §3.4 driver half: RadioSource, time sync, IMU rectify, Provider modes, Touch-only fallback, re-announce, fake-dongle tests | `driver/`, `tools/install.sh` | **after BUILD-1 commits link v3** |

**How many at once:** 4 is the sweet spot: RE-1, RE-2, BUILD-1, AUDIT-1. Add RE-3 if the machine
copes with three Ghidra sessions, otherwise start it when RE-1 or RE-2 finishes. BUILD-2 starts
when link v3 lands. Five or six at once works only if you can keep up with reviewing them. The
limit is your attention and RAM, not the plan.

**Is an audit worth it now? Yes, one.** This pass found two doc-vs-binary contradictions (deerfly,
0x47604) in material marked CONFIRMED. Host mode *transmits* on these claims, and a wrong claim
costs a day of hardware debugging. AUDIT-1 runs alongside the RE chats on the committed baseline.
When RE-1/RE-2 finish, a second short pass (**REVIEW-RE**) checks their new claims before
hardware day. Build branches get `/code-review`, not a dedicated chat.

### Phase D: devices free (Quest + Frame), no dongle. One session.

| Session | Goal |
|---|---|
| **DEV-1 Frame bench** | (a) Touch-only: all Frame controllers off since boot; can our driver Create the shared queues and does XRService track an injected device? (b) Relay Gate B long run (§3.2): any `[ContrLedsStats]` hit for device 41 is a strong early yes. (c) If RE-3 found the exposure tap: log the Frame's controller-frame schedule. (d) Read the controllers' firmware version and freeze Quest updates. |

### Phase H: dongle in hand. Sequential, one hardware driver at a time.

| Session | Goal | Gate |
|---|---|---|
| **HW-1 Sniff & validate** | HARDWARE-DAY §0–5: flash, sweep, discovery, pairing capture, connected link, decode | PROTOCOL Q1 confirmed on air |
| **HW-2 Host bring-up** | Pair a Touch Plus to the dongle, connect, read inputs, set LEDs, haptics. The second dongle sniffs. | **G-Link:** controller streams input to our host |
| **HW-3 Gate B + tracking** | LEDs held on (or synced), IMU feed into CvTouchSource, XRService tracks the Touch Plus | **G-B:** 6DoF go / no-go |
| **HW-4 Integrate & ship** | Both hands, Touch-only boot, pairing command, battery, install/udev, docs, release notes | §1 "done" |

An offline **analysis** chat can run alongside HW-1/HW-2 on captured `.jsonl` files (decode,
statistics), because it never touches the hardware.

## 6. Decision gates and fallbacks

| Gate | Decided by | If it fails |
|---|---|---|
| **G-LED** can the controller hold its LEDs on? | **ANSWERED NO by RE-2 (2026-10-04)**: cmd 0x28 on-time is clamped to 75 µs, p ≤ 500 ms, p ≥ 700 µs for safety, phase `d` = pulse centre on the host (dongle) clock | **Strobe in sync is now the plan:** RE-3's exposure-schedule tap, plus dongle-µs ↔ CLOCK_MONOTONIC_RAW sync good to **±32.5 µs** (the camera exposure is 10 µs at 30 Hz, RE-3b), or a closed loop that walks `d` to maximise XRService's LED matches. XRService logs each controller-frame timestamp, which gives the phase directly, with p = the Frame controller-frame period. This is now on the critical path. |
| **G-Touch-only** can queues exist without a Frame controller? | **ANSWERED YES by DEV-1 (2026-10-04)** | Create them only if none exist. If the user later powers on a Frame controller in the same session, it gets no pose until SteamVR restarts, so document that. Alternative: power one Frame controller on once per session (its queues persist after it's switched off). |
| **G-Link** does the controller accept our host and stream? | HW-2 | Gate A says no auth. A failure means a protocol detail, so back to RE-1 with captures from the second dongle. |
| **G-B** do Frame cameras track Touch Plus LEDs? | HW-3 (DEV-1 can give an early yes) | **Plan B:** 3DoF from the radio IMU plus position from Frame hand tracking (wrist), if a driver can read it (RE-3). Otherwise keep the relay as the 6DoF product. |

## 7. Session kickoff prompts (paste into a new chat in `TouchFrame/`)

**RE-1**
> You are RE-1 (Pulsar link, host side) for TouchFrame. Read docs/MASTER-PLAN.md §3.1 and
> docs/PROTOCOL.md first. Do static RE only (no devices), on the extracted images in artifacts/
> (syncboss.bin, libsyncboss.so, elk-app/elk-spl ruby_prq) with tools/ghidra. Goal: everything a
> non-Meta host must transmit and accept after pairing: connected-link negotiation (both
> directions, slot assignment), CL/TL framing, hreg read/write/subscribe/notify, the steady-state
> CCM nonce packing, and the pairing-link initiation. Resolve whether syncboss FUN_00047604 is
> the PairingData wrap or a connected-link negotiation (MASTER-PLAN §3.1.4). Also look for the
> default AES key. Write findings with CONFIRMED/INFERRED/UNKNOWN and addresses to
> docs/re/LINK.md only. Extend tools/pulsar_host.py builders + selftests. Commit to main in small
> commits. Don't edit PROTOCOL.md (the planner merges).

**RE-2**
> You are RE-2 (controller peripherals) for TouchFrame. Read docs/MASTER-PLAN.md §3.1 and
> docs/PROTOCOL.md Q4/Q5 first. Do static RE only, on elk-app ruby_prq, deerfly-app.bin (Cortex-M23,
> dAeH header, see MASTER-PLAN §3.1.7) and libsyncboss.so. Goals, in priority order: (1) the IR
> LED config command layout and its validation limits: can the LEDs be held on continuously? max
> on-time/duty? brightness/current; (2) the IMU: ICM-42686 FSR/ODR from the register writes,
> reg 0x0b/0x16 layout, timestamps, how the host reads per-unit IMU/LED calibration; (3) the
> deerfly input map: which ADC is which axis, button bits → A/B/X/Y/menu/system/stick, touch
> flags, the battery scale; (4) the haptics command format. Write to docs/re/PERIPHERALS.md only.
> Update tools/pulsar_input.py (and touchplus_config.py if the cal format changes) with selftests.
> Don't edit PROTOCOL.md.

**RE-3**
> You are RE-3 (Frame camera side) for TouchFrame. Read docs/MASTER-PLAN.md §3.3 and
> docs/FRAME-TRACKER.md first. Do static RE only, on artifacts/frame (driver_cv.so, XRService,
> vrserver, libArcturusPerception). Goals: (1) can a driver in vrserver Create
> /xrservice/controller/{event,data} when no Frame controller has connected, and will XRService
> connect to them? What does driver_cv do to the queues when its last controller disconnects?
> (2) An in-process way for driver_touchframe to receive the controller-frame exposure schedule
> (driver_cv FUN_001d1b90 onAddFutureControllerCameraExposureTimings or any other source),
> robust to SteamVR updates. (3) Controller-frame exposure/gain/threshold settings we can set.
> (4) Plan B: can a driver read Frame hand-tracking wrist poses? Write to docs/re/FRAME.md only.
> No device access until the planner says the devices are free.

**AUDIT-1**
> You are AUDIT-1 for TouchFrame. Read docs/MASTER-PLAN.md. Adversarially verify every
> CONFIRMED claim in docs/PROTOCOL.md against the decompiled code in artifacts/work and the
> binaries: re-derive it, don't trust the prose. Start with the known contradictions in
> MASTER-PLAN §3.1.4 and §3.1.7. Also check that tools/pulsar_{host,crypto,input}.py and
> radio-fw implement what the docs claim (constants, byte orders, CRC, nonce layout). Output
> docs/re/AUDIT.md: each finding with severity (blocks host mode / wrong but harmless / wording),
> evidence and the suggested fix. Don't edit other files.

**BUILD-1**
> You are BUILD-1 (dongle host firmware) for TouchFrame. Read docs/MASTER-PLAN.md §3.4,
> radio-fw/README.md and docs/PROTOCOL.md Q1–Q3. Work in a worktree branch. First commit a link
> protocol v3 (radio-fw/src/link.h + tools/radio.py) with commands for host mode (pair, connect,
> register read/write, LED, haptics, IMU/input events with dongle-µs timestamps, time-sync ping),
> because BUILD-2 builds against it. Then implement the parts already pinned: the RADIO TX path,
> the 2000 µs beacon scheduler with the documented beacon layout, CSA#1 hop, inline HW AES-CCM,
> uplink slot RX, the DM/pairing exchange (0x12, 0x11). Leave clean stubs where RE-1 is still
> open. Add a loopback test rig: a fake-controller firmware mode for a second dongle, or a
> host-side model. No hardware yet: build clean, unit-test on the PC, fake-dongle-test radio.py.

**BUILD-2** (start once link v3 is on main)
> You are BUILD-2 (driver radio backend) for TouchFrame. Read docs/MASTER-PLAN.md §3.3–3.4,
> docs/FRAME-TRACKER.md §6/§9 and radio-fw/src/link.h (v3). Work in a worktree branch. Build a
> RadioSource that reads the dongle (/dev/ttyACM*), syncs dongle µs to CLOCK_MONOTONIC_RAW,
> rectifies the IMU into CvTouchSource (stub the scale/cal until RE-2 lands), wires CvTouchSource
> into the Provider behind a mode setting (relay | radio_camera | radio_3dof), re-announces on
> competing-controller disconnects, and falls back to Creating the shared queues for Touch-only.
> Add the udev rule + install.sh support. Test offline with a Python fake dongle and
> driver/test. No device access until the planner says the devices are free.
