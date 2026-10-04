# REVIEW-RE: adversarial re-check of LINK.md (RE-1) and PERIPHERALS.md (RE-2)

Written 2026-10-04 by REVIEW-RE against `e1350a4` (RE-1 and RE-2 merged). Every claim below was
re-derived from the binaries, not from the reports' prose:
- `artifacts/work/elk-app-ruby_prq.bin` (base 0x14000), `elk-spl-ruby_prq.bin` (base 0x2000),
  `syncboss.bin` (base 0) and their `*.decomp.c`;
- `artifacts/quest/odm/lib64/libsyncboss.so` (AArch64), with its `.dynsym` plus the 1044
  `.gnu_debugdata` names;
- `artifacts/quest/fw/ruby_prq/deerfly-app.bin` (base 0x6800).

**Tools.**
- `tools/ghidra/{disasm,getfn,xref}.py`.
- A tolerant Thumb sweep (capstone; it steps over data words).
- An AArch64 capstone wrapper that labels symbols, strings and branch targets.

**Scope.** BUILD-1 (`radio-fw/`, branch `5e35606`, re-checked on main `167f6fa`: the same code; line numbers below are main's) was read to see which
claims the firmware already encodes. Static only: no device was touched. No Meta bytes are copied
here, only addresses, short instruction snippets and our own descriptions. Three helper passes
(register layer, peripherals, tools) were run. Every BLOCKS item and every closed open item was
then re-checked by hand in the disassembly.

**Severity scale** (same as [AUDIT.md](AUDIT.md)):
- **BLOCKS**: a host built on the current text fails.
- **HARMLESS**: wrong, but host mode still works. Side effects are noted.
- **WORDING**: a misleading label, a wrong citation, or a tag to upgrade or downgrade.

**Abbreviations.**
- `LL` = the controller's link-layer state at RAM `0x20004f38`.
- `rec` = the controller's connection record at `0x20004ec0`.
- `SPL` = elk-spl; `app` = elk-app; `sb` = libsyncboss (ELF vaddr; Ghidra shows +0x100000).

---

## Summary (BLOCKS first)

| # | Finding | Severity | Who must act |
|---|---|---|---|
| R0 | **On-air TL header pinned (planner's top ask; was INFERRED/UNKNOWN in LINK §3).** Downlink = beacon byte 16 on: `[reg][flags][payload ≤ 32]`. Uplink (after CL byte 0 = slot): `[reg][flags][data]`. flags: bits 0..3 = seq, bit 4 = **read** (1) / write (0), bit 5 = error (responses), bit 6 = notification. Notifications use reg 0 followed by the ntf chunk stream. CONFIRMED on both sides. | **closes BUILD-1's last stub** | LINK §3, BUILD-1 `pulsar_cl.c` TODO(RE-1) |
| R1 | The accept packet's slot byte `[11]` must be **1..4**. `[11] = 0` trips a fatal assert in the controller (`accept_pkt->endpoint != CONN_NEG_SLOT`). Slot 0 is the negotiation slot only. | **BLOCKS** | LINK §4, `pulsar_host.py`, BUILD-1 `pick_slot` |
| R2 | Accept `[2]&7 == 3` is **reject**, not "lock". It sends the controller back to idle. The host sends exactly one accept with `[2] = (fmt<<3)\|2`. | **BLOCKS** | LINK §4, tool `EP_LOCK`, BUILD-1 (queues CONN_NEG then LOCK) |
| R3 | Accept bytes `[12]`/`[13]` are **not** the version. `[12]` = "use your steady IV" flag (0 makes the controller zero its IV). `[13]` = slot count (≥ 1). The tool and BUILD-1 put `01 17` there, which means slot count 23. | **BLOCKS** (corrupts the uplink length budget) | LINK §4, tool, BUILD-1 |
| R4 | Beacon byte 14/15 bit = `1 << S`, where S is the accept `[11]` value (1..4). It is the same number as the "CL endpoint", and the device TX prefix is S+1. BUILD-1 sends `1 << (s+1)` for prefix s+1, which is off by one. | **BLOCKS** (no downlink delivered, no acks) | LINK §4 (open item closed), BUILD-1 `PULSAR_ENDPOINT_OFFSET` |
| R5 | SPL reply = `[LEN][status][seq][data]`. Status bit 7 = command failed and bit 0 = 0. Bits 1..6 are **stale** (left from the advert or an earlier poll), **not** the command number. BUILD-1 drops every reply whose bits 1..6 ≠ the request number, so pairing never completes. | **BLOCKS** (BUILD-1) | LINK §5 (UNKNOWN → pinned), BUILD-1 `pair_on_reply` |
| R6 | After a successful PairingData the real host writes **cmd 0x15 Reset (on-air `0x2a`, empty)**, then drops the DM link. The SPL jumps to the app 500 ms later. LINK leaves this INFERRED; BUILD-1 doesn't send it. | **BLOCKS** (probable: the controller stays in the SPL) | LINK §5, BUILD-1 |
| R7 | The steady-state CCM counter advances **once per beacon period** (plus skipped periods), on both sides. It does not advance per uplink packet. | **BLOCKS** for a per-packet host. BUILD-1 survives through its 32-counter search window. | LINK §2b |
| R8 | Uplink nonce direction bit = **0**. `steady_state_nonce()` defaults to 1, and LINK §2 places the bit wrongly. | **BLOCKS** for any RX port of the tool; BUILD-1 learns the bit | LINK §2, `pulsar_host.py:566` |
| R9 | `PULSAR_DEVICE_MISSED_BEACONS_BEFORE_DC` = **25** (50 ms). The controller then drops to seek. BUILD-1's synchronous `erase_now` path can stall about 90 ms. | HARMLESS if `erase_now` never runs while connected; otherwise a reconnect (≤ ~0.3 s) | BUILD-1 `store.c` |
| R10 | Seek / reconnect cadence pinned: one 75.25 ms RX dwell per channel, rotating channel indices **0, 17, 36** (2404/2442/2478 MHz). ACTIVE_SEEK lasts 30 s, then INACTIVE_SEEK for 1 h. Timeouts can be set with cmd 0x49. | open item closed. The host must keep indices 0/17/36 in its channel map. | LINK §5.1 |
| R11 | Handedness pinned: cmd 1 `device_desc` bytes 16..23 = `"left"`/`"right"`/`"unconf"` (UICR `0x10001094`). Also pulsar-type byte 2 = 0/1/2. | open item closed | PERIPHERALS §4.1/§9, BUILD-1 `LINK_HAND_UNKNOWN` |
| R12 | cmd 9 "data ready" does **not** gate streaming. The controller waits 100 ms for it, then streams anyway. cmd 0xa1 is a battery load test that pulses the motor: don't send it. | HARMLESS (wrong inference) | PERIPHERALS §1.2 |
| R13 | Notification fragments span notifications. A non-final fragment ends the chunk loop, and reassembly persists per controller. `pulsar_input.unpack_chunks` resets per buffer. | HARMLESS (loses fragmented chunks) | `pulsar_input.py`, BUILD-2 |
| R14 | Netaddr `0` crashes the controller app (`init->address` assert). `0xFFFFFFFF` reads as "no pairing info". BUILD-1 already excludes both; the docs don't say so. | HARMLESS (doc gap) | LINK §5/§6 |
| R15 | A PairingData that fails still moves the SPL to state 5 and wipes its keys. The host must redo `0x25` before retrying `0x22`. A request whose seq equals the previous one (including **0 as the first frame**) is treated as a retransmit and not executed. | HARMLESS (BUILD-1 starts at seq 1) | LINK §5, `pulsar_host.py` (`seq=0` defaults) |
| R16 | Smaller report errors: the 0x2b request has no `type`; the sidechannel chunk size is 4; PCM haptics are 3-bit; on-time resets to 19 µs per enumeration; the validator doesn't wake the LED thread; the ntf 8 label; deerfly pins; conn-request format byte. | HARMLESS / WORDING | §R16 |
| R17 | Tool mismatches and selftest independence. | HARMLESS / WORDING (except R1–R3/R8, counted above) | §R17 |

**Bottom line for HW-2:**
- BUILD-1 can now implement the TL from R0.
- R1–R6 must be fixed in BUILD-1 before G-Link. They are all small code changes.
- R7/R8 are already absorbed by BUILD-1's RX search but should be fixed in the docs and tools.
- Everything else in LINK/PERIPHERALS that BUILD-1/BUILD-2 rely on re-verified (list at the end).

**BUILD-1 checklist** (`radio-fw/src`, main `167f6fa`):

| # | where | change |
|---|---|---|
| 1 | `pulsar_cl.c:31,66`, `host_core.c:817` | implement the TL per R0 |
| 2 | `host_core.c:119-120` `pick_slot` | never return 0; slots 1..4 (R1) |
| 3 | `host_core.c:499` + `pulsar_cl.c:24,71` | drop the second accept with `CL_EP_LOCK` (R2) |
| 4 | `pulsar_cl.c:46` | `[2] = (fmt<<3)\|2`, `[12] = iv != 0`, `[13] = 1`; no version (R3) |
| 5 | `pulsar_ll.h:21` | `PULSAR_ENDPOINT_OFFSET 0`, with slot = prefix−1 ∈ 1..4 (R4) |
| 6 | `host_core.c:345` `pair_on_reply` | match on seq only; fail on `data[0] & 0x80` (R5) |
| 7 | after PairingData OK | send Reset `0x2a` (empty), then stop DM polling (R6) |
| 8 | `decrypt_uplink` | advance the counter per beacon period (R7; the window already hides it) |
| 9 | `store.c:124-125` | no synchronous `erase_now` while any slot is connected (R9) |
| 10 | channel map | keep indices 0/17/36 (R10) |
| 11 | `LINK_HAND_UNKNOWN` | fill from cmd 1 desc[16..23] (R11) |

---

## R0. The TL header (register read / write / response / notification): CONFIRMED on both sides

**Sources:**
- host: syncboss `pulsar_tl_host.c` (`0x19acc..0x1a220`, string refs at `0x19e48..0x1a214`);
- controller: elk the TL state machine at `T = 0x200051e8` (hsm states `0x253e5` → `0x22761` →
  `0x235fd` / `0x236a5`), handlers registered at `0x18b5a..0x18b6c`.

### Where the TL packet sits

| direction | CCM | layout |
|---|---|---|
| downlink | plaintext | beacon payload `[0..13 beacon][14 = 1<<S downlink mask][15 = ack mask][16.. TL packet]` |
| uplink | decrypted | `[S][TL packet]` |

- **Downlink.**
  - Controller: the CL layer hands `CL+2` with length `LEN−2` to the TL (`0x23d02..0x23d1c` →
    `rec+0x38` = `0x251f9` = TL event 7).
  - Host: `FUN_00019acc` (the CL `prepare_beacon_handler`) writes the TL packet into the CL buffer
    and gives the length.
  - TL packet ≤ 34 bytes (syncboss asserts payload ≤ 0x20, `FUN_00019fd0`/`FUN_0001a088` line
    0xbe).
- **Uplink.**
  - Controller: `0x23d26 strb slot,[buf],#1`, then the TL builder fills the rest.
  - Host: `FUN_0001d038` takes CL[0] ≠ 0 as data and passes `data+1`, `len−1` to the TL RX
    `FUN_00019c70`.

### TL packet

`[0] reg | [1] flags | [2..] payload`

| flags bit | meaning | host evidence | controller evidence |
|---|---|---|---|
| 0..3 | **seq** (0..15) | `FUN_0001a6f8` stamps the current seq into every TL packet it sends (`bfi r3,r0,#0,#4` at `0x19b30`, `0x19bae`, `0x19bdc`, `0x19c1c`) | RX: `pkt[1] & 0xf` → `T+0x40` (last seen seq). TX: every uplink carries `T+0x40` in bits 0..3 (`bfi r2,r1,#0,#4` at `0x23670`, `0x23706`, `0x237d8`, `0x23860`) |
| 4 | **1 = READ, 0 = WRITE** | the read path (msg type 0, as for SPL `0x12`) → `FUN_000198e0` → `FUN_0001a088` sets `\|0x10`. Writes (types 1/2) → `FUN_000198ac` → `FUN_00019fd0` with `& 0xcf` | `ubfx sb,r3,#4,#1` (`0x234f6`): `sb = 0` calls `T+0x2c` = `FUN_00027ebc` (**write** handler, `app_command_registers.c`); `sb = 1` calls `T+0x30` = `FUN_00025c98` (**read** handler) |
| 5 | **error** (responses) | the completion callback `T[2]` gets `(flags >> 5) & 1` as its first argument (`0x19dc4 ubfx r0,r0,#5,#1; blx r4`) | `T+0x4b` bit 5 = `!handler_ok` (`0x2355a..0x2355e`) |
| 6 | **notification** (unsolicited uplink) | `pkt[1]` bit 6 → notification callback `T[0]` with `reg = pkt[0]`, `data = pkt+2`, `len−2` (bit-6 test `0x19ca6 lsls r2,r2,#0x19`) | set on notification uplinks (`0x23664 orr #0x40`, `0x2371a`); clear on responses (`0x23850 bfi …,#6,#1` with 0) |
| 7 | unused (always 0 as far as seen) | printed only in the mismatch assert | never set |

### Exchange rules (CONFIRMED unless tagged)

1. **Host request.**
   - Format: `[reg][seq \| 0x10 if read][payload ≤ 32]`, addressed to the controller (beacon byte 14
     bit S).
   - The seq advances by one per new request (`FUN_0001a708`: +1, wrapping 15 → 0; initial 0 from
     `FUN_0001a6d8(T+0x10, 0xf)`).
   - The **same packet is re-sent in every beacon** until it is answered or its timeout runs out
     (`T+0x1c` = timeout in beacon periods; `ms*1000 → /2000`, minimum 1).
   - On timeout the host completes with an error and sends the empty packet below.
2. **Idle host beacon.** It carries the 2-byte TL `[0x00][seq]` with byte 14 = 0 (`0x19b98`
   path). INFERRED to be optional for the controller: a byte-14 = 0 packet goes to the broadcast
   handler `T+0x34`, not to the command path.
3. **Controller duplicate filter.** An addressed packet with the same (seq, reg, bit 4) as the
   last one (`T+0x40`, `T+0x4a`, `T+0x4b` bit 4) is a retransmit (`0x234f2..0x23514`). The
   controller re-sends its last response and does not execute the command again. So the host must
   advance the seq for every new command, including a repeat of the same command.
4. **Read response.** `[reg][ack-seq \| 0x10 \| err<<5][data]`, data length = what the read
   handler returned (`T+0x48`; `0x23834..0x23866` copies `T+0x4a..` = reg, flags, then the
   `T+0x4c` buffer). It is always sent for reads (`0x23544`: `sb ≠ 0` → `T+0x49 = 1`).
5. **Write acknowledgement.** A successful write that returns no data sends **no response
   packet**: `T+0x49 = 0` unless the handler failed or returned data (`0x2354a..0x23552`).
   - The host completes it when **any** uplink from that controller (for example the next
     notification) carries the request's seq in bits 0..3.
   - `FUN_00019c70`: `FUN_0001a6fc(seq_state, pkt[1] & 0xf)` passes, and bit 6 set → completion
     `T[2](bit5, reg, 0, NULL)`.
   - A failed write gets an explicit `[reg][ack-seq \| err]` response.
6. **Response check.** The host requires response `pkt[0]` == the request reg (or it asserts, with
   all six flag fields in the message) and bits 0..3 == its current seq.
7. **Notifications.**
   - Format: `[0x00][ack-seq \| 0x40][ntf chunk stream]`.
   - The packer `0x20210` writes reg = 0 first (`0x2021c strb r4(=0),[r0]`) and fills chunks up to
     the uplink budget `0x34 + 0x47*(slots−1)` = 52 bytes for one slot (`0x22714..0x2272e`).
   - Host: notification reg 0 = chunk stream. libsyncboss sees it as the 0x14-byte wrapper with
     byte 0x13 = 0, sidechannel absent because caps bit 0 is set (R16); reg 8 = blob.
   - This is the stream `pulsar_input.unpack_chunks` parses (remember R13).
8. **Reg `0x2a` (`'*'`)** in either direction is the RF-performance stats channel (host
   `FUN_0001a430` / `FUN_0001a524`, controller `FUN_000232c0` and the `0x20007158` builder). A
   non-Meta host doesn't need it; ignore uplinks with reg `0x2a`.

**Example (hand-built, not from a capture):**
- Read cmd 0x32 with seq 3, controller in slot 1: beacon bytes 14..18 = `02 00 32 13`. The CL
  length covers 2 + 2 bytes.
- Response uplink plaintext = `01 32 13 <16 bytes>`.
- A write of cmd 0x28 with seq 4 = `.. 28 04 <12 bytes>`. Its ack = the next uplink with bits 0..3
  = 4.

**Still to confirm on air (non-blocking):** that the Quest's real downlink matches (HW-1 can check
from plaintext); the exact CL LENGTH accounting; whether the idle `[00][seq]` must be present.

**Fix:**
- LINK §3: replace the "on-air TL header UNKNOWN" paragraph with the above.
- BUILD-1: implement `pulsar_cl.c` TODO(RE-1) to it (per-controller seq, retransmit per beacon,
  read = bit 4, implicit write-ack, reg 0 notifications).
- `pulsar_host.py`: add `build_tl_request` / `parse_tl_uplink` with literal-byte selftests.

---

## R1. Accept slot `[11]` is 1..4. 0 is fatal.

**Claim:**
- LINK §4: "`[11]` = assigned slot (… `< 5`)"; "the slot assigned in the negotiation packet is 0..4".
- `pulsar_host.py:310` `SLOT_MIN = 0`; selftest builds slot 0.
- BUILD-1 `pick_slot()` returns slot 0 first and `real_encode` writes it to `[11]`.

**Evidence (elk accept handler, connection state `0x23ace`, RX case `0x23af8`):**
- `0x23afc ldrb r2,[r3]; cmp r2,#1` → type.
- `0x23b04..0x23b16`: `[3..10]` vs `rec+0/+4`.
- `0x23b18 ldrb r1,[r3,#2]; and #7; cmp #2`.
- `0x23b22 ldrb r1,[r3,#0xb]; cbnz r1 → 0x23b30`; otherwise `bl 0x1f43c` (fatal assert, no return) with
  `0x303b9 "accept_pkt->endpoint != CONN_NEG_SLOT"`.
- `0x23b30 strb r1,[rec,#0xc]`, the slot used from then on.
- `FUN_00028ad0` (`0x28ae0 cmp r0,#4; bls`) bounds it at ≤ 4 and programs TX prefix `slot+1`
  (`0x28afc adds r5,#1`, `FUN_00024c24(7, slot+1)`).
- During seek the controller calls `FUN_00028ad0(0, …)` (`0x23ae8`), so slot 0 = prefix 1 = the
  negotiation slot.
- Host side agrees. The allocator `FUN_0001d4d8` scans slot bits from 1, and the response staging in
  `FUN_0001d038` writes the allocated value to `rec_host+0x7f`.

**Fix:**
- LINK §4: the slot is **S ∈ 1..4**. Slot 0 is negotiation only, and a Touch Plus host can hold at
  most 4 controllers.
- `pulsar_host.py`: `SLOT_MIN = 1` for the accept and the selftest.
- BUILD-1: never assign 0.

## R2. Accept endpoint 3 = reject, not "lock"

**Claim:** LINK §4 "`[2] & 7` = endpoint (2 = CONN_NEG, 3 = lock)"; "first `2` = CONN_NEG, then
`3` = lock on the follow-up". `pulsar_host.EP_LOCK`. BUILD-1 queues an accept with endpoint 2 and
then a second one with 3.

**Evidence:**
- **Device.** `0x23b64 cmp r1,#3` takes this path:
  - it switches state to `0x23955` (the idle state, which on entry re-draws the steady IV from the
    RNG, `0x2396e..0x239c4`);
  - it bumps a reject counter and calls the connection-change callback `rec+0x40` with **0**
    (`0x23b82 movs r0,#0; blx r3`).
  - The success path calls the same callback with **1** (`0x23c8c`).
- **Host.** `FUN_0001d038` writes `rec_host+0x76 = (fmt<<3) | 3` only when the upper layer's
  connection-request callback returns 1 (refuse). On accept it writes `(fmt<<3) | 2`.

**Effect:**
- If the first accept is lost, the "lock" that follows rejects the controller.
- If the first accept arrives, the controller is already in the connected state. The second packet
  then lands as stray downlink data.

**Fix:** one accept, `[2] = (fmt<<3) | 2`, where fmt = the request's `[1] >> 3` (2 for Touch Plus).
Drop `EP_LOCK` from the tool and BUILD-1, or rename it `EP_REJECT` and use it only to refuse.

## R3. Accept bytes 12 and 13: the IV flag and the slot count, not the version

**Claim:** LINK §4 "the protocol version `0x1701` … echoed into the outgoing response". The tool
and BUILD-1 put `01 17` at `[12..13]`.

**Evidence:**
- **Device:**
  - `0x23b32 ldrb r1,[r3,#0xc]; cbnz`. Otherwise `strd 0,0,[rec,#0x68]`: `[12] = 0` zeroes the
    controller's steady IV, so it keeps using the legacy nonce for the whole session.
  - `0x23b3e ldrb r3,[r3,#0xd]; cmp #1; it lt; movs #1; strb [rec,#0xd]`: `[13]` = slot count, at
    least 1.
  - The slot count sets the uplink length budget `0x34 + 0x47*(n-1)` (`0x22718`, `0x236e4`).
  - Nothing in the accept path reads a version.
- **Host** `FUN_0001d038`: `+0x80 = (iv_lo | iv_hi) != 0` and `+0x81 = slots requested` (request
  `[14]`, honored only as 1 or 2, else 1). These are bytes `[12]`/`[13]` of the body copied from
  `+0x74`.
- **Version:** `0x1701` belongs to the controller's **request** (bytes 10..11, AUDIT A14), not to
  the accept.

**Full accept body, CONFIRMED on both sides:**

| byte | value |
|---|---|
| `[0]` | 1 |
| `[1]` | `+0x75`, not read by the device |
| `[2]` | `(fmt<<3)\|2` |
| `[3..10]` | device ID, LE (lo word, hi word) |
| `[11]` | S (1..4) |
| `[12]` | 1 if the request carried a non-zero IV |
| `[13]` | slot count (1) |

The rest of the 26-byte body is not read.

**Fix:** LINK §4, `build_conn_negotiation`, BUILD-1 `real_encode`.

## R4. Beacon bytes 14/15: endpoint == slot; the open item is closed

**Claim:** LINK §4 keeps "radio slot 0..4" and "CL endpoint 1..4" apart and says their mapping
needs a capture. BUILD-1 uses `PULSAR_SLOT_BIT(s) = 1 << (s + 1)` with s = prefix−1.

**Evidence:**
- **Device, connected state.**
  - `0x23ccc ldrb r2,[rec,#0xc]` gives S (the accept `[11]`).
  - `0x23cd0 ldrb r3,[CL]; lsls r7,r2; ands r7,r3`: CL[0] = beacon byte 14, test `1<<S`.
  - `0x23cda ldrb r3,[CL,#1]; asr r3,r2; tst #1`: byte 15, ack bit S, which calls `rec+0x44`.
  - Downlink data = CL+2 (beacon byte 16 on), length `LEN−2`, delivered to `rec+0x38` when bit S is
    set or byte 14 = 0 (the "addressed" flag is set only in the first case).
  - Uplink CL[0] = S (`0x23d26`), CL length ≤ 0x7d (assert `0x23d42`).
- **Host.** `FUN_0001d038` treats CL[0] ≠ 0 as an existing endpoint's data. Its endpoint allocator
  is the slot allocator (R1).

**Result:** a single number S ∈ 1..4:

| use | value |
|---|---|
| accept `[11]` | S |
| controller TX prefix (and host RX pipe) | S+1 |
| beacon byte 14 downlink bit, byte 15 ack bit | `1 << S` |
| uplink CL[0] | S |

**Fix:**
- BUILD-1: index slots by S = prefix−1 ∈ 1..4, and set `PULSAR_ENDPOINT_OFFSET 0`.
- `pulsar_host`: collapse slot/endpoint into one parameter.
- LINK §4 bullet "byte 14 = `1 << slot`" is right; the "two domains" paragraph should go.

## R5. SPL reply format (was UNKNOWN; BUILD-1 guessed wrong)

**Evidence (elk-spl):**

*Buffers.*
- TX buffer = `0x20000cb0` (`0x7f18`/`0x7f94` → `FUN_00008ebc` PACKETPTR).
- RX buffer = `0x20000db0` (`0x8652`). They are separate, so the reply doesn't reuse the request
  header.

*Reply build at the end of the dispatcher `FUN_0000822c`:*
- `+0x59 &= 0xfe`;
- `+0x5a = seq state`;
- `+0x59 = (+0x59 & 0x7f) | (!ok << 7)`;
- `+0x58 = n + 2`, where n = the per-read reply length (0x20 for 0x12; 0 for writes).

*All writers of `+0x59` (full-image scan):*
- the advert copy (`0x7f7c`, 32 B from `+0x38`, so `+0x59` = advert byte 0 = 2);
- the empty-poll reply `FUN_00007fd4` (`+0x59 = 0`, LEN 2);
- the unsolicited-reply path `0x86f0` (`(num<<1 & 0x7e) | 1`);
- the dispatcher.

Nothing copies the request's command number.

*Sequence number.*
- Seq state `{last, 0xff}` (`FUN_00009008`). `FUN_00009010` stores the request seq.
- `FUN_0000902c(last == seq)` routes a repeat to the retransmit path `0x871e`: no dispatch, and the
  old buffer goes out again.
- So the reply seq = the request seq, and a repeated seq (including 0 as the first frame after link
  start, since `last` starts at 0) is never executed.

**Result:**
- Reply = `[LEN = n+2][status][seq][n data bytes]`.
- status bit 7 = 1 when the handler returned failure; bit 0 = 0; bits 1..6 are undefined (0 after
  an empty poll, 1 straight after advertising).
- Match replies by **seq only**. Treat bit 7 as the result.
- For `0x25` the 32-byte controller public key is the data.

**Fix:**
- BUILD-1 `pair_on_reply`: drop the `PAIR_CMD_NUM(r->data[0]) != PAIR_CMD_NUM(h->pair_cmd)`
  test, and fail on `r->data[0] & 0x80`.
- `pulsar_host.parse_setup_x25519_response`: check bit 7.
- LINK §5: replace "reply command-byte format is UNKNOWN" with the above.

## R6. The host must send Reset (0x15) after pairing

**Claim:** LINK §5 says 0x11 "only advances the state; reboot/jump-to-app is INFERRED". The Reset
handler is described as "for a forced restart".

**Evidence:**

*Real host, `sb input_pair` (`0x66124`):*
- After `syncboss_send_cmd_and_wait_for_response_with_timeout` (the MCU pairing run) returns fw
  status 0 (`0x665ac ldr w7,[sp,#0x10]; cbz w7 → 0x6663c`), it calls
  `pulsar_write_nolock(dev, reg 0x15, NULL, 0, 0x960)` (`0x6663c..0x66654`, log on failure
  "Failed to reset controller with status %i").
- Then `syncboss_queue_simple_cmd(0xc9)` = DM disconnect (`0x665e4..0x665f4`).
- On failure it only disconnects.

*SPL:*
- Nothing ever reads pairing state 5. The only refs to `0x20000328` are `0x3894` (init = 1),
  `0x3928` (= 2), `0x3948` (= 3) and `0x39fc` (= 5).
- Reset `FUN_00002a04`: if the mode byte `0x200001ac` is 0 or 0x7f, it schedules `FUN_00002928`
  (validate the app image, then jump) 500 ms later (`FUN_000031e8(500, 0x29cd)`).

**Fix:**
- After a successful `0x22` reply (status bit 7 clear), send `[2][0x2a][seq+1]` (Reset write, no
  payload).
- Wait for the reply, or keep polling for up to ~10 ms.
- Stop polling the DM link, then start beaconing. The controller boots the app about 500 ms later
  and seeks (R10).
- Add this to LINK §5, HARDWARE-DAY §5 and BUILD-1.

## R7. Steady-state counter: per beacon period, not per packet

**Claim:** LINK §2b: "`PACKETCOUNTER` = a per-slot counter … that advances per uplink packet."

**Evidence:**
- **Controller TX counter `LL+0x1b8`:**
  - reset to 0 in `FUN_00028ad0` (`0x28b22`, at the accept);
  - incremented in the per-period state handlers: `0x2449e` (+1), `0x2450e`, `0x2593a`, `0x25976`
    (`+= LL+0x1c4 + 1`, where `+0x1c4` = beacons skipped since the last RX, `0x23f3c..0x23f44`);
  - used as `PKTCTR` at `0x240dc`.
- **Host:** the per-period handler in syncboss (decomp near `0x1de..`, `param_2 == 1`) increments
  **all five** per-slot counters `LL+0x3c..+0x4c` together, with the hop (`FUN_0001aaf4(+0x70,1)`)
  and the beacon timestamp (`+0x5e4 += 2000`). The RX arm passes `LL[0x3c + slot*4]` as `PKTCTR`
  (`FUN_0001e2dc` case 1).

**Result:** `PKTCTR` = the number of beacon periods since the accept. It advances in every period
whether or not that period carried an uplink. Still a live-capture item: the exact period the count
starts in (off-by-one at the accept).

**Fix:**
- LINK §2b.
- `pulsar_crypto scan`: default `--max-counter` well above 8 (AUDIT A8 already asked).
- BUILD-1: advance per period; keep the search window for safety.

## R8. Uplink nonce direction = 0

**Evidence:**
- The controller's CCM setup `0x239fc` writes `+0x120` (8 B, `strd lr,ip`) and `+0x129/+0x12d`
  (IV), but never `+0x128`.
- A full-image scan finds no store to `cfg+0x128` (AUDIT A17 agrees).
- An AESCCM uplink built with direction 0 fails MIC under `steady_state_nonce()`'s default and
  passes with `direction=0` (tools helper, independent `cryptography` vector).

**Fix:**
- `pulsar_host.steady_state_nonce(direction=0)`; flip the selftest's bit-39 assert.
- `pulsar_crypto` selftest: build its A2 packet with direction 0.
- LINK §2: "direction = nonce bit 39 (byte 4 bit 7), always 0".

BUILD-1 tries both directions, so it is unaffected.

## R9. Missed beacons before disconnect = 25 (50 ms)

**Evidence:**
- The beacon-timeout handlers (`0x244b0`, `0x244e2`, `0x24540`, `0x24584`) all do
  `ldr [LL,#0x280]; cmp #0x18; bhi → state 0x245b5`. More than 24 consecutive missed beacons sends
  the controller to the seek state.
- Seek entry (`0x245c4..0x24612`) recomputes the hop increment, resets the channel map to all 37,
  and clears the counters.
- Assert at beacon RX `0x24280..0x24292`:
  `"m_pulsar_dev_ll.consecutive_missed_beacons < (PULSAR_DEVICE_MISSED_BEACONS_BEFORE_DC + …"`
  (string `0x3058b`), with `adds r2,#0x19`.
- Period 2000 µs (`udiv` by `0x7d0` at `0x23f24`). Total: about **50 ms of silence**.

**BUILD-1:**
- `main.c` already erases in 1 ms `ERASEPAGEPARTIAL` slices (`STORE_SLICE_MS 1`, 90 slices),
  which is fine.
- But `store.c:124-125/167/177` `erase_now()` runs all remaining slices synchronously, up to ~90 ms.
- `:177` is boot-only (radio idle). `:124-125` (compaction when the target page isn't blank) can run
  while connected, and drops every controller to seek.

**Fix:** never call `erase_now` while any slot is connected. Defer compaction, or interleave slices
with the beacon schedule. Recovery costs ≤ one seek rotation (R10) plus negotiation, so this is
HARMLESS but visible as a tracking dropout.

## R10. Seek / reconnect cadence (open item, closed)

**Evidence:**
- Seek RX `FUN_00022de8`: the channel index = table `0x316ec` = `{0, 17, 36}` indexed by a rolling
  counter `% 3`.
- Frequency from `0x31658` gives channels 4/42/78, i.e. **2404/2442/2478 MHz**.
- `TIMER0` is cleared and restarted, and the RX window closes at `CC[2] = 0x125f2 = 75 250 µs`
  (`0x22e22`, `FUN_000228cc` `str r4,[TIMER,#0x548]`).
- Each timeout or bad RX moves to the next of the three channels.

**Why it works:**
- 37 hops × 2000 µs = 74 000 µs < 75 250, and the hop increment 5..15 is coprime with 37.
- So a host with a full channel map puts exactly one beacon on any fixed channel in every dwell.
- **Requirement:** indices 0, 17 and 36 must be in the host's channel map, or the controller can't
  find the host.

**Power states** (elk `.data` `0x2000050c..0x2000052c`, `ms` INFERRED; cmd **0x49** sets them by
name, `{char state[28], i32 timeout}`):

| state | default |
|---|---|
| NO_PAIRING | 1 200 000 |
| **ACTIVE_SEEK** | **30 000** |
| **INACTIVE_SEEK** | **3 600 000** |
| ACTIVE_CONNECTED | 300 000 |
| INACTIVE_CONNECTED | 14 400 000 |
| DEAD_BATTERY | 15 000 |
| PAIRING | 60 000 |
| INACTIVE_SEEK_BOOT | 300 000 |
| COLD_BOOT | 10 000 |

- Entering INACTIVE_SEEK sets `0x2000549c+0x324 = 1000`; connected states set 4000. INFERRED to be
  a lower duty cycle. The inactive-seek RX pattern is UNKNOWN.
- So after a power cycle a paired controller seeks continuously for about 30 s, then keeps seeking
  at a lower duty for about an hour.
- After a 25-beacon drop it reconnects within one ~226 ms rotation plus negotiation.
- "Invalid host Pulsar version detected, stopping seek" (`0x149b4`, event 0x10) leaves seek.

## R11. Handedness (open item, closed)

**Evidence:**
- elk read case 1 (`0x25e22..0x25e70`, length 0x20) builds four strlcpy'd 8-byte fields:

| bytes | content |
|---|---|
| 0..7 | `"oculus"` |
| 8..15 | `"rubyprq"` |
| 16..23 | from UICR `0x10001094`: 0 = `"left"`, 1 = `"right"`, > 1 = `"unconf"` (`cmp r3,#1; bhi`) |
| 24..31 | `"0x%02x"` of the board ID (UICR `0x10001090`) |

- Bytes after each NUL are not cleared.
- **Host:** `input_refresh_cache` reads cmd 1 → `+0x4dc` and logs `handedness : %s` from `+0x4ec`
  (= desc+16).
- **Pulsar type:** elk `rec+0xa` = the same UICR value. The host maps pulsar-type byte 2 to
  0 left / 1 right / 2 unconf (`apply_spoofing 0x66bf4..0x66c5c`), subtype = byte 2 + 1.
- **"Failed to get Input MCU handedness."** is elk's boot cross-check against deerfly SPI reg 0x0f
  (`0x19384..0x1938e`). It only logs a mismatch, so the UICR value wins.
- `syncboss_starlet_get_handedness` is for a different device (starlet) and is irrelevant here.

**Fix:**
- BUILD-2: read cmd 1 at connect and take the NUL-terminated string at 16..23.
- BUILD-1 can drop `LINK_HAND_UNKNOWN` once the driver fills it.
- PERIPHERALS §4.1/§9: closed.

## R12. cmd 9 does not gate streaming; don't send 0xa1

**Claim:** PERIPHERALS §1.2 step 8 "INFERRED: a non-Meta host must send it before input/IMU
notifications flow". Step 9 0xa1 "signals thread 5 flag 0x40".

**Evidence:**
- **cmd 9.** Case 9 calls `*0x2000549c` = `0x1481d` = `FUN_00027d74(1, 0x20)`, which signals the
  *wireless* thread.
  - That thread (`0x17cd6..0x17d4c`) waits up to 100 ms (`add.w r6,r0,#0x64`) after link-up for
    flag 0x20.
  - On timeout it logs "Failed to receive ready signal from host" (`0x2d2f7`) and falls through to
    the same `0x17d4c` message post as the signalled path.
- **cmd 0xa1** (`0x2854e`) signals the haptics thread 0x40, which runs `FUN_0001ab98`: deerfly
  reg 0x4a pulses at three amplitudes, measured through reg 0x5a, logged "Battery health: %u/%u/%u".

**Fix:**
- §1.2: cmd 9 is optional (send it; it is harmless). Skip 0xa1 (motor pulses).
- §9 open item "must a non-Meta host send 0xa1": closed, no.

## R13. Notification fragments span notifications

**Evidence:**
- `ntf_unpacker_next` (`0x12e74`) returns `csel x20,x19,xzr,lt` on the header's sign bit
  (`0x13004`): a **non-final fragment returns NULL**. The caller's loop (`0x58854 cbnz x0`) then ends
  for this notification.
- Reassembly state lives in the per-controller entry (`+0x158`) and carries over to the next
  notification.
- A broken sequence also returns NULL, and the rest of that notification is dropped.
- The other bit fields re-verified exactly (see the list at the end). The total must be ≤ 0x3f.

**Effect:** `tools/pulsar_input.unpack_chunks` resets per call and keeps parsing after a fragment, so
a chunk split across two uplinks is lost.

**Fix:** keep reassembly state per controller across calls (BUILD-2 and the tool). HARMLESS for
plain IMU/input chunks, which fit in one uplink.

## R14. Netaddr constraints

- elk app init (`FUN_00018a24`): `FUN_0001ed9c` checks whether the record's first word is erased.
  If it is, "No pairing info found. Skipping wireless init." (`0x2d610`) — so netaddr `0xFFFFFFFF`
  = unpaired.
- `0x18bcc cbnz r3` else assert `"init->address"` (`pulsar_ll_device.c`) — so netaddr `0` is fatal.
- BUILD-1 `host_core.c:698` already redraws on both values.
- LINK §6's "default network address = 0x00000000" would therefore crash a controller provisioned
  with it. Add a note to LINK §5 and Q2: the netaddr must not be 0 or 0xFFFFFFFF.
- The record the app reads is the same single SPL record (`m_pairing` pointer `0x20004dd8`, one
  record). The key comes from `rec+0x14` unless that is erased, otherwise `rec+4`
  (`FUN_0001ed76(+0x14, 4)`). This **confirms LINK §5.1's single record** from the app side.

## R15. SPL state and seq traps

- **Failed PairingData.** `0x39fc`: a failed `0x22`/`0x3a` (MIC fail or length ≠ 0x14) still runs
  `0x3a64..0x3a6c`: state = 5 and `FUN_000039bc` zeroes the private key, both public keys and the
  secret.
  - A retry of `0x22` passes the state ≥ 3 check but derives a secret from zeroed keys.
  - Always redo `0x25` first.
  - Every `0x25` regenerates the controller key pair (`FUN_00003928` runs each time).
- **Boot state.** Pairing state = 1 at boot (`FUN_00003894`, record `0x3b000`). So `0x25` is
  accepted with no prior command.
- **Seq.** R5: the first frame must not use seq 0. `pulsar_host.frame_spl`/`build_*` default
  `seq=0`. Default to 1 and document "increment per new command; resend with the same seq".

## R16. Smaller report corrections (HARMLESS / WORDING)

**LINK.md**
- §3 table: 0x2b's request is `{u32 offset, u32 len}` with **no** `type` at +5 (`sb 0x53150`,
  `stp w23,w24`, len 8). 0x28 is also a write (12 B). The table omits many IDs (0x01/02/03/0x0a/0x31/
  0x32/0x54/0xb6 R; 0x09/0x20/0xa1 W; 0x49 W state timeouts; firmware-update IDs).
- §3 notifications:
  - "conn+0xd2" is **type_info+0xd2**.
  - The sidechannel chunk size is **4** (`sidechannel_client_init(…, 0x127, 4, …)` at
    `0x5d730..0x5d744`), not "default 0".
  - Touch Plus has no sidechannel prefix only because elk forces capabilities bit 0 (cmd 0x0a,
    `orr r2,#1`, elk `0x25ef4..0x25f08`).
  - Host rule: sidechannel length = 0 if `caps & 1`, else 4.
- §3: the 0x14-byte wrapper is `spi_data_pulsar_data_t`:
  - `+0` u64 input_id
  - `+0x10` u16 timeout
  - **`+0x13` = register id**

  "Byte 0x13 must be 0" therefore means "push register 0 = chunk stream". The `pulsar_manager_*`
  layer also caps req_len at 0x40.
- §4 request table, byte 1: `[1] >> 3` = 0 means no bytes 14..24; 1 means bytes 14..22 present and
  23/24 forced 0; ≥ 2 means all present (`FUN_0001d038`). AUDIT A3's "zeroed when == 1" refers to
  bytes 23/24, not the IV.
- §4 request byte 14: the host honors only 1 or 2 slots (else 1, and 1 if `+0xf4` is set).
- §2: "direction bit as bit 0 of the counter's first byte region": wrong (R8).
- §6 "default netaddr 0": see R14.
- Steady IV origin (AUDIT A3 UNKNOWN): 8 RNG bytes drawn on **every entry to the idle state**
  (`0x2396e..0x239aa`, RNG `0x4000d000`, assert non-zero at `0x239b4`). A fresh IV per connection.

**PERIPHERALS.md**
- §2.2: the validator **does not wake** the LED thread. The thread re-reads `0x200069f8` at each
  end-of-pulse signal, so a new config applies from the next pulse.
- §2.2: the "IR LED configured" log prints before validation.
- First pulse after boot uses offset = d (no −ot/2).
- To switch LEDs off, send ot = 0 with a large p. With p < 1000 the ot = 0 path busy-loops
  (`osDelay(p/1000)` = 0, INFERRED).
- §2.1: ntf 0xb echo is also **periodic, every 2 s** (timer `0x2ebb4`, started with 2000 at
  `0x15674`), not only on change.
- No command handler checks payload length (cases 0x28, 0x97, 0xa0, …). Always send full-size
  payloads; a short one reads stale bytes.
- §4.1 ntf 8 "cap-touch raw" is doubtful. Deerfly writes the Fore Hall reading to buf[7..8]
  (`dfy 0xb146..0xb162`), and §4.2 itself calls buf[5..6]/[0xb..0xc] the stick ADC. Relabel it
  "raw analog (stick ADC + Hall)", INFERRED.
- §4.1 ntf 0x15: the host caches it raw (no `&0xfff`) and emits `raw/4095` with a separate
  `8.5 N` max field. It is not pre-multiplied.
- §4.1: the elk ntf table also has ids 0x19 (61 B) and 0x1b (24 B), and the host decodes an
  alternate 10-bit touch ntf 5. All are unused by Touch Plus (INFERRED).
- §4.2 deerfly buf[4] pins mix two board branches. Production (board > 9, ≠ 0xc), all active-low:
  - b0 P214
  - b1 **P215**
  - b2 P200
  - b3 P407 (boards 0x90..0x94) or P408
  - b4 P915

  P400 is the dev branch only.
- §4.2 "Hall → buf 0x23/0x25" and "stick → buf[0..3]": not traced end-to-end in deerfly (COULD NOT
  VERIFY). Host labels and the elk remap still pin the meaning (CONFIRMED there).
- §5: battery_info `[0..3]` f32 percent: upgrade to CONFIRMED (host prints `fcvtzs(+0x4fc)` as
  "battery state : %i%%").
- §7: PCM haptics (0x9d) are **3-bit ADPCM**, not IMA (2-bit plane 18 B + 1-bit plane 9 B; encoder
  config `{0x12, 9}` at `sb 0x83c50`).
- §7: 0xa0's deerfly reg 0x4a payload has one uninitialised byte (`{amp, ?, u16 freq}`). An
  out-of-range 0xa0 still sets the "playing" state.
- §7: haptics requests are dropped while the haptics state byte `0x20003c20` is 0.
- §1.2: the secondary-MCU branch is taken for Touch Plus (type_info+0x98 = "deerfly-app.bin").
  `input_refresh_cache` zeroes the cached on-time (`+0x488`, `0x5d6e0`), so an OS-set on-time
  falls back to **19 µs after every re-enumeration**. DEV-1 / relay Gate B must re-apply it after
  reconnects.
- Addresses: `0x114fe8`, `0x1af8f8/0x1af8fc` are Ghidra +0x100000 forms. The ELF vaddrs are
  `0x14fe8`, `0xaf8f8/0xaf8fc`.

## R17. Tools vs reports, and selftest independence

**All three selftests PASS** (`pulsar_host`, `pulsar_crypto`, `pulsar_input`). A separate set of 60
independent vectors (built with `cryptography`'s AESCCM, GF(2) CRC, and bytes hand-packed from the
instruction sequences) gave 54 passes. The 6 failures are listed below.

**Mismatches:**

| tool | issue | severity |
|---|---|---|
| `pulsar_host.py:310,408,436` | slot 0 allowed (R1) | BLOCKS |
| `pulsar_host.py:300,403` | `EP_LOCK = 3` (R2) | BLOCKS |
| `pulsar_host.py:416` | version at `[12..13]` (R3) | BLOCKS |
| `pulsar_host.py:525` | `downlink_endpoint` separate from the accept slot (R4); correct only if the caller passes S | HARMLESS |
| `pulsar_host.py:566` | `direction=1` default (R8) | BLOCKS for an RX port |
| `pulsar_host.py:135,189,267` | `seq=0` defaults (R15) | HARMLESS |
| `pulsar_host.py:147,160` | `frame_spl`/`unframe_spl(addr=)` still use raw-address `crc24`, not `crc24_air`; the selftest at `:680` exercises the AUDIT A9 bug path | HARMLESS (offline) |
| `pulsar_host.py:244` | `build_pairing_payload` takes 4 raw bytes, not a `<I` netaddr (AUDIT A16 not folded) | HARMLESS |
| `pulsar_host.py:197` | reply status bit 7 not checked (R5) | HARMLESS |
| `pulsar_crypto.py:279` | `--max-counter` default 8 (R7 makes it worse) | HARMLESS (decode) |
| `pulsar_crypto.py` | the legacy path uses the last captured beacon's ts; the firmware uses `ts + missed*2000` (AUDIT A2), so one missed beacon defeats it | HARMLESS (decode) |
| `pulsar_input.py` (`controller_apply_led :371`, `led` CLI `:604`) | no p < 700 µs warning although PERIPHERALS says never send it | HARMLESS |
| `pulsar_input.py:338` | ntf 0x15 not masked to 12 bits | HARMLESS |
| `pulsar_input.unpack_chunks` | no cross-notification reassembly (R13) | HARMLESS |
| `pulsar_input.py` docstring `:6` | "There is NO HID report descriptor" (LINK §3: cmd 0xab returns one) | WORDING |
| `pulsar_host.py:88-89,99-102` | stale CRC "literal" citations and "hardware-day item" (AUDIT A11) | WORDING |

**Matches (independently re-checked):**
- on-air cmd bytes 0x25/0x22/0x3a/0x28/0x2a;
- `[LEN][cmd][seq][payload]`;
- PairingData `[IV8][CCM20+MIC4]`, wrap key `shared[:16]`, nonce `00×5‖IV`, AAD 0, M = 4;
- `legacy_nonce`;
- `parse_conn_request` offsets;
- beacon bytes 0..13;
- `crc24`/`crc24_air` against a GF(2) reference;
- `split_notification`;
- `unpack_chunks` bit fields;
- ntf 1/2/3/4/9/0xb/0x17 decoders;
- 0x28 payload, clamp 75, p ≤ 500 000;
- `next_pulse_start` (20 000 random cases against a model re-derived from `FUN_0001873c`, 0
  mismatches);
- 0x97/0xa0 builders.

**Selftest independence.**

| tool | check | class |
|---|---|---|
| `pulsar_host` | X25519 RFC 7748 | independent |
| `pulsar_host` | cmd-byte literals | independent |
| `pulsar_host` | conn_request (hand-packed from the A3 table) | independent |
| `pulsar_host` | legacy nonce | independent |
| `pulsar_host` | pairing round-trip | self-consistent only (`ccm_encrypt`/`ccm_decrypt` share `aes_ecb`) |
| `pulsar_host` | crc framing | self-consistent, and on the bug path |
| `pulsar_host` | crc_air | self-consistent |
| `pulsar_host` | conn_negotiation | self-consistent; it asserts R1–R3 errors |
| `pulsar_host` | beacon | mostly round-trip |
| `pulsar_host` | steady nonce | asserts the wrong direction (R8) |
| `pulsar_crypto` | RFC 3610 #1 | independent, but M = 8 / 8-byte AAD, so it misses the M = 4 / 1-byte-AAD path used on air |
| `pulsar_crypto` | keystream round-trip | circular, no value |
| `pulsar_crypto` | A2 scan | AESCCM independent; nonce from the tool's own code with direction 1 |
| `pulsar_input` | CRC (zlib) | independent |
| `pulsar_input` | IMU SI arithmetic | independent |
| `pulsar_input` | LED literals | independent |
| `pulsar_input` | 4 hand scheduler cases | independent |
| `pulsar_input` | builder literals | independent |
| `pulsar_input` | ntf3 `23 c1 ab` | independent |
| `pulsar_input` | single-bit remap literals | independent |
| `pulsar_input` | deerfly → ntf → labels | mostly self-consistent (`pack_deerfly` and `deerfly_to_ntf` share offsets) |
| `pulsar_input` | chunks | round-trip |
| `pulsar_input` | ntf 0x17 | no hand-packed vector (AUDIT A6 asked for one) |

**Add as selftests** (all computed and passing, except where noted):
- an AESCCM direction-0 legacy request found by `scan` and parsed by `parse_conn_request`;
- an AESCCM M = 4 / AAD `00` wrap vs `build_pairing_payload`;
- ntf 0x17 `80 40 ff 07 80 23 f1 ff` packed by the A6 `bfi` sequence;
- every ntf 9 bit vs the table;
- a direction-0 steady packet (currently fails, R8);
- a counter-1000 packet (currently fails, R7);
- R1–R3 accept bytes as literal expectations.

---

## Open items: status after this review

| item | status |
|---|---|
| Handedness | **closed** (R11) |
| `PULSAR_DEVICE_MISSED_BEACONS_BEFORE_DC` | **25** (R9) |
| Seek / reconnect cadence | **closed** statically (R10); the inactive-seek RX pattern is still UNKNOWN |
| Slot ↔ endpoint mapping | **closed** (R4) |
| SPL reply byte | **closed** (R5) |
| Post-0x11 transition | **closed**: Reset 0x15 (R6) |
| Steady IV origin | **closed**: RNG per idle entry (R16) |
| Steady counter rule | per period (R7); the start period needs one live MIC |
| cmd 9 / 0xa1 | **closed** (R12) |
| On-air TL header for register read/write/notify | **closed** (R0), CONFIRMED on both sides; a capture only double-checks it |
| Inactive-seek duty, CRC trailer byte order, cmd 0x2b blob content, sync-buffer haptics rate | unchanged, live items |

---

## Re-verified as correct (with evidence)

**Pairing (priority 1)**
- **On-air bytes.** The SPL RX path `0x86a0..0x86d0` passes `pkt+1` / `pkt[0]` to `FUN_0000822c`:
  - `ldrb r1,[r0],#2` (the cmd byte; seq at +1, payload at +2 of that pointer);
  - `ands r7,r1,#1` (read bit);
  - `ubfx r1,r1,#1,#6` (number).
  - Read 0x12 → `FUN_00003948` (reply length 0x20). Write 0x11 → `0x3abc` = `movs r1,#0; b 0x39fc`.
    Write 0x1d → `0x3ac6` = `movs r1,#1; b 0x39fc`. Write 0x15 → `FUN_00002a04`.
  - So the on-air bytes `0x25`/`0x22`/`0x3a`/`0x2a` are CONFIRMED.
- **Host public key and key pair.** `FUN_00003948` requires state ≠ 0. It runs `FUN_00003928`
  (key pair: private `0x200002a1`, controller public `0x200002c1`), copies 32 request bytes to
  `0x200002e1` (host public), returns 32 bytes from `0x200002c1`, and sets state 3.
  - The host builds the same request in `syncboss 0x474xx` (`local_35 = 0x12`, payload =
    `m_session+0x21`, read type 0).
- **PairingData layout and KDF.** `0x39fc`:
  - requires state > 2;
  - `FUN_000093c0(priv 0x200002a1, host_pub 0x200002e1, out 0x20000301)` (X25519 via import/agree;
    the output is the third argument);
  - `FUN_0000909c(0x20000301)` → `FUN_00009084` copies **4 words = secret[0..15]** to the CCM key
    at `0x20001034`;
  - `FUN_00009198(payload+8, out 0x2000028d, 0x18, IV = payload[0..7], ctr = 0,0)`;
  - `FUN_0000904c` stores the IV at `cfg+0x19/+0x1d` (nRF DIRECTION at +0x18 untouched) and the
    counter at `+0x10/+0x14`;
  - header `[0]=0, [1]=len, [2]=0`, so AAD = 0x00;
  - MODE `0x01010001`;
  - MIC failure (`MICSTATUS == 0`) returns 0, and length must be 0x14.
  - Plaintext `[u32 LE netaddr][16-byte key]`.
- **0x11 vs 0x1d store.** `FUN_000038e8(dec, 0)` stores key = dec+4. `FUN_000038e8(dec, secret)`
  stores key = `secret[:16]`.
- **Single host record.** `FUN_000038e8`:
  - erases the page when the record is present (`FUN_000038a8` → `FUN_00006054`);
  - writes 0x14 B at `+0` and the key copy at `+0x14`;
  - the record pointer is set once to flash `0x3b000` (`FUN_00003894`).
  - The app reads the same one record (R14).

**Connected link (priority 2)**
- **Negotiation nonce.** elk `0x24092..0x240d6`: if `LL+0x1e8` (IV) == 0, the IV = `(LL+0x290 ts48
  + LL+0x280*2000) | session(LL+0x298) << 48` (`0x240cc add.w r3,r3,r4,lsl #16`), counter `0,0`.
  - Host `FUN_0001aba8` mirrors it in `FUN_0001e2dc` case 1 when the per-slot IV is 0.
- **Steady IV at request bytes 15..22.** `0x23c04 ldrd r1,r2,[rec,#0x68]; str r2,[pkt,#0x13];
  str r1,[pkt,#0xf]`.
  - Request LENGTH 0x19.
  - `[1] = 0x11`, `[2..9]` ID, `[10..13]` `rec+8` word (0x1701 + `+0xa` handedness, `+0xb` board).
  - `[14]` slot count, `[23]` RADIO `+0x50c` + byte, `[24]` byte `0x200000b0`.
  - Host parse `FUN_0001d038` reads the same offsets. Request = CL `[0] == 0`.
- **CCM uplink only.**
  - elk has only `0x01010000` (encrypt; `0x23a6c`, used by `0x239fc`; `0x3013c` is data).
  - syncboss decrypt literals are `0x1b37c`/`0x1b47c`. The other `0x01010001`/`0x01010000` byte
    hits at unaligned addresses (`0x38a46`, `0x5f52e`, `0x5f566`, `0x5fa2e`) are not literal-pool
    words.
  - The controller TX plaintext bypass `LL+0x29c` (`0x24052`) is unchanged.
- **Beacon bytes 14/15.** CONFIRMED with the corrected index (R4). Host `FUN_0001cf30` /
  `FUN_0001cdcc` agree.

**Register access (priority 3)**
- **Command-register IDs.** Every LINK §3 row: the literal `reg_id` and direction at its
  libsyncboss caller (sites: `0x540dc` 0x05, `0x540f8/0x5411c` 0x06, `0x549e0` 0x0b, `0x5255c` 0x13,
  `0x55148/0x551c0` 0x19/0x1a, `0x53e70` 0x1c, `0x533b8` 0x28, `0x532a8` 0x2b, `0x53440` 0x2f,
  `0x53e28` 0x33, `0x10898` 0x34, `0x54270` 0x38, `0x544e4` 0x3f, and 0x4c..0xb4).
- **Transport limits.**
  - `pulsar_read_nolock 0x67178`: `cmp w8,#0xec` → in_len ≤ 0xeb; sends `in_len+0x14` via get_data
    0x8f.
  - `pulsar_write_nolock_internal 0x66eb4`: `0x14+len < 0x100`.
- **Notification framing.** `controller_process_notification 0x57324`: len ≥ 0x14 and
  `ldrb [x3,#0x13]; cbz` (`0x5739c`). `ntf_unpacker_next` fields:
  - len = `ubfx #5,#6`;
  - type = `(h>>6)&0x20 | h&0x1f`;
  - seq = `ubfx #0xc,#3`;
  - last = sign bit;
  - unfragmented = `(h & 0xf000) == 0x8000`;
  - append needs the same type and seq + 1;
  - total ≤ 0x3f.

  The jump tables (u16 entries, ×4) are at `0x85150` / `0x8518e`.
- **Enumeration** (`input_refresh_cache 0x5d090`), in order:
  1. sidechannel init
  2. W 0x20 = 0
  3. R 0x24 (28)
  4. R 0x25 (28)
  5. secondary MCU: W 0x20 = 1, R 0x24, W 0x20 = 0
  6. R 0x32 (16) → `+0x49c`
  7. R 0x31 (16) → `+0x4ac`
  8. R 3 (16)
  9. R 2 (16)
  10. R 1 (32) → `+0x4dc`
  11. R 0x2f (9)
  12. R 0x0a (8) → `+0x47e`
  13. assert check
  14. optional 0x54 / 0xb6
  15. W 9 = 0 (`0x5e044`)
  16. W 0xa1 = 0 (if `handle+0x4b8d == 0`)
  17. LED refresh queued by `pulsar_devices_changed`

  Timeout 0x960.

**Peripherals (priority 4)**
- **75 µs clamp.**
  - Init `0x16e98..0x16eb0` (p 33333, ot 19, d −9, max_ot 0x4b, max_p 0x7a120).
  - Stored once at `0x16f08/0x16f0e` (`0x20004c28+0xa0/+0xa4`, no other writer).
  - Write case 0x28 `0x27fe6`: `cmp; ite ls`, an unsigned min applied before the validator call at
    `0x2801a`.
- **Validator `FUN_0001fbb8`.** Reject iff ot > max_ot, ot > p or p > max_p (unsigned). No
  minimum-p check, no d check. Copies to `0x200069f8` in a critical section.
- **cmd 0x28.** `{u32 p, u32 ot, i32 d}` at payload +0/+4/+8 (`0x27fdc`). Read case `0x26018`
  returns the applied config (12 B). Host `pulsar_write(…, 0x28, …, 0xc, 0x960)` at `sb 0x5c0b0`.
  Default ot 19.
- **`d` = pulse centre.** `0x156f6 sub.w r3,r2,r3,lsr #1` (offset = d − ot>>1).
  - `FUN_0001873c`: asserts p > 0; lead = max(min_lead, 700) (`cmp #0x2bc; it lo`); t ≡ offset
    (mod p).
  - **Exactly one** `+p` when delta < lead (no loop).
  - min_lead `+0x6c` is never written, so it is 0.
  - "IR LED timeout" is a 1000 ms wait (`0x156b0`).
  - Start CC = t, end CC = t + ot (`0x2949c`).
- **700 µs lead.** CONFIRMED as above.
- **IMU ntf 1** (18 B):
  - u48 translator-time timestamp (`FUN_000250e4`);
  - **accel x, y, z then gyro x, y, z**, i16 raw chip order (driver `0x247b0`: 14-byte read from reg
    0x1d, byte-swapped);
  - table entry `0x2e7dc` id 1 = size 18 × count 6 (`0x612`);
  - temperature in ntf 0x28 on change.
- **Host IMU scaling.** `×f32@+0x4a4×9.80665` and `×f32@+0x4a8×0.017453292…` (`0x57bf8..0x57c70`).
  Timestamp checks 48 000 / 2099 / `(Δ+1000)/2000−1` (`0x58ec8`).
- **cmd 0x32** (16 B):
  - accel range 32000 mg, gyro 4000 dps, ODR 500/500;
  - f32 `1/1024.0` and `1/8.192` (`0x2614c`, sensitivities set at `0x2728c`);
  - ICM-42686 = WHO_AM_I 0x44 → column 1;
  - config `0x2e1fc` indices 0/6/0/6 → codes 0x00/0x0f (±32 g, ±4000 dps, 500 Hz).
- **Input map.** elk `FUN_000173bc`, all bits checked:
  - sample `FUN_00021fd4(0x37, buf, 0x3d)`; CRC-32 over `[0:0x39]` vs `buf+0x39`;
  - ntf 2 = buf[0..3];
  - ntf 3 = `(u16@0x23 & 0xfff) | (u16@0x25 & 0xfff) << 12`;
  - ntf 4 = `{in.1, in.2, in.3, in.0}` (`0x17ab2..0x17ac2`);
  - ntf 9 byte 0 = `b0 b2 b4 c2 b6 b1 b3 b5`, byte 1 = `b7 c3 c0 c1`;
  - ntf 0x15 = u16@0x37;
  - ntf 0x17 bits 0/16/28/40/52.

  Host decode, all 12 ntf 9 bits through the shift tables `{10,5,6,8}` / `{1,4,2,3}`:
  - b0 → ax, b1 → by, b2 → ts, b3 → sys;
  - stick `/32767` if > 0 else `/32768`;
  - trigger = `&0xfff`, grip = `>>12`, each `/4095`;
  - curl `×360/4096`.

  Every label row in PERIPHERALS §4.1 matches.
- **Haptics.** Jump table `0x2803c`:
  - 0x97 → `FUN_0001f968(0, &amp, 1)`;
  - 0xa0 → `{amp, ldrh [+1]}` (LE u16, unaligned) → `FUN_000150fa` accepts `freq−40 ≤ 0x209` (40..561);
  - 0x9b masks n & 0x1f;
  - 0x9d → 31 B;
  - **0x9c → default (unsupported)**.

  Auto-stop: `FUN_0001f8c0` stamps `+0x17c`; in state 2 the thread checks `now − stamp > 0x7d0`
  (`0x1ad68`). Host: 0x97 len 1 (`0x53a88`), 0x9b len 0x20, 0x9c len 4, 0x9d len 0x1f + caps bit 1;
  there is no libsyncboss 0xa0 writer.
