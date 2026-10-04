# Pulsar connected link — host side (RE-1)

What a non-Meta host must **transmit and accept** after pairing, to bring a Touch Plus onto a
connected link and read its registers. Scope = MASTER-PLAN §3.1 items 1–4, 9, 10. This file is
RE-1's; the planner folds confirmed results into PROTOCOL.md.

Status tags: **CONFIRMED** = read directly in code/data. **INFERRED** = strongly implied by code
plus the rest of the protocol. **UNKNOWN** = not established statically; needs a live capture.
Addresses are load-address (see PROTOCOL.md "Images"). Prime new source this pass:
`artifacts/quest/odm/lib64/libsyncboss.so` — the Android host library, an **ELF with a full symbol
table**, so its functions and many structs are named (decompiles cleanly, unlike the stripped
`ruby_prq` firmware). It is the authority for the register layer; `syncboss.bin` is the authority
for the on-air LL/CL framing; `elk-app`/`elk-spl` are the device side we must satisfy.

Tooling: findings reproduced with `tools/ghidra/*` over the flattened images; the register-ID map
and the framing builders are in `tools/pulsar_host.py` (run `python tools/pulsar_host.py selftest`).

---


> **Planner note (2026-10-04): [REVIEW-RE.md](REVIEW-RE.md) corrects this report and takes
> precedence.**
> - R0: the TL header is pinned.
> - R1: the accept slot `[11]` is 1..4.
> - R2: accept endpoint 3 = reject, so send one accept.
> - R3: accept `[12]` = IV flag and `[13]` = slot count, not the version.
> - R4: beacon bit = `1<<S` with TX prefix S+1, no offset.
> - R5: SPL reply `[LEN][status][seq][data]`.
> - R6: Reset `0x2a` after PairingData.
> - R7: the steady counter advances per beacon period.
> - R8: direction 0.
> - R10: seek on channel indices 0/17/36.

## 0. Executive summary — what blocks host mode

| Item | State |
|---|---|
| Pairing wrap vs connected-link negotiation contradiction (§3.1.4) | **Resolved** (§1, = AUDIT A1). Two different crypts: pairing wrap uses a random IV; connected-link negotiation uses a beacon-derived IV (§2a). |
| CCM nonces (negotiation + steady state) | **CONFIRMED** (§2, folds AUDIT A2/A3/A4): CCM is uplink-only; negotiation IV = `session<<48\|ts48`; steady IV = the controller's connection-request bytes 15..22. Counter start/increment needs a live MIC check. |
| SPL on-air command byte | **CONFIRMED** (§5, AUDIT A5) = `(num<<1)\|read`; tool bug fixed (`0x25`/`0x22`, not `0x12`/`0x11`). |
| Register read/write/command mechanism + full register-ID map | **CONFIRMED** (§3). On-air TL **header bytes** still INFERRED. |
| Streaming input vs on-demand registers (two namespaces) | **Resolved** (§3). |
| Notification transport (0x14 wrapper + sidechannel + chunk stream) | **CONFIRMED** (§3, via `.gnu_debugdata`). |
| Connected-link negotiation (both directions) + slot assignment | request + response layouts **CONFIRMED** (§4, incl. AUDIT A3 request table); a few request-body bytes still UNKNOWN. |
| Pairing-link (DM) initiation + post-0x11 behavior | framing **INFERRED**, command bytes + state transition **CONFIRMED** (§5). |
| Single host pairing record (Quest↔dongle switching) | **CONFIRMED** one record (§5.1); re-pair needed to switch; seek timing UNKNOWN. |
| Default AES key / network address | **CONFIRMED** = all-zeros fallback (§6). |

**Nothing here is a hard blocker for a first bring-up.** The residual UNKNOWNs (on-air TL/notification
header bytes; the steady-state counter's start/increment; the seek cadence) are all decided by a
single sniffed connected session from the second dongle, and a host can be built to the CONFIRMED
layouts and corrected against that capture.

---

## 1. §3.1.4 contradiction — RESOLVED (CONFIRMED)

**`syncboss FUN_00047604` is the pairing ECDH wrap, NOT a connected-link negotiation.** Its literal
pool references, read directly, settle it:

- `0x5dda8 "ecdh_pairing.c"`, `0x5dde8 "ECDH"`, `0x5df84 "Calculated shared secret"`,
  `0x5e014 "m_session.pairing_state == PAIRING_STATE_SENDING_KEY"`,
  `0x5de1c "Secure pairing failed. Status %d"`, `0x5dfa0 "encrypted_length >= PULSAR_CRYPTO_MIC_LENGTH"`.

So `FUN_00047604` runs in the host's **pairing** state machine (`ecdh_pairing.c`), on the DM link
(2426 MHz). It is the host mirror of the controller's `elk-spl FUN_00003abc` (the `0x11
PairingData` handler). Q2's "pairing wrap" reading is correct; Q3/HARDWARE-DAY's "grab this IV from
the connected link" is describing a **different** operation.

**The connected link has its own, separate negotiation crypt.** The elk-app string
`0x30479 "Must use legacy nonce for connection negotiation"` is referenced by a guard assert in the
connected-link beacon/CL path (elk-app `fn 0x23e54`, literal at `0x24120`) — **not** in the pairing
SPL. Disassembly of the surrounding function (`0x24090..0x240da`) confirms it is the beacon builder
(`n*2000 + timestamp`, session nonce packed into the timestamp's high 16 bits at `0x240cc`), i.e.
the connected link, not pairing.

**Conclusion:** there are two distinct crypts. They share only "packet counter = 0"; their IVs
differ (so they are genuinely different operations, settling §3.1.4):

1. **Pairing wrap** (DM link, 2426): `syncboss FUN_00047604` ↔ `elk-spl FUN_00003abc`. Wrapping key
   = `shared_secret[:16]`. **8-byte random IV** (RNG `FUN_000185d8`) sent in the clear. Payload
   `[8-byte clear IV][24-byte CCM(20)]`.
2. **Connected-link connection negotiation** (hop channels): a CL packet whose CCM uses a
   **counter-0 nonce with IV derived from the beacon** — `session_nonce<<48 | beacon_ts48` (§2) — not
   a random IV, under the **link key** provisioned in step 1. (The random-IV reading was the pairing
   wrap, item 1; AUDIT A2 re-derived both sides.)

So the two crypts share only "counter 0", not the IV. **AUDIT A1 agrees** `FUN_00047604` is the
pairing wrap alone.

> **Correction for PROTOCOL.md (open item 4):** the claim "the device puts the [session nonce] in
> the top 16 bits of its 64-bit CCM packet counter (elk-app `0x240cc`)" is **wrong**. `0x240cc`
> (`add.w r3, r3, r4, lsl #16`) packs the 16-bit session nonce into the high bits of the 48-bit
> **beacon timestamp**, which is then used **as the negotiation IV** (`session_nonce<<48|ts48`, §2),
> not the CCM packet counter.

---

## 2. CCM nonces — the host as PRODUCER / CONSUMER (CONFIRMED, folds AUDIT A2/A3/A4)

**CCM is UPLINK ONLY (AUDIT A4):** beacons and the host's downlink/CL data are **plaintext**; only
the device→host uplink is encrypted (plaintext-uplink bypass flag at elk LL `+0x29c`). So a host
*transmits* downlink in the clear and only needs to *decrypt* uplinks — the direction bit is
effectively fixed to the uplink value for everything we verify. This also means the beacon header
and the connection-response §4 are built in clear (consistent with `FUN_0001cf30` having no crypt
call).

The nonce packing must still be exact to check the uplink MIC. nRF hardware AES-128-CCM
(`pulsar_crypto.c`); the software crypt helper is `syncboss FUN_0001b1a4`, whose register writes
(disasm `0x1b1a4..0x1b240`) pin the config block relative to `CNFPTR`:

| CCM config field | offset | bytes | written by (`FUN_0001b1a4`) |
|---|---|---|---|
| KEY | `+0x110` | 16 | set at CCM setup (`FUN_0001b0a4`) = the link key from pairing |
| PACKETCOUNTER | `+0x120` | 5 LE | `strd sb,r8,[r7,#0x120]` (low 32 + next byte; asserts 5th byte `< 0x80`, so 39-bit) |
| DIRECTION | `+0x128` | 1 | bit0 = host(0)/device(1) |
| IV | `+0x129` | 8 | `str r0,[r7,#0x129]` + `str r1,[r7,#0x12d]` (8 bytes) |

So the **13-byte CCM nonce = PACKETCOUNTER[5, little-endian] ‖ IV[8]**, with the direction bit as
bit 0 of the counter's first byte region (BLE-CCM convention; the `+0x128` DIRECTION byte feeds the
hardware). CCM MODE word at `+0x504 = 0x01010000`; MIC = 4 bytes (crypt returns `len + 4`). This
matches PROTOCOL Q3 exactly and is **CONFIRMED**.

There are **two IV regimes** (AUDIT A2/A3, CONFIRMED both sides; host `FUN_0001aba8` @ `0x1aba8`,
elk `0x24092..0x240d6`, connection-request builder elk `0x23bc4`):

**(a) Negotiation / "legacy" nonce (A2) — decrypts the controller's FIRST uplink.**
- `PACKETCOUNTER = 0`.
- `IV (u64 LE) = session_nonce << 48 | beacon_ts48`, where `session_nonce` = beacon bytes 6..7 and
  `beacon_ts48` = beacon bytes 8..13 of the beacon that started the period. **Nothing is on air** —
  the host (and a sniffer with the key) derives the whole nonce from the beacon.
- 13-byte nonce = `00 00 00 00 00 ‖ ts[0..5] LE ‖ session_nonce LE`.
- Host mirror: `FUN_0001aba8` returns `ts48 | session_nonce<<48`; its callers (`FUN_0001da8c`
  case 1, `FUN_0001e2dc` case 1) pass it as the IV with counter 0 **when the per-slot IV
  (`LL+0xf10+slot*8`) is still 0** (i.e. before the steady IV is known).

**(b) Steady-state nonce (A3) — all subsequent uplinks.**
- `IV` = the **8 bytes the controller sends in its connection request**, at CL payload bytes
  **15..22** (elk record `+0x68`; §4). The host reads them out of the (negotiation-decrypted)
  request and stores them per slot. **This replaces the earlier "reuse the negotiation IV" guess.**
- `PACKETCOUNTER` = a **per-slot** counter (elk LL state, reset at accept — `FUN_00028ad0`) that
  advances per uplink packet.
- **Still needs one live MIC check (non-blocking):** the counter's exact start value and the moment
  it first increments. `tools/pulsar_crypto.py scan --key <k> --iv <the 8 request bytes>
  --capture conn.jsonl` pins it; for the negotiation packet, `scan` reads session+ts from the
  preceding AP1 beacon automatically.

`tools/pulsar_host.py` exposes `legacy_nonce(session_nonce, beacon_ts48)` (a) and
`steady_state_nonce(counter, iv, direction=0)` (b; direction is 0, REVIEW-RE R8), plus `parse_conn_request()` to pull the steady
IV out of the connection request; all with selftests. `pulsar_crypto.py` `candidate_nonces` /
`scan` lead with these two regimes (A8 fixes: S0-aware header strip, AAD = `S0 & 0xE3`, beacon
tracking, a real AES-CCM MIC selftest).

---

## 3. Register access (CL/TL) — read / write / command (CONFIRMED map)

### Two register namespaces (this resolves the Q4 "battery = 0x15 vs 0x2f" tension)

1. **Streaming input** (buttons, analogs, touch, IMU). Pushed by the controller every cycle, not
   polled. elk packs its *internal* host-register table (buttons=9, analogs=3/0x17, battery=0x15,
   IMU=0xb/0x16 — PROTOCOL Q4, from `elk-app FUN_000173bc`) into a report that arrives host-side via
   `libsyncboss process_beacon_mode_pulsar_data` / `syncboss_stream_register_handler`. This is
   RE-2's / `pulsar_input.py`'s domain.
2. **On-demand command registers** (this section). A request/response "packet register" space with
   its own IDs, read/written with `pulsar_manager_read_sync` / `pulsar_manager_write_sync`
   (libsyncboss `pulsar_manager.c`). **Different numbering** from the streaming hreg space above.

Both ride the same connected link; they do not share IDs. "battery = 0x15" (streaming) and
"battery voltage query = 0x2f" (command) are two different mechanisms, not a contradiction.

### Command-register ID map (CONFIRMED — from symbol-named libsyncboss callers)

Each row: a literal `reg_id` passed to `pulsar_manager_{read,write}_sync(input_id, reg_id, req,
req_len, resp, &resp_len)`, tagged by the exported function that issues it.

| reg | R/W | operation (libsyncboss symbol) |
|---|---|---|
| 0x05 | W | `syncboss_input_shutdown` |
| 0x06 | W | `syncboss_input_sleep` / `syncboss_input_wake` |
| 0x0b | R | `syncboss_input_platform_attachment_info` |
| 0x0c | R/W | `syncboss_input_platform_attachment_auth_{read,write}` |
| 0x13 | W | `syncboss_input_unpair` |
| 0x19 | W | `syncboss_input_console_cmd` |
| 0x1a | W | `syncboss_input_console_cmd` |
| 0x1c | W | `syncboss_input_set_carrier` |
| 0x28 | R | `syncboss_input_get_led_config` |
| 0x2b | R | `syncboss_input_get_calibration_data` (req carries `type` at +5, 8 bytes) |
| 0x2f | R | `syncboss_input_get_battery_voltage` / battery-pack |
| 0x33 | R | `syncboss_input_get_imu_temp` |
| 0x34 | R | `syncboss_internal_input_get_assert_info` |
| 0x38 | R | `syncboss_input_get_backtrace` |
| 0x3f | R | `syncboss_internal_input_get_build_hash` |
| 0x4c | R/W | `syncboss_input_{get,set}_thumbstick_user_calibration` |
| 0x4e | W | `syncboss_input_clear_thumbstick_user_calibration` |
| 0x4f | R/W | `syncboss_input_{get,set}_thumbstick_user_deadband_percentage` |
| 0x50 | R/W | `syncboss_input_{get,set}_adc_stream_enable` |
| 0x53 | R/W | `syncboss_internal_input_get_battery_pack` / `set_battery_pack_pollrate` |
| 0x9f | W | `syncboss_input_imu_integration_uplink` |
| 0xab | R | `read_hid_report_descriptor` (**a HID descriptor IS readable as a register**; see note) |
| 0xac | R/W | `syncboss_input_hid_feature_report_{read,write}` |
| 0xb4 | W | `syncboss_input_stream_rf_perf` |

> **Note (correction nuance for PROTOCOL Q4).** Q4 says "there is NO HID report descriptor". That is
> true of the *controller firmware's own input packing*, but libsyncboss reads a descriptor from
> **command register `0xab`** (`PULSAR_PKT_ID(hid_report_descriptor)`, with device IDs
> `HID_DEVICE_ID_ATTACHMENT` / `HID_DEVICE_ID_CALDERA`) and feature reports from `0xac`. So a
> descriptor exists as a *readable register value*, built by the host SoC/attachment layer, not as a
> fixed table in elk. Pinning its bytes is RE-2's input-map work; noted here only to correct the
> absolute phrasing.

LED config read = `0x28`; LED *timing set* is a separate manager call (`pulsar_manager_set_led_timing`
/ `set_led_ontime_us` / `set_led_period_delay_us`) — RE-2 owns the on-wire LED command.

### Request / response transport (CONFIRMED lengths; on-air header INFERRED)

The Android→MCU request is a `spi_data_pulsar_data_t` (libsyncboss `pulsar_read_nolock` /
`pulsar_write_nolock_internal`): a fixed **0x14-byte (20) header** + up to a payload, with
`sizeof(spi_data_pulsar_data_t) + len <= WIRELESS_MAX_PAYLOAD_SIZE`. Read `in_len <= 0xeb` (235);
write `len` such that `0x14 + len <= 0xff`. The `reg_id` byte passes through to the MCU unchanged
(`pulsar_read_nolock` places `param_3` into the struct, `read_nolock` asserts
`(sizeof(*pdata) + in_len) <= WIRELESS_MAX_PAYLOAD_SIZE`). The MCU then frames the **over-air TL
packet** (`syncboss pulsar_tl_host.c`, `TL_HOST_MAX_PAYLOAD_LEN`). The exact on-air TL header bytes
(request/response tag, reg_id position, length, sequence) are **UNKNOWN** statically — they live in
the elk-app TL command dispatcher, which the stripped `ruby_prq` image does not split cleanly, and a
dongle host can match them from one sniffed register exchange. What is **CONFIRMED** is the
semantic contract: `(reg_id, request-bytes) → (response-bytes)`, with the IDs above.

### Notifications / subscribe (CONFIRMED framing, using the `.gnu_debugdata` symbols)

`libsyncboss.so` carries a `.gnu_debugdata` (xz MiniDebugInfo) section = **1044 internal symbol
names** (section [23], file off `0x9fe1c`; extract with `lzma.decompress`; Ghidra 12 reads it
automatically, so the decomp is already named — RE-2 flagged this). With those names the
device→host notification path is pinned, `controller_process_notification @ 0x57324`
(`syncboss_hal_input_controller.c`):

A received notification is `[0x14-byte header][optional sidechannel chunk][ntf chunk stream]`:

- **0x14-byte header (host↔MCU wrapper, CONFIRMED).** `len >= 0x14` (else `"Controller
  notification data length too small"`), and **byte `0x13` must be `0`** or the packet is not a
  normal chunk notification. This is the MCU→Android `spi_data` wrapper — the **same 0x14-byte size
  as the request-side `spi_data_pulsar_data_t`** (§3 transport) — **not** the over-air header; a
  dongle host emits the over-air CL/TL header instead (still the UNKNOWN above). The header's
  interior fields are MCU-side and not inspected here beyond `+0x13`.
- **Optional sidechannel chunk (CONFIRMED present; inner ARQ framing INFERRED).** When the session
  enables it (`(conn+0xd2)==0 && (state+0x47e & 1)==0`), a sidechannel chunk of
  `sidechannel_client_get_chunk_size()` bytes (`@0x114fe8`, a configured fixed size, default 0 =
  none) sits **right after** the 0x14 header and is consumed by `controller_handle_sidechannel_chunk
  @ 0x58b0c` / `sidechannel_client_process_chunk @ 0x114d00` before the chunk stream. Its first byte
  is flags (bit0 = start-of-message, bit1 = sequence parity), byte 1 = length — a fragmented-message
  ARQ, used for blobs (host blob / attachment auth), not per-frame input.
- **ntf chunk stream (end-to-end payload, CONFIRMED — the part a dongle host must produce/consume).**
  `ntf_unpacker_start @ 0x12e60` / `ntf_unpacker_next @ 0x12e74` iterate little-endian **u16-header
  chunks**; chunk **type = `(h>>6 & 0x20) | (h&0x1f)` = the ntf register id**, length =
  `(h>>5)&0x3f` (0..63), with fragment seq in bits 12..14 and last-fragment in bit 15 (full table in
  PERIPHERALS.md §1.1 — RE-2's; `pulsar_input.py unpack_chunks`). Type 1 = IMU (18 B), 0xb = 12 B,
  3 = 3 B, etc. Unknown types are rate-limit-logged `"Unknown chunk type %d"` and skipped.

So for host mode the **chunk stream framing is fully pinned** and travels end-to-end; only the
over-air CL/TL header that *carries* the chunk stream (the MCU strips/adds it) is the residual
UNKNOWN, decided by the same single capture as the read/write TL header. `tools/pulsar_host.py
split_notification()` strips the 0x14 wrapper + sidechannel and hands the chunk stream to
`pulsar_input.unpack_chunks`.

---

## 4. Connected-link bring-up + slot assignment

### Device-side accept rules (CONFIRMED — the authority for what the host must send)

The controller's connection-negotiation accept handler is `elk-app fn 0x23aa8` (references
`0x303b9 "accept_pkt->endpoint != CONN_NEG_SLOT"` at code `0x23c40`). It validates, on the host's
connection packet: `[0] == 1` (type), `[2] & 7` = endpoint (**2 = CONN_NEG, 3 = lock**), `[3..10]` =
the controller's 64-bit device ID (vs its connection record `0x20004ec0 +0/+4`), `[11]` = assigned
slot (assert `0x31ba1 "slot < (PULSAR_NUM_DEVICE_SLOTS + PULSAR_NUM_AUXILIARY_DEVICE_SLOTS)"`). The
record also holds the **Pulsar version `0x1701`** at `+8` (set at `0x18b90`), echoed into the
outgoing response. See PROTOCOL Q6.

**So the host, to accept a seeking controller, emits (in the beacon CL-data area) a negotiation
packet carrying:** byte0 = 1, byte2 = endpoint (first `2` = CONN_NEG, then `3` = lock on the
follow-up), bytes 3..10 = the controller's 64-bit device ID, byte 11 = the slot we assign, and the
protocol version `0x1701`. Advertise `0x1701` and **never reject the controller** (PROTOCOL Q6).
`tools/pulsar_host.py build_conn_negotiation()` builds this.

### Device→host connection REQUEST (CONFIRMED, AUDIT A3 — carries the steady IV)

Before the host responds, the **controller transmits a connection request** (uplink, CCM-encrypted
with the negotiation nonce §2a). The host decrypts it, then parses it in `FUN_0001d038`
(note `[0] == 0` here, which is how `FUN_0001d038` knows it is a request, **not** the `[0] == 1`
response above). CL payload, LENGTH `0x19` = 25, built at elk-app `0x23bc4..0x23c22` from connection
record `0x20004ec0`:

| CL byte | content |
|---|---|
| 0 | `0` (request discriminator) |
| 1 | `0x11`; the host reads `[1] >> 3` (= 2) as a format version — non-zero means bytes 0x0e..0x18 present |
| 2..9 | 64-bit controller device ID (record +0/+4) |
| 10..13 | record +8 word: `0x1701` version (bytes 10..11 = `01 17`) + record +0xa/+0xb |
| 14 | slot count (record +0x71, or 1 if record +0x70 == 0) |
| **15..22** | **8-byte steady-state IV, u64 LE (record +0x68)** — the §2b IV |
| 23 | RADIO `+0x50c` + a global byte (UNKNOWN) |
| 24 | global byte at `0x200000b0` (UNKNOWN) |

The host stores the key+IV per slot (`FUN_0001d038 → FUN_0001e90c`), keyed per device. Parse it with
`tools/pulsar_host.py parse_conn_request()` (extracts device id, version, and the 8-byte steady IV).

### Host-side state machine (CONFIRMED functions; exact TX offsets INFERRED)

- **`pulsar_cl_host.c` init** = `syncboss FUN_0001d300`: installs four callbacks the host must
  provide — `prepare_beacon_handler`, `packet_rx_handler`, `connection_change_handler`,
  `connection_request_handler` (asserts at `0x1d300` name each). A host firmware needs all four.
- **Inbound connection request parse** = `FUN_0001d038` (refs `0x50450 "Unknown connection
  response"`, `0x50410 "Unable to allocate endpoint, ignoring request from %08lx%08lx"`). It reads
  the device's request fields (type/flags byte, 64-bit device UUID, a slots-requested byte near
  offset 0xe, extra address words), allocates an endpoint/slot, and stages the response into the
  host connection record at `+0x74..+0x81` (`+0x76` = endpoint|flags, `+0x77` = peer, `+0x7f` =
  slot, `+0x81` = slot count). Exact request byte offsets are INFERRED (stripped-side cross-check
  pending); the device-side accept rules above are the firm contract.
- **Slot / endpoint allocator** = `FUN_0001d4d8` (+ `connection_tracker.c` `FUN_0001d8d4` /
  `FUN_0001d910`, `endpoint_allocator.c`). **Two distinct, both-CONFIRMED indices — do not
  conflate them; their exact correspondence is the one slot fact a live capture must settle:**
  - **radio slot, 0-based (0..4).** The negotiation slot byte `[11]` is asserted `< PULSAR_NUM_
    DEVICE_SLOTS + PULSAR_NUM_AUXILIARY_DEVICE_SLOTS = 5` (elk-app `0x31ba1`), and the device TX
    prefix = `slot + 1 = 0x01..0x05` (PROTOCOL Q1). So the slot assigned in the negotiation packet
    is 0..4 and the controller will transmit on prefix slot+1.
  - **CL endpoint, 1-based (1..4).** `TRANSPORT_ENDPOINT_START = 1`, `endpoint < END`
    (`FUN_0001d8d4` rejects `endpoint == 0`, requires `< 5`), tracked in a bitmap at connection
    record `+0x4`. The beacon **byte-14 downlink bit and byte-15 ack bitmap are `1 << endpoint`**
    over these 1..4 endpoints (`FUN_0001cf30`/`FUN_0001d738` return the endpoint 1..4;
    `FUN_0001cdcc` sets bit `endpoint`).
  - A requested run of contiguous slots is honored (`slot + slots_requested <=
    PULSAR_NUM_DEVICE_SLOTS_TOTAL`); auxiliary slots are single (`slot >=
    PULSAR_NUM_AUXILIARY_DEVICE_SLOTS || slots_requested == 1`). **Whether CL endpoint == radio
    slot, or endpoint == slot + 1, is INFERRED and needs one capture** — the tool keeps the two as
    separate parameters rather than assuming a mapping.
- **Beacon builder** = `FUN_0001cf30` (`prepare_beacon`, asserts `0x503dc "tx_beacon.len <=
  CL_HOST_MAX_PAYLOAD_LEN"`, max `0x22 = 34`). Two shapes, **CONFIRMED**:
  - normal beacon: **byte 14** = `1 << slot` of the device addressed by this beacon's downlink data
    (else 0); **byte 15** = the rx/ack bitmap accumulated since the last beacon (conn `+0xf3`, then
    cleared). Matches PROTOCOL Q1.
  - **connection-negotiation beacon**: when a response is pending it copies a 26-byte body from the
    connection record (`+0x74..`) into the CL data area and sets the CL length to `0x24 = 36` — the
    "36-byte connection-negotiation variant" PROTOCOL Q1 mentions. This body is the negotiation
    packet §4 describes; its field offsets within the 26 bytes are INFERRED (confirm on air).
  - `rx-mask` marking (device uplink heard) = `FUN_0001cdcc` (`mark_rx_mask`, sets bit `slot` of conn
    `+0xf3`) — CONFIRMED.

`tools/pulsar_host.py` builds/parses the **connection-negotiation packet** to the device-side
contract (type, endpoint, 64-bit ID, slot, version) and the **beacon header** (bytes 0..15 incl. the
byte-14 downlink-slot bit and byte-15 ack bitmap), with round-trip selftests.

---

## 5. Pairing-link (DM) initiation + post-0x11 behavior

- **DM link open (INFERRED, from PROTOCOL Q1 + libsyncboss symbols).** Host enumerates advertisers
  (`pulsar_manager_enumerate_advertising_devices`, `wait_for_dm_device`), then
  `syncboss_pulsar_dmm_connect` / `syncboss_hal_input_dmm_connect` opens the DM link on **2426 MHz**,
  base = the controller's `DEVICEID[0]` (advert bytes 5..8 as LE u32), prefix `0xAA`, S0 off,
  MAXLEN 255 (PROTOCOL Q1). The advertisement carries DM flags libsyncboss decodes:
  `PULSAR_DM_FLAG_ECDH_PAIRING`, `_APP_REQUEST`, `_USER_RESET`, `_CORRUPT_APP`, `_ASSERT_SET`,
  `_IS_SPOOFING` — presence of `ECDH_PAIRING` is the "this device will do our anonymous pairing" cue
  (`"Pulsar device type 0x%x does not support ECDH pairing."` is the reject). The DM framing is a
  host-polled ping-pong `[ctrl][seq][data…]` (PROTOCOL Q2 "DM link and SPL framing"); INFERRED.
- **SPL command framing (CONFIRMED, PROTOCOL Q2 + AUDIT A5).** Frame = `[LENGTH][cmd][seq][payload]`.
  The `cmd` byte encodes a command **number** and a read/write bit: the dispatcher `elk-spl
  FUN_0000822c` does `ldrb r1,[r0],#2` (first byte), `ands #1` (bit0 = read/write), `ubfx r1,#1,#6`
  (number in bits 1..6). **On-air byte = `(number << 1) | read_bit`** — the earlier tool put the raw
  number on air, which decodes as the wrong command (**pairing could not work**). Verified bytes:

  | command | number | on-air byte |
  |---|---|---|
  | SetupX25519Keys (read; carries the 32-byte host pubkey) | 0x12 | **`0x25`** |
  | PairingData (write) | 0x11 | **`0x22`** |
  | 0x1d PairingData-derived (write) | 0x1d | **`0x3a`** |
  | WriteAESKey | 0x14 | `0x28` (stub in this SPL) |
  | Reset | 0x15 | `0x2a` |

  `0x22 PairingData` payload = `[8-byte clear IV][24-byte CCM(20)]`; plaintext `[4-byte base][16-byte
  key]`. The **reply** command-byte format is UNKNOWN (the pubkey reply is a 0x20-byte payload).
  `tools/pulsar_host.py` now encodes `(num<<1)|read` in `frame_spl`/`spl_cmd_byte` and no longer
  asserts the reply byte.
- **0x11 vs 0x1d (AUDIT A7).** A real Quest sends **`0x1d` first** (derived key = `shared_secret[:16]`)
  and falls back to `0x11`. TouchFrame uses **`0x11`** so we choose the link key; both reach the same
  `[base][key]` store. `build_pairing_data(..., num=CMD_PAIRING_DATA_DERIVED)` builds the 0x1d form if
  ever needed.
- **CRC byte order (item 10, AUDIT A9) — caveat, not a code change.** On air the nRF RADIO computes
  and appends the 24-bit CRC in **hardware** (CRCCNF, poly `0x108421`, init `0xFFFFFF`, SKIPADDR=0);
  a dongle host does **not** hand-assemble it. For *offline* verification the firmware feeds the
  access address **LSbit-first** (bit-reverse each of the 4 base bytes LE + the prefix, then
  S0/LENGTH/payload unreversed — elk `FUN_00024164 → FUN_00022ab8`, table at `0x316f8`). The tool now
  has `crc24_air(base, prefix, data)` doing this; the old selftest fed the raw (un-reversed) address.
  The on-air CRC trailer byte order (MSB-first under ENDIAN=big) is still INFERRED, a capture item.
- **What the controller does after `0x11` (CONFIRMED state + INFERRED reboot).** `elk-spl
  FUN_00003abc`: requires pairing state `>= 3`, computes the shared secret (`FUN_000093c0`, flag 0),
  decrypts the 24→20 bytes (`FUN_00009198`, asserts `== 0x14`), stores `[base][key]` via
  `FUN_000038e8`, then **sets the pairing state to `5`** (`*pbVar2 = 5`) and zeroes the key buffers
  (`FUN_000039bc`). State 5 = pairing complete; the DM session then tears down and the controller
  returns to its connected-link app (reboot/jump-to-app is INFERRED — the explicit `Reset 0x15`
  handler `FUN_00002a04` exists for an forced restart, but 0x11 itself only advances the state).

### 5.1 Multi-host pairing — can a user switch between Quest and dongle? (planner's question)

**The Touch Plus keeps a SINGLE host pairing record (CONFIRMED).** `elk-spl FUN_000038e8` stores into
one `m_pairing` record (`*0x20000324`): it erases the existing record first (`FUN_000038a8` present-
check → `FUN_00006054`), then writes the 20-byte `[base][key]` at record `+0`, and a second copy of
the 16-byte key at record `+0x14`, via the nRF flash writer (`FUN_00006090`, `nrf52_flash.c`). There
is **no array and no index** — one slot, flash-backed.

- **So pairing to our dongle OVERWRITES the Quest pairing (INFERRED, strong).** A single record means
  the controller can be bonded to exactly one host at a time. After pairing to the dongle it stores
  the dongle's netaddr+key and has discarded the Quest's.
- **Switching back to the Quest requires re-pairing (INFERRED).** And re-pairing to the Quest would
  then evict the dongle. Users cannot hop between the two without a re-pair each way.
- **Post-power-cycle seek (netaddr from the record; timing/give-up) — UNKNOWN, needs a live test.**
  The connected app seeks the stored netaddr (the record's base address) and must hear a beacon
  matching it (hop/`INVALID_HOST_PULSAR_VERION` gating, PROTOCOL Q6); the exact seek cadence, how
  long it searches, and the give-up/advertise-for-pairing fallback are in the connected-link seek
  state and are **not pinned statically** — settle on hardware.

> This is a product constraint worth surfacing: TouchFrame users will re-pair their Touch Plus to the
> dongle (losing the Quest bond) and re-pair to the Quest to go back. A dual-bond "just works" switch
> is not possible with one record. (If this matters, a future option is to re-provision the record
> each boot, but that is firmware work, not static RE.)

---

## 6. Default AES key / network address (item 10, optional) — CONFIRMED

`libsyncboss pulsar_manager_init_and_start` reads three persisted blobs, each with a logged
fallback: `/persist/pulsar/pulsar_host_address.bin` (4-byte network address),
`/data/misc/pulsar_whitelist_v3.bin` (0xC1 bytes), `/data/misc/pulsar_aes_key.bin` (16 bytes).

On any read failure the code logs `"… (continuing with default)"` and **leaves the pre-zeroed stack
buffer in place** — there is no baked-in constant key or address. So the **default link key = 16
zero bytes** and the **default network address = `0x00000000`**. (Confirmed by control flow: the key
buffer `(&local_150 | 4)` and the 4-byte address are zeroed before `fopen`; on `fopen`/`fread`
failure the code jumps straight to the log call without writing them.)

**Consequence:** a Quest with no provisioned key file runs on an all-zero link key — so its sessions
are decryptable with a zero key (item 10 "decrypt a default Quest" = CONFIRMED feasible). For
**TouchFrame host mode this is moot**: we choose our own key at pairing (`0x11`), so we never depend
on the default.

---

## Open items handed on

- **Live-capture-only (non-blocking):** (a) the steady-state counter's start value and increment
  point (IV origin itself is now pinned, §2b/A3); (b) the exact on-air TL/notification header bytes —
  §3; (c) the post-power-cycle seek cadence/give-up (§5.1); (d) the on-air CRC trailer byte order
  (§5/A9). All fall out of one sniffed connected session (second dongle).
- **A20 (open, for the host RX path):** which key the host loads to decrypt a controller that was
  paired with `0x1d` (per-device derived key) when it seeks on slot 0 — the host's slot-0 key is set
  once from `pulsar_host_init`'s global key (`FUN_0001d300 → FUN_0001e8b0(0, key, 0, 0)`); it may
  reload per candidate in `FUN_0001e2dc` case 2, or an upper layer reprograms it. **Moot for our
  host** (we pair with `0x11` and one global key), so not a blocker; settle before supporting
  dongle-side re-pair of a Quest-bonded controller.
- **For the planner (PROTOCOL.md corrections):** the `0x240cc` session-nonce-in-CCM-counter claim is
  wrong — it is the negotiation IV `session<<48|ts48` (§1/§2a); CCM is uplink-only (§2/A4); the SPL
  on-air command byte is `(num<<1)|read` not the raw number (§5/A5); add the command-register
  namespace + ID map and the "HID descriptor is register 0xab" nuance to Q4 (§3); fold the §3.1.4
  resolution and the single-pairing-record constraint (§5.1) in. These all match AUDIT A1–A5/A8/A9.
- **For BUILD-1:** the four CL host callbacks (`FUN_0001d300`), the radio-slot domain (0..4, TX
  prefix slot+1) vs the CL-endpoint domain (1..4, beacon `1<<endpoint`), beacon bytes 14/15, and the
  negotiation packet contract (§4) are enough to stub the connection state machine; leave the TL
  header bytes **and the endpoint↔slot correspondence** as parameters to fill from the first capture.
