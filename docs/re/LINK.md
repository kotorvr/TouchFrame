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

## 0. Executive summary — what blocks host mode

| Item | State |
|---|---|
| Pairing wrap vs connected-link negotiation contradiction (§3.1.4) | **Resolved** (§1). Two different crypts on two different links; both use a counter-0 random-IV "legacy" nonce. |
| Steady-state CCM nonce structure | **CONFIRMED** (§2). One field (session-nonce role) still needs a live MIC check. |
| Register read/write/command mechanism + full register-ID map | **CONFIRMED** (§3). On-air TL **header bytes** still INFERRED. |
| Streaming input vs on-demand registers (two namespaces) | **Resolved** (§3). |
| Connected-link connection-negotiation, slot assignment | device-side accept rules **CONFIRMED**; exact host-TX byte offsets **INFERRED** (§4). |
| Pairing-link (DM) initiation + post-0x11 behavior | framing **INFERRED**, state transition **CONFIRMED** (§5). |
| Default AES key / network address | **CONFIRMED** = all-zeros fallback (§6). |

**Nothing here is a hard blocker for a first bring-up.** The two residual UNKNOWNs (exact on-air TL
header bytes; which steady-state nonce packing is live) are both decided by a single sniffed
connected session from the second dongle, and a host can be built to the INFERRED layout and
corrected against that capture.

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

**Conclusion:** there are two distinct crypts that share one nonce *style* (packet counter = 0, an
8-byte random IV sent in the clear):

1. **Pairing wrap** (DM link, 2426): `syncboss FUN_00047604` ↔ `elk-spl FUN_00003abc`. Wrapping key
   = `shared_secret[:16]`. Payload `[8-byte clear IV][24-byte CCM(20)]`.
2. **Connected-link connection negotiation** (hop channels): a CL packet whose CCM also uses a
   counter-0 random IV, under the **link key** provisioned in step 1. This is the IV HARDWARE-DAY §5
   means — it is on air **on the connected link during negotiation**, not (only) during a re-pair.

So both prior statements were right about different links. **For host mode we are the producer of
both**, so we choose both IVs; nothing needs to be sniffed to *build* them. A sniff is only needed
to *decode a real Quest's* steady-state traffic (§2).

> **Correction for PROTOCOL.md (open item 4):** the claim "the device puts the [session nonce] in
> the top 16 bits of its 64-bit CCM packet counter (elk-app `0x240cc`)" is **wrong**. `0x240cc`
> (`add.w r3, r3, r4, lsl #16`) packs the 16-bit session nonce into the high bits of the 48-bit
> **beacon timestamp**, not the CCM packet counter. The CCM counter is written only by the crypt
> helper (§2). The session nonce's role in steady-state CCM is therefore **UNKNOWN** statically.

---

## 2. Steady-state CCM nonce — the host as PRODUCER (CONFIRMED structure)

The host must emit valid 4-byte MICs, so the nonce packing must be exact. nRF hardware AES-128-CCM
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

**Negotiation nonce (both links):** counter = 0, 8-byte random IV in the clear
(`FUN_00047604`: RNG `FUN_000185d8` → IV, `param_7 = param_8 = 0`).

**Steady-state packing (host must produce) — INFERRED, one field UNKNOWN:**
- IV = the 8 random bytes established at the connected-link negotiation (sent in the clear in the
  negotiation CL packet). `FUN_00047604` copies its negotiation IV from `+0x88` to `+0x99`
  immediately after the crypt, which is exactly what saving a session IV for reuse looks like.
- PACKETCOUNTER = a per-direction packet counter that **advances by 1 per encrypted packet**,
  starting at (near) 0 after negotiation.
- DIRECTION bit distinguishes host→device from device→host so the two counters never collide on one
  nonce.
- **UNKNOWN:** whether the 16-bit beacon session nonce also seeds the counter's high bits. Static RE
  does not show it feeding `+0x120..+0x124`. Decide with one captured packet:
  `tools/pulsar_crypto.py scan --key <k> --iv <IV from the negotiation packet> --capture conn.jsonl`
  — a correct MIC pins key+IV+counter+direction. The tool already leads with the IV-reuse hypothesis.

`tools/pulsar_host.py` exposes `steady_state_nonce(counter, direction, iv)` (thin wrapper over the
shared `pulsar_crypto.nonce_from_fields`) and a round-trip selftest against the same CCM primitives.

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

### Notifications / subscribe (CONFIRMED mechanism, INFERRED framing)

Device→host asynchronous notifications exist: libsyncboss `pulsar_host_get_notification`
("Get the last notification the Host received"), `pulsar_notifications` / `pulsar_lp_notifications`
counters, and a typed handler `controller_process_irled_config_ntf_data(…, const
ntf_reg_irled_config_t *)` plus `controller_handle_sidechannel_chunk`. So the host receives
register-change notifications (e.g. the IR-LED config) as a distinct message class, dispatched by
register id — `"Unexpected controller notification register %i"` and `"Controller notification data
length too small"` are the reject paths. The host-mode dongle must accept and surface these; the
exact on-air notification header is the same UNKNOWN as the TL header above.

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
  `FUN_0001d910`, `endpoint_allocator.c`): **CONFIRMED** — slots are endpoints `1..4`
  (`TRANSPORT_ENDPOINT_START=1`, `< 5`), i.e. `PULSAR_NUM_DEVICE_SLOTS_TOTAL` usable device slots,
  tracked in a bitmap at connection-record `+0x4`. Device TX prefix = `slot + 1` (PROTOCOL Q1:
  `0x01..0x05`). A requested run of contiguous slots is honored
  (`slot + slots_requested <= PULSAR_NUM_DEVICE_SLOTS_TOTAL`); auxiliary slots are single
  (`slot >= PULSAR_NUM_AUXILIARY_DEVICE_SLOTS || slots_requested == 1`).
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
  host-polled ping-pong `[ctrl][seq][data…]` (PROTOCOL Q1 "Pairing link framing"); INFERRED.
- **SPL command framing (CONFIRMED, PROTOCOL Q2):** 2-byte SPL header `[cmd][seq]` then payload. The
  `0x11 PairingData` payload = `[8-byte clear IV][24-byte CCM(20)]`; plaintext `[4-byte base][16-byte
  key]`. `tools/pulsar_host.py` already builds/parses this.
- **CRC byte order (item 10) — caveat, not a code change.** On air the nRF RADIO computes and appends
  the 24-bit CRC in **hardware** (CRCCNF, poly `0x108421`, init `0xFFFFFF`, SKIPADDR=0, transmitted
  per the nRF big-endian-on-air convention); a dongle host does **not** hand-assemble it. The manual
  `crc24()` in `pulsar_host.py` is for **offline frame verification only**; its `to_bytes(3,
  "little")` packing is a convenience for that offline check and is a hardware-day validation item,
  not an on-air claim. Left as-is with this note.
- **What the controller does after `0x11` (CONFIRMED state + INFERRED reboot).** `elk-spl
  FUN_00003abc`: requires pairing state `>= 3`, computes the shared secret (`FUN_000093c0`, flag 0),
  decrypts the 24→20 bytes (`FUN_00009198`, asserts `== 0x14`), stores `[base][key]` via
  `FUN_000038e8`, then **sets the pairing state to `5`** (`*pbVar2 = 5`) and zeroes the key buffers
  (`FUN_000039bc`). State 5 = pairing complete; the DM session then tears down and the controller
  returns to its connected-link app (reboot/jump-to-app is INFERRED — the explicit `Reset 0x15`
  handler `FUN_00002a04` exists for an forced restart, but 0x11 itself only advances the state).

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

- **Live-capture-only (non-blocking):** (a) which steady-state nonce packing is live (IV reuse vs
  session-nonce-in-counter) — §2; (b) the exact on-air TL/notification header bytes — §3; (c) the
  exact byte offsets inside the connection-request and the 26-byte negotiation body — §4. All three
  fall out of one sniffed connected session (second dongle).
- **For the planner (PROTOCOL.md corrections):** the `0x240cc` session-nonce-in-CCM-counter claim is
  wrong (§1); add the command-register namespace + ID map and the "HID descriptor is register 0xab"
  nuance to Q4 (§3); fold the §3.1.4 resolution into Q2/Q3.
- **For BUILD-1:** the four CL host callbacks (`FUN_0001d300`), slots = endpoints 1..4, device TX
  prefix = slot+1, beacon bytes 14/15, and the negotiation packet contract (§4) are enough to stub
  the connection state machine; leave the TL header bytes as a parameter to fill from the first
  capture.
