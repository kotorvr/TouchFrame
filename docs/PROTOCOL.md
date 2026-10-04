# Touch Plus <-> host radio protocol ("Pulsar")

The radio link between a Quest 3 and its Touch Plus controllers, written as a spec for a non-Meta
host: the TouchFrame nRF52840 dongle. It comes from static RE of the user's own OTA (build
52433670048800520), extracted under the gitignored `artifacts/quest/`. Nothing here reproduces Meta
firmware: only our own prose, addresses, constants and small layout tables (README "Legal").

**Status (2026-10-04).** Everything a host has to send and accept is pinned statically, and
implemented offline in `radio-fw/` (BUILD-1 + BUILD-1b) and the driver (`driver/RADIO.md`,
BUILD-2). Nothing is confirmed on air yet: see [Open items](#open-items) and
[HARDWARE-DAY.md](HARDWARE-DAY.md) "Host mode".

**Evidence.** This file is the current spec; the derivations live in `docs/re/`:
[re/LINK.md](re/LINK.md) (RE-1: connected link, nonces, register map, pairing initiation),
[re/PERIPHERALS.md](re/PERIPHERALS.md) (RE-2: LEDs, IMU, input, haptics, calibration),
[re/AUDIT.md](re/AUDIT.md) (findings A1–A21), [re/REVIEW-RE.md](re/REVIEW-RE.md) (findings R0–R17,
incl. the TL header), plus [re/DEV-1.md](re/DEV-1.md) and [re/FRAME-MODEL.md](re/FRAME-MODEL.md).
Where they disagree, REVIEW-RE wins, then AUDIT, then LINK / PERIPHERALS.

**Tags.** **CONFIRMED** = read directly in code or data. **INFERRED** = strongly implied by code
(plus public prior work). **UNKNOWN** = not established.

**Names and addresses.** `monospace` names are the firmware's own (strings, `__FILE__`). Addresses
are Ghidra load addresses (see [Images](#images-and-load-addresses-confirmed)); `sb` = libsyncboss
ELF vaddr (Ghidra shows +0x100000). RAM structs: elk-app controller LL `0x20004f38`, connection
record `rec` = `0x20004ec0`, TL state `T` = `0x200051e8`; syncboss host LL `0x200156d0`.

---

## Gate A: can a non-Meta host pair? **YES (INFERRED, near-confirmed)**

**There is no host authentication.** Pairing is an anonymous X25519 exchange, after which the host
hands the controller a link key:
- A keyword sweep of elk-spl (pairing, "DM" mode) and elk-app for `sign / cert / verif / attest /
  rsa / ecdsa / ed25519 / hmac / sha / hkdf / challenge / trust` finds nothing in the pairing path
  (`device_pairing.c`, `x25519.c`). The only primitives are Curve25519 and AES-CCM.
- `bad_signing` is an SPL boot reason (app image check at firmware update); `security_is_locked` /
  `unlock_request` are the factory lock. Neither is host identity.
- The only gate is the numeric Pulsar version ([Q6](#q6--pulsar-version-check)). The Quest's own
  host-side check is skippable (`SYNCBOSS_DISABLE_FW_VERSION_CHECK`).
- The Quest's fallback link key, when `/data/misc/pulsar_aes_key.bin` can't be read, is a zeroed
  buffer: **default key = 16 zero bytes, default netaddr = 0** (CONFIRMED, [LINK §6](re/LINK.md)). A
  real Quest normally pairs with per-device keys (0x1d, [Q2](#0x11-vs-0x1d)).

So an nRF52840 host can pair with its own key and run the connected link without any Meta secret.
No reflash of the controller is needed.

---

## Images and load addresses (CONFIRMED)

Meta images start with a 0x2e-byte `dAeH` header: magic, checksum, header length, image kind
(`0x01020304` app / `0x11223344` SPL / `0xeeddccbb` updater), payload length, format 2, the
vector-table flash address (the table sits at file offset 0x100), firmware version, 12-char git
hash. Load base = vector address − 0x100.

| Image | MCU | base | reset | git | role |
|---|---|---|---|---|---|
| `fw/ruby_prq/elk-app.bin` | nRF52820 | 0x14000 | 0x2b771 | edbf4671d29b | Touch Plus radio app (connected link) |
| `fw/ruby_prq/elk-spl-updater.bin` (SPL at file 0x2ea0) | nRF52820 | 0x02000 | 0x09855 | 31970301f3a3 | bootloader / **DM (pairing) mode** |
| `fw/ruby_prq/deerfly-app.bin` | RA2E1, Cortex-M23 | 0x06800 | 0x10919 | edbf4671d29b | input co-processor, feeds elk over SPI; FSP 4.2.0 |
| `odm/firmware/syncboss.bin` | nRF52833 | 0x00000 | 0x48c19 | (raw, vector at 0x1100) | headset radio MCU: the host we replace |
| `odm/lib64/libsyncboss.so` | AArch64 | ELF | – | – | Android host library, with 1044 `.gnu_debugdata` names; authority for the register layer |

`ruby` (the older variant) has the same structure. Unwind tables give exact function boundaries for
syncboss and the `ruby` elk-app; the `ruby_prq` elk-app and the SPLs have none. The user's
controllers run firmware 207.5.0, the version in these headers ([DEV-1 §1](re/DEV-1.md)).

---

## Q1 — Radio PHY, channels, timing

The stack is Meta's **Pulsar** HAL, PHY → LL → CL → TL (`pulsar_phy.c`, `pulsar_ll_*.c`,
`pulsar_cl_*.c`, `pulsar_tl_*.c`), mirrored on host and device. Nordic proprietary 2 Mbit/s, not BLE.

### Radio configuration per link (CONFIRMED)

One PHY init sets it: host `syncboss FUN_0001b61c` (writes at `0x1b6e0..0x1b756`), device elk-app
`0x25662..0x256b2`, SPL `elk-spl FUN_000080c8`.

| register | value | evidence |
|---|---|---|
| `MODE` | 1 = Nrf_2Mbit | host `+0x510`, elk-app `0x25688` |
| `MODECNF0` | 1 (fast ramp-up; the device arms TXEN 0x28 µs early) | elk-app `0x2565c`, `0x23fd4` |
| `PCNF0` connected | LFLEN=8, **S0LEN=1** (S0 always `0x04`), S1LEN=0, S1INCL=1 (RAM pad, nothing on air), 8-bit preamble | host `FUN_0001e150`; device `0x2566e` |
| `PCNF0` discovery / pairing / DM beacon | LFLEN=8, **S0LEN=0** | host `FUN_00020440`, toggle `FUN_0001bfbc(1)`; device `FUN_00023d6c` |
| `PCNF1` | BALEN=4, ENDIAN=big, STATLEN=0, WHITEEN=0. MAXLEN: host connected 59 (`syncboss 0x1e1e6`), device connected 130 (`0x25674`), DM 255 | `maxlen \| 0x01040000` |
| `CRCCNF` | 3 = 24-bit, **SKIPADDR=0** (address in the CRC) | host `0x1b752`, device `0x25694..0x256a4` |
| `CRCPOLY` / `CRCINIT` | `0x108421` / `0xFFFFFF` | host `0x1b756` / `0x1b74a` (A9); CRC tables at `syncboss 0x52030`, `elk-app 0x316f8` (A11) |
| `SHORTS` | `0x113` (READY_START, END_DISABLE, ADDRESS_RSSISTART, DISABLED_RSSISTOP) | both |

On air: 8-bit preamble, 4-byte base + 1-byte prefix, [S0], 8-bit LENGTH, payload, CRC-24. The radio
appends the CRC. For offline checks the device's software CRC (`elk-app FUN_00024164 →
FUN_00022ab8`, table `0x316f8`) feeds `bitrev()` of each base byte LSByte first, then `bitrev(prefix)`,
then S0 / LENGTH / payload unreversed (A9; `tools/pulsar_host.py crc24_air`). The CRC trailer byte
order on air is INFERRED (MSB first).

**Logical addresses.** `BASE0` = `BASE1` everywhere, except the host's connected link: `0xFACEB00C`
in `BASE0` (AP0) and the netaddr in `BASE1` (`syncboss FUN_0001bb60`). Both sides TX on logical
address 7 (host `FUN_0001bb90`, device `elk-app FUN_00028ad0`). Host uplink RX prefixes are set by
`syncboss FUN_0001bbb8`.

### Addresses (CONFIRMED)

Full table in [Sniffer recipes](#sniffer-recipes-radio-fw-sniffer_config_t).
- **Discovery:** 2402 MHz, base `0xFACEB00C`, prefix `0xAA`, no S0 (host `FUN_000207c8` /
  `FUN_000208dc`; SPL `elk-spl 0x7f60`).
- **Pairing (DM link):** 2426 MHz, prefix `0xAA`, base = the controller's FICR `DEVICEID[0]` (`elk-spl
  FUN_00006e4c` reads `0x10000060`; used at `0x8008..0x8016`). Host `syncboss FUN_00020cc4(id_lo,
  id_hi)` / `FUN_000204f0`.
- **Connected:** base = the host's 4-byte **netaddr**, given to the controller in PairingData (host
  LL+0x50 via `FUN_00019e4c → FUN_0001d300 → FUN_0001e5dc`; device LL `+0x1e4`). Host TX prefix
  `0xF0`. Controller TX prefix = slot + 1 = `0x01..0x05` (`syncboss FUN_0001ab84`, `elk-app
  FUN_00028ad0`). The host enables AP0 (`0xAA`/`0xFACEB00C`) only during DM beacons
  (`FUN_0001bc9c(1)`).
- **The netaddr must not be 0 or `0xFFFFFFFF`** (R14): 0 trips the `init->address` assert in the app
  (`0x18bcc`), and `0xFFFFFFFF` reads as "No pairing info found".

### Channels and hop (CONFIRMED both sides)

- 37 logical channels; frequency table `syncboss 0x4fe70` (`FUN_0001ac24`), MHz above 2400:
  `4 6 8 … 24, 28 30 … 78`, i.e. 2404–2478 MHz in 2 MHz steps without 2402 and 2426.
- The host distributes a 37-bit channel map (adaptive FHSS, `adaptive_fhss.c`, log at `syncboss 0x6dd8`,
  `vendor.syncbosshal.pulsar_blocklist`); a map needs ≥ 8 channels (`FUN_0001aa30`). **Indices 0, 17
  and 36 must stay in the map** or seeking controllers can't find the host ([Seek](#seek); R10).
- **Hop = BLE CSA #1** (host `FUN_0001aaf4`, device `FUN_00023d6c`):
  - `hop = (netaddr & 0xFF) % 11 + 5` (host `FUN_0001e150`, device `0x245c6`);
  - per beacon period `unmapped = (unmapped + hop × n) % 37`; if `unmapped` isn't in the map, `idx =
    used[unmapped % num_used]` (enabled channels, ascending), else `idx = unmapped`;
  - host start: full map, `unmapped = 0` (`FUN_0001a85c`). The controller resets to a full map and
    recomputes `hop` on every entry to seek (R9).
- **DM beacons:** while scanning for advertisers (`pulsar_ll_dm_scan.c`), some periods go out on
  **2402 MHz** with S0 off and AP0 RX on (`FUN_0001dbf8`); the hop still advances. Beacon byte 0
  bits 1..2 announce it (device: DM event at `counter + ((b0 & 7) >> 1)`). Spacing is xorshift16
  seeded with `netaddr & 0xFFFF`, `(r % 20) + 5` periods (INFERRED, `FUN_0001f65c`). With DM scan
  active the host adds one extra period and hop step (INFERRED, `iVar4 = 4000` branch); a follower
  should re-sync from byte 5 of each beacon.

### Timing (CONFIRMED unless noted)

- **Beacon every 2000 µs.** Host `LL+0x5e4 += 2000` (`FUN_0001dbf8`); device expects `anchor +
  (missed + 1) × 2000` (`FUN_00023e54`), anchor = ADDRESS capture − 20 µs.
- **Device RX window:** `[t − w, t + 252 + w]`, `w = (n+1) × 80000 / 1e6 + 6` µs, capped at 920.
- **Uplink slots:** slot `s` (0..4) TXes at `anchor + 350 + {0, 225, 525, 825, 1125}[s]` µs (table
  `elk-app 0x32504`). That `anchor` is this beacon is INFERRED.
- **Acks:** no per-packet ack. Uplinks heard set bit S in an rx mask (`syncboss FUN_0001cdcc`), sent
  in the next beacon's byte 15, then cleared. The controller tests its bit and calls `rec+0x44`
  (R4); its retransmission behaviour is INFERRED.
- **Disconnect:** more than 24 missed beacons (`PULSAR_DEVICE_MISSED_BEACONS_BEFORE_DC` = 25, ≈ 50 ms)
  send the controller to seek (R9).

### Beacon (host → all, prefix `0xF0`, S0 = `0x04`) (CONFIRMED)

Builder `syncboss FUN_0001dbf8` + CL `FUN_0001cf30`, parser `elk-app FUN_00024164`. Plaintext (A4).

| byte | content |
|---|---|
| 0 | bit 0 reserved (UNKNOWN); bits 1..2 = periods until the next DM beacon (0 = none); bits 3..7 = map bits 0..4 |
| 1..4 | map bits 5..36 (LSB first) |
| 5 | current `unmapped` (0..36) |
| 6..7 | 16-bit **session nonce**, LE (from host init; used only in the negotiation nonce, [Nonces](#nonces)) |
| 8..13 | 48-bit timestamp, µs on the host clock, LE |
| 14 | `1 << S` when the downlink data is for the controller in slot S, else 0 (A18, R4) |
| 15 | ack mask: bit S per slot heard since the last beacon |
| 16.. | downlink: a [TL packet](#register-access-the-tl-layer) or the [accept](#accept-host--controller) |

- LENGTH 14..50. The controller hands CL+2 (byte 16 on) to the TL when bit S is set or byte 14 = 0
  (only the first counts as addressed; R4).
- **Limits disagree across reports:** LINK §4 gives `CL_HOST_MAX_PAYLOAD_LEN` = 34 for a normal beacon
  and CL length 36 for the negotiation beacon; R0 gives TL payload ≤ 32. How they add up to LENGTH is
  not pinned (R0, hardware-day item).
- Uplinks carry S0 = `0x04`, LENGTH ≤ 126 (`LL_DEV_MAX_PAYLOAD_LEN`).

### Discovery advert (controller → 2402, no S0, LENGTH 32)

Layout CONFIRMED (`elk-spl FUN_000080c8`, host parse `syncboss FUN_000208dc`): `[0]` type = 2 (the host
also accepts type 1 with the ID at `[6..13]`); `[1..4]` `01 17 hw hw` = Pulsar version `0x1701` + hardware
(INFERRED); `[5..12]` 64-bit device ID, LE; `[13..16]`, `[17..30]` (from `FUN_00003418`) and `[31]`
UNKNOWN. libsyncboss decodes DM flags from it (`PULSAR_DM_FLAG_ECDH_PAIRING`, `_APP_REQUEST`,
`_USER_RESET`, `_CORRUPT_APP`, `_ASSERT_SET`, `_IS_SPOOFING`). Interval ≈ 100 ms (INFERRED, A18).

**Clock.** A 1 µs sync timer (`pulsar_sync_timer.c`) and a time translator (`time_translator.c`)
align the controller to the beacon timestamp. IMU timestamps and LED phase are in this translator
time, so **the dongle's µs clock is the reference for both**.

---

## Q2 — Discovery and pairing

### DM link and SPL framing

- **Opening the link (INFERRED):** after an advert, the host polls the controller on 2426 MHz in
  ping-pong: TX (`FUN_000204f0`), RX window ~900..2000 µs (`FUN_0001be1c(900, 2000)`), give up after
  666 misses (`FUN_00020a70`).
- **Request (CONFIRMED):** `[LENGTH][cmd][seq][payload]`. Dispatcher `elk-spl FUN_0000822c`: cmd
  bit 0 = read, bits 1..6 = number, so **on-air byte = `(number << 1) | read`** (A5). `cmd & 0x7e` = 0
  is an empty poll. No SPL-level CRC beyond the radio's (INFERRED).
- **Reply (CONFIRMED, R5):** `[LENGTH = n+2][status][seq][data]`. Status bit 7 = failed, bit 0 = 0,
  bits 1..6 stale (not the command number). **Match replies by seq only.**
- **Seq (R5, R15):** a request with the same seq as the previous one is a retransmit (old reply
  re-sent, not executed). The previous seq starts at 0, so **don't start at seq 0**.

| command | number | on-air byte | handler | notes |
|---|---|---|---|---|
| SetupX25519Keys (read) | 0x12 | **`0x25`** | `FUN_00003948` | payload: 32-byte host public key; reply: controller public key |
| PairingData (write) | 0x11 | **`0x22`** | `0x3abc → 0x39fc` | below |
| PairingData, derived key | 0x1d | `0x3a` | `0x3ac6 → 0x39fc` | Meta's default |
| WriteAESKey | 0x14 | `0x28` | `FUN_000081bc` | **no-op stub**, don't send |
| Reset (write, empty) | 0x15 | **`0x2a`** | `FUN_00002a04` | send after PairingData (R6) |

### Pairing sequence for a host (CONFIRMED)

1. Send `0x25` (seq 1) with the host public key. Pairing state is 1 at boot (`FUN_00003894`), so no
   earlier command is needed. Each `0x25` regenerates the controller key pair (`FUN_00003928`) and sets
   state 3.
2. Send `0x22` (seq 2) with the wrapped PairingData (needs state ≥ 3).
3. If status bit 7 is clear, send `0x2a` Reset (seq 3, no payload); wait for the reply or ~10 ms, stop
   polling and start beaconing. The SPL jumps to the app 500 ms later (`FUN_000031e8(500, 0x29cd)`,
   when mode byte `0x200001ac` is 0 or 0x7f), and the app seeks the netaddr. This is what the Quest
   does: `sb input_pair` writes reg 0x15, then sends DM disconnect `0xc9` (R6).
4. **A failed PairingData** still sets state 5 and zeroes all keys and the secret (`0x3a64..0x3a6c`).
   Redo `0x25` before retrying `0x22` (R15).

### PairingData layout and key derivation (CONFIRMED, both sides)

The link key is **chosen by the host and sent encrypted**. The ECDH secret only wraps it:
- **wrapping key = first 16 bytes of the X25519 shared secret**, no hash (controller `FUN_000093c0` →
  `FUN_0000909c → FUN_00009084`, scalarmult `FUN_0000934c`, buffers zeroed by `FUN_000039bc`; host
  `syncboss FUN_00047604`, `ecdh_pairing.c`, key at `m_session+0x61`, IV from RNG `FUN_000185d8`);
- AES-128-CCM, counter 0, nonce = `00×5 ‖ IV[8]`, AAD = one `0x00` byte, MIC 4 bytes.

`0x22` payload (32 bytes; `FUN_00009198(payload+8, …, 0x18, payload[0..7], 0, 0)`):

| offset | bytes | content |
|---|---|---|
| 0 | 8 | IV, random, in the clear |
| 8 | 24 | ciphertext of the 20-byte plaintext + MIC |

Plaintext (length ≠ 0x14 logs `"incorrect decrypted length"`, `elk-spl 0xf11c`): `[0..3]` netaddr as
**u32 LE** (A16; host source `FUN_00045a6c`), `[4..19]` link key (host source `FUN_000439bc`). `FUN_000038e8` stores the 20 bytes at record `+0` and the key again at `+0x14`;
the app loads the key from `+0x14` unless erased, else `+4` (R14).

### 0x11 vs 0x1d

`0x1d` decrypts the same payload but stores **key = shared secret[:16]**. The only difference is
`FUN_000038e8(decrypted, 0)` vs `FUN_000038e8(decrypted, shared_secret)` (A15). A real Quest sends
0x1d first and falls back to 0x11 with its global key only on an error reply (`FUN_00047548`,
`FUN_00047834`; A7), so its keys are per device and never on air. **TouchFrame sends 0x11** with its
own key.

### One host record (CONFIRMED)

`FUN_000038e8` erases the page and writes a single record at flash `0x3b000`; the app reads the same
one (R14). **Pairing to the dongle replaces the Quest bond**; going back needs a re-pair
([LINK §5.1](re/LINK.md)).

---

## Q3 — Connected link

### Seek

A paired controller seeks its netaddr (CONFIRMED, R10):
- RX dwell of 75 250 µs per channel on indices **0, 17, 36** (2404 / 2442 / 2478 MHz; `FUN_00022de8`,
  table `0x316ec`), moving on after a timeout or bad RX. 37 hops × 2000 µs = 74 000 µs and every hop
  step is coprime with 37, so a full map puts one beacon on each channel per dwell.
- After a 25-beacon drop it reconnects within one ~226 ms rotation plus negotiation.
- While seeking it sits in slot 0 (TX prefix `0x01`) with IV 0 (`FUN_00028ad0(0, …)` at `0x23ae2`).
- **Power states** (defaults in elk `.data`, ms INFERRED): ACTIVE_SEEK 30 000, then INACTIVE_SEEK
  3 600 000 at a lower duty (INFERRED; pattern UNKNOWN); full list in R10. cmd **0x49** sets them by
  name, `{char state[28], i32 timeout}`.

### Connection request (controller → host)

Sent on prefix `0x01` under the **negotiation nonce**. Built at `elk-app 0x23bc4..0x23c22`, LENGTH
`0x19`, parsed by `syncboss FUN_0001d038` (CONFIRMED both sides; A3, A14, R16):

| CL byte | content |
|---|---|
| 0 | `0` = request (data uplinks carry S here) |
| 1 | `0x11`; fmt = `[1] >> 3` = 2. fmt 0: no bytes 14..24; 1: bytes 14..22 only; ≥ 2: all |
| 2..9 | 64-bit device ID (`rec+0/+4`) |
| 10..13 | version `01 17`, handedness (`rec+0xa`, UICR value), board ID (`rec+0xb`) |
| 14 | slots requested; the host honours only 1 or 2 |
| **15..22** | **steady-state IV**, u64 LE (`rec+0x68`) |
| 23, 24 | UNKNOWN (RADIO `+0x50c` + a global byte; global `0x200000b0`) |

The steady IV is 8 fresh RNG bytes drawn on every entry to the controller's idle state
(`0x2396e..0x239b4`): a new IV per connection (R16).

### Accept (host → controller)

The host answers with **one** accept, a 26-byte body in the beacon's downlink area (CL length 36). The
controller (`0x23ace`, RX case `0x23af8`) reads bytes 0..13 only (CONFIRMED both sides, R1–R3):

| byte | value | controller check |
|---|---|---|
| 0 | 1 | type |
| 1 | host `+0x75` | not read |
| 2 | `(fmt << 3) \| 2` | `& 7`: **2 = accept, 3 = reject** |
| 3..10 | device ID, LE | must equal `rec+0/+4` |
| 11 | **S ∈ 1..4** | **0 = fatal assert** (`"accept_pkt->endpoint != CONN_NEG_SLOT"`) |
| 12 | 1 if the request's IV was non-zero | 0 = zero the IV, negotiation nonce all session |
| 13 | slot count, 1 | uplink budget `0x34 + 0x47 × (n − 1)` |

- On accept the controller stores S (`rec+0xc`), calls `FUN_00028ad0(S, key, IV)` (TX prefix S+1,
  counter reset) and reports "connected" (`0x23c8c`).
- Endpoint 3 sends it back to idle (new IV) and reports "disconnected" (`0x23b64..0x23b82`). Don't send
  a second "lock" packet: after a lost accept it rejects the controller (R2).
- **There is no version field in the accept** (R3).

### Slot number S (CONFIRMED, R4)

One number S ∈ 1..4 per controller, so a host holds at most 4. It is accept byte 11, uplink CL byte 0,
the bit `1 << S` in beacon bytes 14 and 15, uplink slot S, and controller TX prefix S + 1. Host
allocator `FUN_0001d4d8` scans from 1; slot 0 is negotiation only.

Host CL structure: `pulsar_cl_host.c` init `syncboss FUN_0001d300` registers `prepare_beacon_handler`,
`packet_rx_handler`, `connection_change_handler`, `connection_request_handler`. `FUN_0001d038` stores
per-slot key and IV via `FUN_0001e90c` (`LL+0xeb0+slot*16`, `LL+0xf10+slot*8`).

### CCM: uplink only (CONFIRMED)

nRF hardware AES-128-CCM (`pulsar_crypto.c`; A10): `syncboss FUN_0001b0a4` init, `FUN_0001b1a4` encrypt
(pairing wrap only), `FUN_0001b29c` / `FUN_0001b3cc` uplink decrypt.
- **Only controller → host packets are encrypted** (A4). elk-app has only the encrypt mode (`0x23a6c`),
  syncboss decrypts (`0x1b37c`, `0x1b47c`). **Beacons and downlink are plaintext and unauthenticated**:
  the host never encrypts on the connected link.
- The controller has a plaintext-uplink bypass (`LL+0x29c`, checked at `0x24052`); what sets it is
  UNKNOWN.
- Config block at `CNFPTR` = `cfg+0x110`: KEY `+0x110` (16), PACKETCOUNTER `+0x120` (5 bytes LE, 39-bit),
  DIRECTION `+0x128`, IV `+0x129` (8).
- **Nonce = PACKETCOUNTER[5 LE] ‖ IV[8]**, direction = nonce bit 39, **always 0**: no image writes it
  (A17, R8). AAD = `S0 & 0xE3` = 0; MIC 4 bytes (A8).

### Nonces

| regime | used for | counter | IV |
|---|---|---|---|
| **negotiation ("legacy")** | the request, and any uplink while the slot IV is 0 | 0 | `session_nonce << 48 \| beacon_ts48`; nothing on air (A2) |
| **steady** | uplinks after the accept | **beacon periods since the accept** (R7) | request bytes 15..22 (A3) |

- Negotiation (host `FUN_0001aba8`, elk-app `0x24092..0x240d6`): nonce = `00×5 ‖ ts[0..5] LE ‖ session
  LE`, where ts is that of the beacon starting the period: the last received timestamp + missed
  periods × 2000.
- Steady counter: reset at the accept (`0x28b22`), +1 plus skipped periods every period, uplink or not
  (controller `LL+0x1b8`; host bumps all five per-slot counters `LL+0x3c..+0x4c` with the hop). Which
  period counts as 0 needs one live MIC check.
- Tools: `pulsar_host.py` `legacy_nonce()`, `steady_state_nonce(direction=0)`, `parse_conn_request()`;
  `pulsar_crypto.py scan`.

**Losing a controller.** It drops to seek after 25 missed beacons. **No real disconnect message is
known**; a host frees the slot when the controller goes quiet.

---

## Register access: the TL layer

CONFIRMED on both sides (R0): host `syncboss pulsar_tl_host.c` (`0x19acc..0x1a220`), controller TL at
`T` (handlers at `0x18b5a..0x18b6c`).

- **Downlink** (plaintext): beacon byte 16 on = TL packet, addressed by byte 14 = `1 << S`.
- **Uplink** (decrypted): `[S][TL packet]`.
- **TL packet** = `[reg][flags][payload]`. Downlink payload ≤ 32 bytes; uplink budget 52 bytes for one
  slot.

| flags bit | meaning | evidence |
|---|---|---|
| 0..3 | **seq** 0..15 | host `FUN_0001a6f8` (`bfi …,#0,#4`); controller stores RX seq at `T+0x40` and stamps it on every uplink |
| 4 | **1 = read, 0 = write** | controller `0x234f6`: write → `FUN_00027ebc`, read → `FUN_00025c98` |
| 5 | **error** (responses) | host `0x19dc4`; controller sets it when the handler failed |
| 6 | **notification** | host bit test `0x19ca6`; controller sets it on notifications only |
| 7 | unused (0) | |

**Rules:**
1. **Request:** `[reg][seq | 0x10 if read][payload]`. New seq for every new request (wrap 15 → 0), also
   for a repeat of the same command: the controller treats a packet with the same seq, reg and read bit
   as a retransmit, re-sends its last response and doesn't execute (`0x234f2..0x23514`). **Re-send the
   same packet every beacon** until answered or timed out (host `T+0x1c` in beacon periods; the Quest
   uses 2400 ms).
2. **Read response:** `[reg][seq | 0x10 | err << 5][data]`, always sent.
3. **Write ack:** a successful write that returns no data gets **no response**; it completes when any
   uplink from that controller carries its seq in bits 0..3. A failed write gets `[reg][seq | 0x20]`.
4. The host requires response `pkt[0]` = request reg and bits 0..3 = its seq.
5. **Notifications:** `[0x00][seq | 0x40][chunk stream]` (packer `0x20210`).
6. **Idle beacon:** the Quest sends `[0x00][seq]` with byte 14 = 0 (`0x19b98`). That the controller
   doesn't need it is INFERRED (hardware-day item).
7. **Reg 0x2a** in either direction is RF-performance stats; ignore it.

Example (hand-built): read cmd 0x32, seq 3, slot 1 → beacon bytes 14..18 = `02 00 32 13`; response
uplink = `01 32 13 <16 bytes>`. Write cmd 0x28, seq 4 → `.. 28 04 <12 bytes>`, acked by the next uplink
with seq 4.

### Command registers

Request/response registers (`pulsar_manager_{read,write}_sync`; controller read `FUN_00025c98`, write
`FUN_00027ebc`). IDs and directions CONFIRMED from libsyncboss callers ([LINK §3](re/LINK.md), R16).
**No handler checks the payload length**: always send full-size payloads (R16).

| reg | R/W | len | content |
|---|---|---|---|
| 0x01 | R | 32 | `device_desc`, handedness at 16..23 ([Handedness](#handedness)) |
| 0x02 / 0x03 | R | 16 | `pcb_sn` / `assembly_sn` |
| 0x09 | W | 1 | "data ready"; optional (R12) |
| 0x0a | R | 8 | capabilities: bit 1 PCM haptics, bit 11 settable on-time, byte 1 bit 0 dual IMU, byte 0 bit 7 fft; elk forces bit 0 |
| 0x20 | W | 1 | select MCU: 0 elk, 1 deerfly |
| 0x24 / 0x25 | R | 28 | app version / DM version |
| 0x28 | RW | 12 | IR LED config ([IR LEDs](#ir-leds)) |
| 0x2b | R | ≤ 32 | calibration blob, request `{u32 offset, u32 len}` ([Q5](#q5--calibration)) |
| 0x2f | R | 9 | `battery_info` ([Battery](#battery)) |
| 0x31 / 0x32 / 0x33 | R | 16 / 16 / 4 | IMU model string / `imu_config` / temperature ([IMU](#imu)) |
| 0x49 | W | 32 | power-state timeout ([Seek](#seek)) |
| 0x54 / 0xb6 | R | 9 | dual-IMU / fft config (optional) |
| 0x97, 0x9b, 0x9c, 0x9d, 0xa0 | W | | [haptics](#haptics) |
| 0xa1 | W | 1 | battery load test that pulses the motor. **Don't send** (R12) |

Others seen: 0x05 shutdown, 0x06 sleep/wake, 0x0b/0x0c attachment info/auth, 0x13 unpair, 0x19/0x1a
console, 0x1c carrier, 0x34 assert info, 0x38 backtrace, 0x3f build hash, 0x4c/0x4e/0x4f thumbstick
user cal / clear / deadband, 0x50 ADC stream, 0x53 battery pack, 0x9f IMU integration uplink, 0xab
`read_hid_report_descriptor`, 0xac HID feature report, 0xb4 RF-perf stream, plus firmware-update IDs.
The 0xab descriptor is read for attachment devices; Touch Plus input uses no HID descriptor.

### Notifications

The controller pushes streaming data as a **chunk stream** after `[0x00][seq | 0x40]`. Each chunk = LE
u16 header + payload (host `ntf_unpacker_next`, `sb 0x12e74`; CONFIRMED):

| header bits | meaning |
|---|---|
| 0..4, 11 | chunk type = `(h & 0x1f) \| ((h >> 6) & 0x20)` = notification id |
| 5..10 | payload length, 0..63 |
| 12..14 | fragment seq (0 = first) |
| 15 | last fragment |

- `(h & 0xf000) == 0x8000` = unfragmented. A fragment appends only with the same type and seq + 1;
  total ≤ 0x3f.
- **Fragments span notifications** (R13): a non-final fragment ends that notification, and reassembly
  continues in the next one per controller. A broken sequence drops the rest. IMU and input fit in one
  uplink.
- Inside the Quest, libsyncboss sees a 0x14-byte MCU wrapper (`spi_data_pulsar_data_t`, register id at
  `+0x13`) and an optional sidechannel chunk, absent for Touch Plus (caps bit 0). Neither is on air (R16).

### Enumeration on connect

The Quest (`input_refresh_cache`, `sb 0x5d090`): W 0x20 = 0, R 0x24, R 0x25; for deerfly W 0x20 = 1,
R 0x24, W 0x20 = 0; R 0x32, 0x31, 3, 2, 1, 0x2f, 0x0a; optional R 0x54 / 0xb6; W 9; W 0xa1; then W 0x28.

For a non-Meta host: read cmd 1 (hand) and 0x32 (IMU scale). **cmd 9 is optional**: the controller
waits 100 ms for it, logs "Failed to receive ready signal from host" and streams anyway. **Skip 0xa1.**
Re-send 0x28 after every reconnect (R12, R16).

---

## Q4 — Peripherals

Three register spaces share numbers but not meanings: command registers (above), notification
registers (elk table `0x2e7dc`, ids 0..0x2d, writer `FUN_0001f464`), and deerfly SPI registers (`0x37`
input sample, `0x4a` haptics drive, `0x02` status, `0x59` cal write).

### Input (CONFIRMED: elk packs, host unpacks and labels)

elk's `input_mcu_thread` (`FUN_000173bc`) reads deerfly SPI reg 0x37 (61 bytes), checks a **CRC-32
(zlib)** over `buf[0..0x38]` against the LE u32 at `buf[0x39]` (A18), and repacks it. Host labels:
`print_decoded_controller_input` (`sb 0x69018`).

| ntf | size | content | deerfly source | host decode |
|---|---|---|---|---|
| 0 | 1 | battery % | (elk `FUN_00014c38`) | u8 |
| 1 | 18 | IMU sample | (elk) | [IMU](#imu) |
| **2** | 4 | **thumbstick x, y**, 2 × i16 | buf[0..3] | ÷ 32767 if > 0, else ÷ 32768 |
| **3** | 3 | **index trigger** bits 0..11, **grip** bits 12..23 | `u16@0x23`, `u16@0x25`, each `& 0xfff` | ÷ 4095 |
| **4** | 1 | **buttons**: b0 A/X, b1 B/Y, b2 stick click, b3 system/menu | `{in.1, in.2, in.3, in.0}` of buf[4] | |
| 6 | 1 | state: b0 low_power, b1 assert, b2 cap_touch_err, b3 imu_err, b4 asleep, b5 attachment | (elk) | log |
| 8 | 10 | raw analog (stick ADC + Hall), label INFERRED (R16) | buf[7..10], [0xb..0xc], [5..6], [0xd..0xe] | raw |
| **9** | 4 | **touch + proximity**, 12 bits (below) | buf[0x21], buf[0x22] | |
| 0xb | 12 | IR LED config echo `{p, ot, d}` | (elk `FUN_00014c1c`) | |
| 0x15 | 2 | **index-trigger pressure**, 12-bit | `u16@0x37` | raw / 4095, max 8.5 N (R16) |
| 0x16 | 2 | alerts: b0 too_hot, b1 too_cold, b2 dead_battery, b3 brownout_secondary, b4 brownout | (elk `FUN_00014c38`) | log |
| **0x17** | 8 | **index curl**: u8 curl1d, u8 idx_slider, s12 joint angles at bits 16 / 28 / 40 / 52 | buf[0x2d], [0x2e], @0x2f, 0x31, 0x33, 0x35 (A6) | u8 ÷ 255; s12 × 360 / 4096 ° |
| 0x20 | 6 | sensor bytes, **meaning UNKNOWN** | buf[0x1b..0x20], reordered | cached |
| 0x21 | 12 | cap-touch raw, **meaning UNKNOWN** | buf[0xf..0x1a], reordered | cached |
| 0x28 | 4 | IMU temperature, i32 raw, on change | (elk) | cached |
| 0x2b | 2 | buf[4] bit 4 (a fifth GPIO, P915), **meaning UNKNOWN** | buf[4].4 | cached |

Unused by Touch Plus (INFERRED): ids 0x19 (61 B), 0x1b (24 B, dual accelerometer) and an alternate
10-bit touch ntf 5.

**ntf 9 bits** (b = buf[0x21], c = buf[0x22]; CONFIRMED). Touch: 0 A/X (b.0), 1 B/Y (b.2), 2 stick
(b.4), 3 thumbrest `tr` (c.2), 4 index trigger (b.6), 10 "trigger2" (c.0). Proximity: 5 A/X (b.1),
6 B/Y (b.3), 7 stick (b.5), 8 index trigger (b.7), 9 `tr` (c.3), 11 "trigger2" (c.1). "Thumbrest" is
INFERRED from the label; **"trigger2" is UNKNOWN**. Labels are positional (A/X lower, B/Y upper); `sys`
is menu on the left, Meta on the right (INFERRED).

**Deerfly** ([PERIPHERALS §4.2](re/PERIPHERALS.md), R16): buf[4] holds active-low GPIOs, on
production boards b0 P214 (system), b1 P215 (A/X), b2 P200 (B/Y), b3 P407 or P408 (stick click), b4
P915. Index trigger and grip are **Hall-effect sensors** over I²C (`dfy FUN_0000ad7c`); the stick is
an ADC with per-unit cal, rotation and clamp to ±0x7fff. The Hall → buf 0x23/0x25 and stick → buf[0..3]
paths were not traced end to end in deerfly; the elk remap and host labels pin the meaning (R16).

### Handedness

**cmd 1 `device_desc`** (32 bytes, elk read case 1 at `0x25e22`; CONFIRMED, R11): four 8-byte strings,
`"oculus"`, `"rubyprq"`, the hand, and `"0x%02x"` of the board ID (UICR `0x10001090`). **Bytes 16..23**
come from UICR `0x10001094`: 0 = `"left"`, 1 = `"right"`, > 1 = `"unconf"`. Bytes after each NUL are not
cleared. The same value is `rec+0xa` (request byte 12). elk's boot cross-check against deerfly reg 0x0f
only logs a mismatch, so the UICR value wins.

### IMU

**TDK ICM-42686** at **±32 g, ±4000 dps, 500 Hz** (CONFIRMED, `elk 0x16cc8`, config `0x2e1fc`).
Boards 0x90..0x93 / 0x96 / 0x97 use an ICM-476xx driver (INFERRED 800 Hz). **Read cmd 0x32; don't
hardcode.**

**cmd 0x32 `imu_config`** (16 bytes): u16 accel range 32000 mg, u16 gyro range 4000 dps, u16 accel
ODR 500, u16 gyro ODR 500, **f32 accel g/LSB = 1/1024** (offset 8), **f32 gyro dps/LSB = 1/8.192**
(offset 12).

**ntf 1** (18 bytes, `FUN_00015280`): u48 LE timestamp in µs of **translator time = the dongle
clock**, then 3 × i16 accel, 3 × i16 gyro, raw chip axes.
- SI (as the Quest does, `sb 0x57bf8`): `a = raw × f32@8 × 9.80665` m/s², `ω = raw × f32@12 × π/180`
  rad/s.
- One sample per 2000 µs; the Quest flags delta ≤ 0 as a stall, > 48 000 as corrupt, and counts
  `(delta + 1000) / 2000 − 1` missed when > 2099 (`sb 0x58ec8`).
- Temperature: ntf 0x28 or cmd 0x33, 132.48 LSB/°C, offset 25 °C. Rectification into the model frame
  uses the per-unit calibration ([Q5](#q5--calibration)).

### IR LEDs

**The LEDs can only strobe: at most 75 µs per pulse, phase-locked to the host clock** (CONFIRMED,
[PERIPHERALS §2](re/PERIPHERALS.md); `irled_manager.c`, `sync_trigger.c`).

**cmd 0x28** (12 bytes LE, read/write): u32 `period_us` (p), u32 `ontime_us` (ot), i32 `delay_us`
(d) = **pulse centre**, mod p, on the host clock. Host `sb 0x5c0b0`.
- **ot is silently clamped to 75** (`0x27fe6`, before validation; limits set once at boot,
  `0x16e98..0x16eb0`). The validator `FUN_0001fbb8` rejects `ot > p` or `p > 500 000` ("IR LED
  configuration rejected: …") and keeps the old config, else copies it to `0x200069f8`. No minimum p,
  no check on d, no current field.
- Defaults p 33333, ot 19, d −9. Meta sends 66664 / 19 / 26453 µs ([DEV-1 §1](re/DEV-1.md)).
- Pulse start = next `t ≥ now + 700 µs` with `t ≡ d − ot/2 (mod p)` (LED thread `FUN_0001554c`, arm
  `FUN_000293ac`, `FUN_0001873c`). At most one
  period is added, so with p < 700 µs a compare can be missed and the 1000 ms "IR LED timeout" assert
  resets the controller. **Never send p < 700 µs.** Best duty ≈ 75/800 (INFERRED).
- A new config applies from the next pulse (the thread isn't woken, R16). The first pulse after boot
  uses offset d.
- **Off:** ot = 0 with a large p (p < 1000 busy-loops, INFERRED; R16).
- **Echo:** ntf 0xb `{p, ot, d}` on change and every 2 s (R16). The Quest re-sends 0x28 on a mismatch.
- **Quest host:** `pulsar_manager_set_led_timing` / `set_led_period_delay_us` follow the headset's camera
  cadence; the OS can set only the on-time (`set_led_ontime_us`, `sb 0x535fc`), and the cached on-time
  falls back to 19 µs on every re-enumeration (R16).
- `syncboss_led_*` APIs drive the headset's own LEDs, not the controller.

**For TouchFrame:** the Frame exposes controller frames for 10 µs at 30 Hz, so a 75 µs pulse must be
centred within ±32.5 µs; with integer µs, p = 33333 slips 0.33 µs per frame
([FRAME-MODEL §3](re/FRAME-MODEL.md)). The driver finds and holds the phase in a closed loop
(`driver/RADIO.md` "LED phase loop").

### Haptics

Path `FUN_00027ebc` → `FUN_0001f968(type, …)` → thread `FUN_0001ac74` → deerfly reg 0x4a (CONFIRMED
unless noted):

| cmd | len | payload | notes |
|---|---|---|---|
| **0x97** | 1 | u8 amp | 0 = stop |
| **0xa0** | 3 | u8 amp, u16 freq LE | freq 40..561 (`FUN_000150fa`), Hz INFERRED; an out-of-range freq still sets "playing" |
| 0x9b | 32 | u8 n (& 0x1f), n amplitudes | 100-entry ring played on the host clock; **sample rate UNKNOWN** |
| 0x9d | 31 | PCM | **3-bit ADPCM** (2-bit plane 18 B + 1-bit plane 9 B; encoder `sb 0x69864`, config `{0x12, 9}` at `sb 0x83c50`), 72 samples per write, needs caps bit 1; the controller requests more by notification (R16) |
| 0x9c | 4 | multi | **unsupported** on Touch Plus |

Every type **auto-stops 2 s** after the last request (`FUN_0001f8c0`); re-send for longer effects.
Requests are dropped while the haptics state byte `0x20003c20` is 0. SteamVR mapping: 0xa0 with
`{round(amp × 255), clamp(freq, 40, 561)}` (0x97 for freq 0), 0x97 = 0 to stop.

### Battery

ntf 0 = percent. **cmd 0x2f** (9 bytes): f32 percent (CONFIRMED, R16), u32 mV (host `sb 0x53428` reads
`u32@4 / 1000`), byte 8 status when byte 5 is set (INFERRED: charging / health). ntf 0x16 = alerts.

---

## Q5 — Calibration

- **cmd 0x2b = `ir_led_cal`** (CONFIRMED controller side, `FUN_00025c98` case 0x2b). Request `{u32
  offset (low 16 bits), u32 len ≤ 32}`; returns bytes from flash `0x3d000 + offset` (≤ 0x2000 total;
  zeros if erased). The Quest reads 0x1fe0 bytes in 32-byte chunks (`sb 0x53150`).
- **Content INFERRED:** the per-unit constellation JSON (`ModelPoints`, `ImuPosition`,
  `Acc/GyroCalibration`), which `tools/touchplus_config.py --cal` parses. One live read decides it.
  Until then TouchFrame uses Meta's nominal OTA model (`tools/touchplus_config.py`).
- **User calibration** (stick, trigger) lives in deerfly flash and syncs over SPI reg 0x59; deerfly
  output is already calibrated. IMU scale comes from cmd 0x32.

---

## Q6 — Pulsar version check

- **The controller's version is `0x1701`** (CONFIRMED): on air `01 17` = major 1,
  `pulsar_protocol_sub_version` 23. Written at `elk-app 0x18b90` (`FUN_00018a24`) into `rec+8`; the
  only such immediate in elk-app, absent from syncboss. Sent in connection-request bytes 10..11 (A14)
  and advert bytes 1..2. Telemetry: `"cl version: %u"` (`syncboss 0x5ce10` / `0x5e564`).
- **Reaction (CONFIRMED):** event `0x10` `INVALID_HOST_PULSAR_VERION` in the "seek" state handler
  (state record at flash `0x33210`, name `0x2c8b0`; real entry `0x14964`, Ghidra says `FUN_00014960`)
  logs "Invalid host Pulsar version detected, stopping seek" (string `0x2c881`, site `0x149b4`),
  returns action 5 and branches to the seek-stop transition `0x20b88` (RAM state table `0x20000390`).
  It also counts `incompatible_version`. A numeric gate, not crypto.
- **Where an inbound host version is read is UNKNOWN.** The accept has no version and its handler
  reads none (R3); the beacon has none. The code that raises event 0x10 seems to sit in a region Ghidra
  left as raw bytes (`~0x20000..0x20600`, near "Received connection rejection from host", string
  `0x2f671` at code ~`0x20598`).
- **For TouchFrame:** nothing to send; never reject a controller (never use accept endpoint 3).

---

## Sniffer recipes (`radio-fw`, `sniffer_config_t`)

Common: `mode = 1`, `balen = 4`, `big_endian = true`, `lflen = 8`, `s1len = 0`, `statlen = 0`,
`crc_len = 3`, `crc_poly = 0x108421`, `crc_init = 0xFFFFFF`, `crc_skip_addr = false`, whitening off.
Program `base` / `prefix` exactly as the firmware does (both ends are nRF52 radios).

| link | frequency | base | prefix | s0len | maxlen | hop |
|---|---|---|---|---|---|---|
| 1. discovery | 2 | `0xFACEB00C` | `0xAA` | 0 | 255 | none |
| 2. pairing | 26 | `DEVICEID[0]` = advert bytes 5..8 as LE u32 | `0xAA` | 0 | 255 | none |
| 3a. connected, host | per hop | netaddr | `0xF0` | 1 | 255 (≥ 130) | CSA #1, 2000 µs |
| 3b. connected, controllers | per hop | netaddr | `0x01..0x05` | 1 | 255 | CSA #1, 2000 µs |
| 3c. connected, DM beacon | 2 | netaddr | `0xF0` | 0 | 255 | none |

- A Quest's netaddr isn't on air. The CRC covers the address, so a candidate can be checked offline
  against a captured packet with `crc24_air` ([Q1](#radio-configuration-per-link-confirmed)).
- `radio.py sniff --connected` listens on `0xF0` and `0x01..0x05` at once and follows the hop: park on
  3c or any channel, catch a beacon, then follow bytes 0..5 and `hop`.
- A real Quest's beacons and downlink decode (plaintext); its uplinks don't (per-device 0x1d key). Our
  own dongle's sessions decode with our key.

---

## Reproduce

```sh
# 1. flatten the dAeH images and record load bases -> artifacts/work/images.json
python tools/ghidra/extract_images.py
# 2. function boundaries from the OTA's unwind tables
python tools/ghidra/fde_starts.py
# 3. Ghidra headless: import at the right base, label nRF52 RADIO/CCM/AAR/ECB, decompile
tools/ghidra/run.sh syncboss        0x1100  artifacts/work/syncboss.funcs
tools/ghidra/run.sh elk-app-ruby_prq 0x14100
tools/ghidra/run.sh elk-spl-ruby_prq 0x2100
# 4. deerfly: BinaryLoader base 0x6800, ARM:LE:32:Cortex, functions from the vector table at 0x6900
# 5. libsyncboss internal names (MiniDebugInfo; Ghidra 12 also reads them itself)
python -c "import lzma;from elftools.elf.elffile import ELFFile as E;f=E(open('artifacts/quest/odm/lib64/libsyncboss.so','rb'));open('sb_debug.elf','wb').write(lzma.decompress(f.get_section_by_name('.gnu_debugdata').data()))"
# helpers: tools/ghidra/scan.py (constant finder), disasm.py (capstone Thumb), xref.py (string xrefs),
#          getfn.py (pull a function out of a *.decomp.c dump)
# offline models of the formats above, with selftests:
python tools/pulsar_host.py selftest; python tools/pulsar_crypto.py selftest; python tools/pulsar_input.py selftest
```
All scripts read the gitignored `artifacts/work/` produced by step 1. libsyncboss
`controller_process_notification` needs a manual jump-table override: tables at `sb 0x85150` (types <
0x1f, base `0x57708`) and `0x8518e` (types < 0x2e, base `0x58334`), entry × 4.

---

## Open items

Only real unknowns. Everything else above is pinned statically.

**Hardware day** (second dongle sniffing; [HARDWARE-DAY.md](HARDWARE-DAY.md) "Host mode",
`radio-fw/README.md` "Needs hardware"):
1. Whether controllers need the idle TL packet on empty beacons (`radio.py host --tl-idle`; R0).
2. Which beacon period the steady counter counts as 0 (R7), and direction 0 on air (R8). The firmware
   searches both.
3. Whether the 14 accept bytes the controller reads suffice without the rest of the 26-byte body (R3).
4. The CL LENGTH accounting on the downlink ([Beacon](#beacon-host--all-prefix-0xf0-s0--0x04-confirmed)).
5. Whether controllers react to missing beacon acks.
6. How the pairing link is opened (framing and timing INFERRED, [Q2](#dm-link-and-spl-framing)).
7. The TX-to-ADDRESS timing constant; HW CCM = software CCM (`radio.py selftest`).
8. HID throughput on the Frame; flash pairings surviving DFU.
9. That a real Quest's downlink matches the static TL header (HW-1, plaintext).
10. The on-air CRC trailer byte order (offline tools only; A9).

**Not implemented:** 11. PCM haptics, cmd 0x9d (3-bit ADPCM, R16); radio-fw answers
`LINK_ERR_PENDING_RE`.

**Protocol unknowns:**
12. **No real disconnect message is known.** A dropped controller's slot frees when it goes quiet; what
    cmds 0x05 / 0x06 / 0x13 do to the link is unstudied.
13. Meanings of ntf **0x20**, **0x21** and **0x2b**, and of the "trigger2" bits.
14. Content of the cmd 0x2b blob (one live read).
15. Sync-buffer (0x9b) sample rate; the 0xa0 frequency unit (Hz assumed).
16. Where, or whether, the controller checks an inbound host version (event 0x10, [Q6](#q6--pulsar-version-check)).
17. The inactive-seek RX pattern (R10).
18. What sets the plaintext-uplink bypass `LL+0x29c` (A4).
19. Connection-request bytes 23..24; beacon byte 0 bit 0; advert bytes 13..31.
20. ICM-47688 board config offsets (only if such a unit turns up).
21. Whether the user's HardwareRev 0x10 controllers run the `ruby` or `ruby_prq` image (both 207.5.0;
    [DEV-1 §1](re/DEV-1.md)). All RE here is against `ruby_prq`.
22. Which key the Quest uses to decrypt a 0x1d-paired controller on slot 0 (A20). Moot for TouchFrame.
23. Sniffing only: a Quest's netaddr is not on air nor readable over adb ([DEV-1 §4](re/DEV-1.md)), and
    how Android generates it is UNKNOWN. Use the address search (HARDWARE-DAY §4).
