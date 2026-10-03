# Touch Plus <-> Quest radio protocol ("Pulsar")

Static reverse engineering of the Meta "Pulsar" radio link between a Quest 3 headset
and its Touch Plus controllers, for building a non-Meta host on an nRF52840 dongle.

All evidence is from the user's own OTA (build 52433670048800520), extracted under the
gitignored `artifacts/quest/`. Nothing here reproduces Meta firmware; only our own
prose, addresses, and small struct tables. Reproduce the analysis with
`tools/ghidra/extract_images.py`, `fde_starts.py`, and `run.sh` (see end).

Status tags: **CONFIRMED** = read directly in code/data; **INFERRED** = strongly implied
by code plus public prior work; **UNKNOWN** = not yet established.

Names in `monospace` are the firmware's own (strings / `__FILE__`). Addresses are the
load address inside each image (see "Images" below), i.e. the address Ghidra shows.

---

## Gate A verdict: can a non-Meta host pair? **YES (INFERRED, near-confirmed).**

**There is no host authentication.** The controller's pairing module exposes only an
anonymous X25519 ECDH exchange followed by the host handing the controller an AES link
key. Nothing in the controller firmware verifies a host signature, certificate, or a
pre-shared Meta key before accepting a host:

- The controller's pairing code is `device_pairing.c` / `device_pairing_packet_handlers.c`
  / `x25519.c`. A full keyword sweep of both controller images (elk-spl = pairing/"DM"
  mode, elk-app = connected link) for `sign / cert / verif / attest / rsa / ecdsa /
  ed25519 / hmac / sha / hkdf / challenge / trust / attestation` returns **nothing** in
  the pairing path. The only asymmetric primitive present is Curve25519 (`x25519.c`); the
  only symmetric one is AES-CCM (`pulsar_crypto.c`).
- `bad_signing` exists, but it is an SPL **boot fallthrough reason** (the bootloader
  checks the *application image* signature during firmware update), not host
  authentication. `security_is_locked` / `unlock_request` are the factory/debug lock
  state, also unrelated to host identity.
- The host side has a **default AES key fallback**: `libsyncboss.so` reads the link key
  from `/data/misc/pulsar_aes_key.bin` and, on failure, logs
  `"Failed to read external aes key (continuing with default)"`. So even a real Quest can
  run with a baked-in default key.
- The one host-side gate is a *version* check, not a crypto check (see Q6). It is
  bypassable: `"Skipping version check for %08x%08x. This is normal for self-tracked
  controllers."` and env `SYNCBOSS_DISABLE_FW_VERSION_CHECK`.

**Consequence for TouchFrame:** an nRF52840 host can run the discovery -> X25519 ->
AES-key-provision -> connected-link sequence without possessing any Meta secret. The one
residual risk (INFERRED, not UNKNOWN-blocking) is whether the controller validates the
**Pulsar protocol version*** advertised by the host before leaving seek (it emits
`INVALID_HOST_PULSAR_VERION` / `"Invalid host Pulsar version detected, stopping seek"`);
that is a value we can match, not a secret. **No fallback reflash of the controller MCU is
required by Gate A.**

~~Residual UNKNOWN to close before trusting pairing end-to-end: the exact byte layout of
the `PairingData` (0x11) payload the controller decrypts and what it stores, and whether
the AES key is derived from the ECDH secret or sent under it.~~ **Closed** (Q2 "Pairing
data layout + key derivation" below, CONFIRMED both sides): the 16-byte link AES key is
**host-chosen and sent encrypted**, not derived; the ECDH shared secret is only the CCM
wrapping key (its first 16 bytes). Decrypted `PairingData` = `[4-byte connected-link base
address][16-byte AES link key]`.

---

## Images and load addresses (CONFIRMED)

Meta images start with a `dAeH` header (0x2e bytes): magic, checksum, header-len 0x2e,
image-kind (`0x01020304` app / `0x11223344` SPL / `0xeeddccbb` updater), payload-len,
format=2, **vector-table flash address** (the vector table sits at file offset 0x100), fw
version, 12-char git hash. Load base = `vectorAddr - 0x100`.

| Image | MCU | base | reset | git | role |
|---|---|---|---|---|---|
| `fw/ruby_prq/elk-app.bin` | nRF52820 | 0x14000 | 0x2b771 | edbf4671d29b | Touch Plus radio app (connected link) |
| `fw/ruby_prq/elk-spl-updater.bin` (embedded SPL @file 0x2ea0) | nRF52820 | 0x02000 | 0x09855 | 31970301f3a3 | Touch Plus bootloader / **DM (pairing) mode** |
| `odm/firmware/syncboss.bin` | nRF52833 | 0x00000 | 0x48c19 | (raw, vec@0x1100) | Headset radio MCU (the host we must emulate) |

`ruby` (the older variant) is identical in structure; `deerfly-app.bin` is the Renesas
RA2E1 input co-processor (not ARM; it owns the physical buttons/stick/trigger/captouch and
feeds elk over SPI). Unwind tables (`*-unwind.bin`, DWARF `.debug_frame`) give exact
function boundaries for `syncboss` (2220 fns) and the `ruby` elk-app (870 fns); the
`ruby_prq` elk-app and both SPLs have no unwind table, so their Ghidra function splitting is
rougher.

---

## Q1 — Radio PHY, channels, timing

**Modulation / framing (CONFIRMED where noted, else INFERRED from prior work + nRF HAL):**
- 2 Mbit/s Nordic proprietary mode (`RADIO_MODE`), **whitening off**. The stack is a Meta
  HAL called **Pulsar** layered PHY -> LL -> CL -> TL (`pulsar_phy.c`, `pulsar_ll_*.c`,
  `pulsar_cl_*.c`, `pulsar_tl_*.c`); the device and host sides mirror each other.
- **CRC-24, poly `0x00108421`, init `0x00FFFFFF`** — CONFIRMED as literal constants:
  `syncboss 0x52034`/`0x520a8`, `elk-app 0x316fc`/`0x31770`.
- Packet on air: 8-bit preamble, 5-byte address (4-byte base + 1-byte prefix), [S0],
  8-bit LENGTH, payload, 3-byte CRC. Two `PCNF0` variants exist, chosen per link
  (all CONFIRMED, see "Radio configuration per link" below): **connected link has a 1-byte
  S0 (always `0x04`)**, discovery/pairing and the 2402 DM beacon have **no S0**. The
  `syncboss FUN_00018058` TX/PER test path (LFLEN=8, S0=0) is not the live path.

### Radio configuration per link (CONFIRMED)

One PHY init sets everything: host `pulsar_phy.c` init `syncboss FUN_0001b61c @ 0x1b61c`,
device `elk-app` inline init at `0x25662..0x256b2`, controller DM/SPL `elk-spl FUN_000080c8`.
They take an nrf-HAL-style packet-config struct `{lflen, s0len, s1len, s1incl, cilen, plen,
crcinc, termlen, maxlen, statlen, balen, big_endian, whiteen}`.

| register | value | evidence |
|---|---|---|
| `MODE` | 1 = Nrf_2Mbit | `0x1b61c` (`+0x510 = 1`), elk-app `0x25688` |
| `MODECNF0` | 1 (fast ramp-up, 40 µs; device arms TXEN 0x28 µs early) | `+0x650 = 1`, elk-app `0x2565c`, `0x23fd4` |
| `PCNF0` connected | LFLEN=8, **S0LEN=1**, S1LEN=0, S1INCL=1 (RAM-only pad byte, nothing on air), PLEN=8-bit | host `0x1b61c` with `init.s0=1` from `FUN_0001e150`; device struct `{8,1,0,1,..}` elk-app `0x2566e` |
| `PCNF0` discovery / pairing / DM beacon | LFLEN=8, **S0LEN=0**, S1LEN=0, PLEN=8-bit | host DM init `FUN_00020440` (`s0=0`); runtime toggle `syncboss FUN_0001bfbc(1)`; device DM event `elk-app FUN_00023d6c` writes `s0len=0` |
| `PCNF1` | BALEN=4, ENDIAN=big, STATLEN=0, WHITEEN=0; MAXLEN host-connected **59** (`0x13b` literal at `syncboss 0x1e1e6`), device-connected **130** (`0x82`, elk-app `0x25674`), DM/pairing **255** | `+0x518 = maxlen \| 0x1040000` |
| `CRCCNF` | 3 = 24-bit, **SKIPADDR=0 (address is included in the CRC)** | host `0x1b61c`, device `0x2569c`; the device also re-checks the CRC in software over bit-swapped base bytes, prefix, S0, LENGTH, payload (`elk-app FUN_00024164`) |
| `CRCPOLY` / `CRCINIT` | `0x108421` / `0xFFFFFF` | as above |
| whitening | off (`WHITEEN=0`) | `PCNF1` value above |
| `SHORTS` | `0x113` (READY_START, END_DISABLE, ADDRESS_RSSISTART, DISABLED_RSSISTOP) | both images |

Logical-address use: `BASE0` and `BASE1` are always written with the **same** 32-bit value
(`syncboss FUN_0001bb78`, elk-app `0x256aa`), except the host connected link which puts
`0xFACEB00C` in `BASE0` (for AP0) and the network address in `BASE1` (`FUN_0001bb60`). TX is
always logical address 7 on the host (`FUN_0001bb90` writes AP7 + `TXADDRESS=7`); the
device TXes on logical 7 too (`elk-app FUN_00028ad0`). Uplink RX prefixes are set by
`syncboss FUN_0001bbb8` (AP1..AP6 from a list, AP0 separately).

**Access addresses (CONFIRMED):**
- **Discovery: prefix `0xAA` + base `0xFACEB00C`, 2402 MHz, S0=0.** Host listens
  (`syncboss FUN_000207c8`, `FUN_000208dc`); the controller SPL advertises to the same
  address (`elk-spl 0x7f60`: base, `FUN_00007e9c` = TX/RX prefix 0xAA, freq 2).
- **Pairing ("DM link"): prefix `0xAA` + base = the controller's 64-bit device ID low word,
  2426 MHz, S0=0, MAXLEN 255.** The device ID is the controller's **FICR `DEVICEID[0..1]`**
  (`elk-spl FUN_00006e4c` reads `0x10000060`), stored at DM state `+0x28` and used as base at
  `elk-spl 0x8008..0x8016` (freq `0x1a`). Host side: `syncboss FUN_00020cc4(id_lo, id_hi)`
  selects the target, `FUN_000204f0` sets `BASE = id_lo`, prefix 0xAA, freq `0x1a`.
- **Connected link: base = the host's 4-byte "network address"**, provisioned by Android
  (`pulsar_host_init` console arg "4-byte network address"; `libsyncboss` persists it in
  `/persist/pulsar/pulsar_host_address.bin`) and handed to the controller in pairing. Host
  init chain `FUN_00019e4c -> FUN_0001d300 (pulsar_cl_host.c) -> FUN_0001e5dc
  (pulsar_ll_host.c, stores it at LL+0x50) -> FUN_0001e150` (PHY setup). Device copy at
  elk-app LL `+0x1e4`. It is **not derivable** from anything on air (UNKNOWN per headset).
  - **Host TX prefix `0xF0`** (`FUN_0001e150` -> `FUN_0001bb90(0xf0)`); device RX = AP1
    `0xF0` (`elk-app 0x25794`).
  - **Device TX prefix = slot + 1, i.e. `0x01..0x05`** (`syncboss FUN_0001ab84` returns
    `slot+1`, `slot < PULSAR_NUM_DEVICE_SLOTS + PULSAR_NUM_AUXILIARY_DEVICE_SLOTS = 5`;
    elk-app `FUN_00028ad0` sets AP7 = `slot+1`). Host RX = AP1..AP5 = `0x01..0x05` on
    `BASE1`, plus AP0 = `0xAA`/`0xFACEB00C` enabled only during DM beacons
    (`FUN_0001bc9c(1)`) so it can hear advertising controllers.

**Channel list + hopping (CONFIRMED):**
- `PULSAR_NUM_CHANNELS = 37`. `pulsar_ll_channels.c` logical-channel -> frequency lookup is
  `syncboss FUN_0001ac24 @ 0x1ac24`, table at `0x4fe70`. The 37 entries are nRF
  `FREQUENCY` values (MHz above 2400):
  `4 6 8 10 12 14 16 18 20 22 24  28 30 32 34 36 38 40 42 44 46 48 50 52 54 56 58 60 62 64 66 68 70 72 74 76 78`
  i.e. **2404–2478 MHz, 2 MHz spacing, skipping 2402 (discovery) and 2426 (pairing)**.
- Host distributes an active-channel bitmap and runs **adaptive FHSS** with a frequency
  blocklist: `adaptive_fhss.c`, `pulsar_host_get_ch_map` ("channel map distributed by the
  Host"), `"channel map: %05X%08X, active channels: %d"` (`syncboss FUN_00006dd8 @ 0x6dd8`),
  host blocklist via `vendor.syncbosshal.pulsar_blocklist`. A map needs >= 8 channels
  (`syncboss FUN_0001aa30`, elk-app beacon parse).

**Hop rule = BLE Channel Selection Algorithm #1 over 37 logical channels (CONFIRMED both
sides: host `syncboss FUN_0001aaf4`, device `elk-app FUN_00023d6c`):**
- `hop = (netaddr & 0xFF) % 11 + 5` (range 5..15). Host `FUN_0001e150` (`0xba2e8ba3`
  reciprocal = /11), device `elk-app 0x245c6` (`udiv` by 11, `+5`).
- Per beacon period: `unmapped = (unmapped + hop * n) % 37` (n = periods advanced, normally
  1). If `unmapped` is not in the map, `idx = used[unmapped % num_used]` where `used[]` is the
  ascending list of enabled logical channels; else `idx = unmapped`. `FREQUENCY =
  table[idx]` (`FUN_0001ac24`). Initial state at host LL start: map = all 37, `unmapped = 0`
  (`FUN_0001a85c`).
- The beacon carries the map and the current `unmapped` value (layout below), so a sniffer
  can lock on from any single beacon once it knows `netaddr`.
- **DM beacons:** while the host is scanning for advertising controllers
  (`pulsar_ll_dm_scan.c`, `FUN_0001f3f8/0x1f53c/0x1f65c`), some beacon periods are spent on
  **2402 MHz instead of the hop channel**, with S0 off (`FUN_0001bfbc(1)`) and AP0 RX enabled
  (CONFIRMED in `FUN_0001dbf8`). The hop counter still advances. When the DM-scan state is
  active the host also adds one extra 2000 µs period and one extra hop step before the next
  beacon (`iVar4 = 4000` branch of `FUN_0001dbf8`) — INFERRED reading; a follower should
  simply re-sync from byte 5 of every beacon. Spacing between DM scans is pseudo-random (xorshift16
  seeded with `netaddr & 0xFFFF`, `(r % 20) + 5` periods; `FUN_0001f65c`, `FUN_0001e5dc`) —
  INFERRED. The beacon announces it: payload byte 0 bits 1..2 = periods until the DM beacon
  (device sets its DM event at `counter + ((b0 & 7) >> 1)`, elk-app `FUN_00024164`).

**Timing (CONFIRMED unless noted):**
- **Beacon interval 2000 µs (500 Hz).** Host advances its beacon clock by 2000 per beacon
  (`FUN_0001dbf8`, `LL+0x5e4 += 2000`); device expects the next beacon at
  `last_anchor + (missed + 1) * 2000` (`elk-app FUN_00023e54`, and `/ 0x7d0` at `0x23f20`).
  Device anchor = TIMER capture at ADDRESS − 20 µs (`elk-app FUN_00024164`).
- **Device RX window:** centred on the expected beacon, base length 252 µs, widened by
  `elapsed × 40 ppm + 6 µs` per side (`(n+1)·80000/1e6 + 6`), capped at 920 µs
  (`FUN_00023e54`). Disconnect after `PULSAR_DEVICE_MISSED_BEACONS_BEFORE_DC` misses.
- **Uplink slots:** device in slot `s` (0..4) transmits at `anchor + 350 + off[s]` µs with
  `off = {0, 225, 525, 825, 1125}` (table `elk-app 0x32504`, `+0x15e` in `FUN_00028ad0`);
  so slot starts are 350 / 575 / 875 / 1175 / 1475 µs after the beacon, the last one ending
  well before the next beacon. Which time base `anchor` refers to (this beacon) is INFERRED.
- **Ack scheme:** the host has no immediate per-packet ack. Each received uplink sets bit
  `slot` in an rx mask (`mark_rx_mask`, `syncboss FUN_0001cdcc`) which is sent in the
  **next beacon** (payload byte 15) and then cleared (`pulsar_cl_host.c` prepare_beacon
  `FUN_0001cf30`). CONFIRMED that the bitmap is sent; its use by the device for
  retransmission is INFERRED.

**Beacon (host -> all, prefix `0xF0`, S0 = `0x04`) payload layout (CONFIRMED; builder
`syncboss FUN_0001dbf8` into `LL+0x5e8`, parser `elk-app FUN_00024164`):**

| payload byte | content |
|---|---|
| 0 | bit0 reserved (UNKNOWN), bits1..2 = periods until DM beacon (0 = none), bits3..7 = channel map bits 0..4 |
| 1..4 | channel map bits 5..36 (37-bit map, LSB first; byte 4 bits3..7 = map bits 32..36) |
| 5 | current `unmapped` channel (0..36) |
| 6..7 | 16-bit value from host init right after the AES key = the **session nonce** (INFERRED name; CONFIRMED plumbing `FUN_00019e4c -> FUN_0001e5dc +0x54`). The device puts it in the top 16 bits of its 64-bit CCM packet counter (`elk-app 0x240cc`). |
| 8..13 | 48-bit beacon timestamp, µs on the sync clock, little-endian (`LL_BITS_IN_BEACON_TIMESTAMP` = 48) |
| 14 | CL: `1 << slot` of the device addressed by downlink data in this beacon, else 0 (INFERRED meaning) |
| 15 | CL: **rx/ack bitmap** of slots heard since the last beacon |
| 16.. | CL data, <= 34 bytes (`CL_HOST_MAX_PAYLOAD_LEN`); a 36-byte connection-negotiation variant exists |

LENGTH is 14..50 (`"Beacon length too large"`, assert `<= 0x32`). The beacon header is
built and parsed in clear (no CCM call in either path) — INFERRED plaintext; uplink and CL
data are CCM-encrypted (Q3). Uplink packets also carry S0 = `0x04`, LENGTH <= 126
(`LL_DEV_MAX_PAYLOAD_LEN`, elk-app `0x24046`).

**Discovery advertisement (controller -> 2402, S0 off, LENGTH = 32; CONFIRMED layout from
`elk-spl FUN_000080c8` + `0x7f70`, host parse `syncboss FUN_000208dc`):**
`[0] type = 2`, `[1..4]` 32-bit info word (`0x01, 0x17, hw, hw` at build time; `[1..2]` =
**Pulsar version `0x1701`** = major 1 / sub 23, CONFIRMED in Q6; `[3..4]` hw INFERRED),
`[5..12]` 64-bit **device ID (FICR DEVICEID)**, `[13..16]` 32-bit word
(UNKNOWN), `[17..30]` 14 bytes (UNKNOWN, from `elk-spl FUN_00003418`), `[31]` 1 byte. The host
also accepts a type-1 variant with the ID at `[6..13]`.

**Pairing link (2426) framing (INFERRED):** host-polled ping-pong: host TX
(`FUN_000204f0` / `FUN_00020628`), then RX window ~900..2000 µs (`FUN_00020738`,
`FUN_0001be1c(900, 2000)`), up to 666 (`0x29a`) misses before giving up (`FUN_00020a70`).
Payload `[ctrl][seq][data...]`, ctrl bit0 / bit7 are flags, `seq` is checked by
`FUN_0001a6fc`.

**Clock:** a 1 µs sync timer (`pulsar_sync_timer.c`, `"Timer precision must be 1 us"`) and a
time translator (`time_translator.c`) align host and device clocks via the beacon timestamp;
this same clock drives the camera-sync LED strobe (Q4).

---

## Q2 — Pairing flow

**Controller side (SPL "DM" mode, elk-spl):** `device_pairing.c`, `x25519.c`.
- `pairing_get_public_key` returns the controller's Curve25519 public key.
- `pair_ecdh` consumes the host public key and an encrypted blob; it checks state and
  `"incorrect decrypted length"`. ECDH scalarmult + decode is `FUN_0000934c @ 0x934c`
  (calls Curve25519 inner routines `FUN_00004414/000043a0/000044a4`); pairing buffers (4×32
  bytes: host pub, device pub/priv, shared, decrypted) are zeroed by `FUN_000039bc @ 0x39bc`.

**Message IDs (now CONFIRMED from the SPL command dispatcher `elk-spl FUN_0000822c @
0x822c`):** the command byte is `[bit0 = read/request vs write][bits1..6 = command
number][bit7 reserved]`; `FUN_0000822c` splits on bit0, then `switch((b & 0x7f) >> 1)`.
Confirmed numbers: `SetupX25519Keys = 0x12` (read/odd branch, returns a 32-byte payload =
the controller public key, via `thunk_FUN_00003948`), `PairingData = 0x11` (write/even
branch → `FUN_00003abc`), `WriteAESKey = 0x14`, `Reset = 0x15` (→ `FUN_00002a04`). A second
pairing-data variant `0x1d` (→ `FUN_00003ac6`) exists (see below). **`WriteAESKey 0x14` is
a no-op stub in this SPL image** (`FUN_000081bc` just `return 0`, like all the `0x81xx`
app-mode entries) — the link key is committed inside the `0x11` handler itself, so TouchFrame
does not need to send a separate `0x14`. Commands ride the SPL framing (2-byte header =
cmd + seq, then payload, then CRC); the handler receives `payload = packet + 2`.

**Host side (syncboss + libsyncboss):** `pulsar_manager_pair`,
`pulsar_manager_enumerate_advertising_devices`, `syncboss_input_pair`,
`syncboss_starlet_enter_pairing_mode`, `syncboss_set_host_pulsar_pairing_info` /
`get_host_pulsar_pairing_info` (structs `syncboss_set_host_pairing_info_t` /
`syncboss_host_pairing_info_t`). Host AES key: `/data/misc/pulsar_aes_key.bin`, default
fallback. `pulsar_host_init` console takes a "16-byte AES key as a hex string" and a
"16-bit session nonce" (`session_nonce`).

### Pairing data layout + key derivation (CONFIRMED, both sides)

No host auth (Gate A). The flow is: `0x12` establishes the X25519 shared secret, then `0x11`
hands the controller an AES-CCM-wrapped blob that **contains** the link key and the new base
address. **The 16-byte link AES key is NOT derived from the ECDH secret — the host chooses it
and sends it encrypted.** The ECDH shared secret's only job is to be the CCM *wrapping* key.

**KDF from the shared secret (CONFIRMED):** the 16-byte CCM wrapping key = the **first 16
bytes of the 32-byte X25519 shared secret, plain truncation — no hash, HKDF, or SHA.**
Controller: `FUN_00003abc` computes the shared secret into a buffer (`FUN_000093c0`, an
X25519 scalarmult of the stored device-priv × host-pub), then `FUN_0000909c` → `FUN_00009084
@ 0x9084` copies exactly **4 words (16 bytes)** of it into the nRF CCM KEY field. Host mirror:
`syncboss FUN_00047604 @ 0x47604` arms CCM with the key at host-struct `+0x61` (this is the
"legacy nonce / connection negotiation" crypt of Q3 — the pairing wrap and the Q3 negotiation
crypt are the *same* operation).

**`PairingData` (0x11) on-wire payload = 32 bytes** (CONFIRMED from `FUN_00003abc`'s
`FUN_00009198(payload+8, …, 0x18, …, payload[0..3], payload[4..7], 0, 0)` and host builder
`FUN_00047604`):

| payload offset | bytes | content |
|---|---|---|
| 0 | 8 | **CCM IV/nonce**, random, in the clear (host fills via RNG at struct `+0x88`; packet counter = 0 — the Q3 "legacy nonce") |
| 8 | 24 | AES-128-CCM ciphertext of the 20-byte plaintext below + **4-byte MIC** |

**Decrypted plaintext = 20 bytes** (`FUN_00009198` returns `len-4 = 0x14`; mismatch logs
`"incorrect decrypted length"` @ `elk-spl 0xf11c`, `FUN_00003abc` `iVar4 != 0x14` branch):

| plaintext offset | bytes | content |
|---|---|---|
| 0 | 4 | **new connected-link base address** (the host `netaddr`, host source `FUN_00045a6c`) |
| 4 | 16 | **16-byte AES link key** (host source `FUN_000439bc` = `/data/misc/pulsar_aes_key.bin` or default) |

The controller stores it via `FUN_000038e8 @ 0x38e8` into its paired-device record: the full
20 bytes at record `+0x00` (so base address at `+0x00`, key at `+0x04`) and a second copy of
the 16 key bytes at record `+0x14`. That record's key is what the connected-link CCM block
(Q3) later loads.

**Variant `0x1d` (`FUN_00003ac6`, derived-key mode):** identical decrypt, but it calls
`FUN_000038e8(decrypted, shared_secret)` — i.e. it keeps the base address from the decrypted
payload but sets the link key = **first 16 bytes of the ECDH shared secret** (ignoring the
key bytes in the blob). `0x11` passes flag `0` to `FUN_000093c0` and stores the transmitted
key; `0x1d` passes flag `1` and stores the derived key. TouchFrame should use **`0x11`** (we
pick the key) and can ignore `0x1d`.

---

## Q3 — Connected-link cipher (CONFIRMED)

**nRF hardware AES-128-CCM** (`pulsar_crypto.c`), not a custom cipher.
- Setup `syncboss FUN_0001b0a4 @ 0x1b0a4`: writes the CCM config-pointer register
  (`CNFPTR`, base+0x508), arms `ENABLE/EVENTS` and the scratch/out pointers.
- Crypt `syncboss FUN_0001b1a4 @ 0x1b1a4`: builds a 3-byte CCM header in RAM
  (`[0]=flags/0, [1]=length, [2]=0`), programs the nonce fields (packet counter at
  cfg+0x124, direction/IV at cfg+0x129/+0x12d), triggers the task, spins on the ENDCRYPT
  event, then copies out `length + 4` bytes.
- **MIC = 4 bytes** (`len >= PULSAR_CRYPTO_MIC_LENGTH`; crypt returns `len+4`).
- **Nonce** = packet counter (`pktctr < 2^PULSAR_CRYPTO_BITS_IN_PKTCTR`) + direction bit +
  per-session IV. `"Must use legacy nonce for connection negotiation"` (elk-app) shows a
  distinct nonce format is used during connection negotiation vs. the steady link.
- **Key** = the 16-byte AES key provisioned at pairing (Q2), held in the CCM config block.

**CCM config block layout (CONFIRMED, standard nRF BLE-CCM; setup `FUN_0001b0a4`, crypt
`FUN_0001b1a4`):** `CNFPTR` points at `cfg+0x110`:
- `+0x110` KEY, 16 bytes;
- `+0x120` PACKETCOUNTER, 5 bytes little-endian (39-bit counter; crypt writes the low 32 bits
  from `param_7` to `+0x120` and the 5th byte from `param_8` to `+0x124`, asserting `param_8 <
  0x80`, i.e. 7 more bits);
- `+0x128` DIRECTION (1 byte; bit0 — host vs device);
- `+0x129` IV, 8 bytes (crypt writes `param_5` to `+0x129` and `param_6` to `+0x12d`).
So the 13-byte CCM nonce = `packetCounter[5 LE] || IV[8]`, with the direction bit as bit 0 of the
byte at `+0x128` (the counter and direction live in adjacent fields, as in BLE CCM).

**Connection-negotiation ("legacy") nonce (CONFIRMED, `syncboss FUN_00047604`):** the one software
crypt call sets KEY at host-struct `+0x61`, fills an **8-byte random IV** at `+0x88` (RNG
`FUN_000185d8`), and calls crypt with **packet counter 0** (`param_7 = param_8 = 0`), encrypting a
20-byte blob to `+0xa1` and checking the result is 24 bytes (20 + 4 MIC). The random IV is sent in
the clear with the negotiation packet. This is the "Must use legacy nonce" path.

**Steady-state link:** there is no other software crypt call, so per-packet CCM runs inline in the
RADIO↔CCM hardware chain; the LL updates PACKETCOUNTER and the session IV in the config block each
packet. Two hypotheses for the steady-state IV, both **INFERRED, not pinned**: (a) the negotiation's
8-byte random IV is **reused** for the session — `FUN_00047604` copies it from `+0x88` to `+0x99`
right after the negotiation crypt, which is exactly what a saved session IV looks like — with only
the packet counter advancing; or (b) the Q1 packing where the 16-bit session nonce rides the top
bits of the counter and the IV is timestamp-derived. This does not block decoding: capture the
negotiation packet (its first 8 payload bytes are the IV, in the clear) and run
`tools/pulsar_crypto.py scan --key <k> --capture conn.jsonl --iv <those 8 bytes>`, which sweeps the
counter against hypothesis (a); a correct 4-byte MIC confirms key + IV + counter from one packet.
Without the IV, `scan` falls back to the (firmware-contradicted) session-derived guesses of (b).

---

## Q4 — Live reports and host->controller commands

**Controller -> host input — there is NO HID report descriptor (CORRECTED, CONFIRMED).**
A full keyword sweep of all three images + `*.strings` finds **no** `hid`,
`report_descriptor`, `PULSAR_PKT_ID`, `pulsar_manager_read_sync`, or `attachment_info`
token (earlier drafts asserting a self-describing HID descriptor were ungrounded — the host
SoC/Android side owns HID, not this firmware). Instead the controller exposes input through a
**host-register ("hreg") table** the headset reads over Pulsar. There is therefore **no single
packed on-air input report**: each field is an individually-addressable register value.

**Report assembler = `elk-app FUN_000173bc @ 0x173bc`** (`input_mcu_thread`, CONFIRMED). Each
cycle it (1) reads the Renesas "deerfly" input-MCU **register `0x37`** over SPI —
`FUN_00021fd4(0x37, buf, 0x3d)`, a **61-byte** sample; (2) verifies a 4-byte checksum
`FUN_00029f4c(buf, 0x39)` against `buf[0x39..0x3c]`; (3) re-packs the fields into elk
host-facing registers via `FUN_0001f464(reg_id, &value)` and the edge/bit variant
`FUN_0001f748(value, len)`. The elk hreg table is at **`0x2e7dc`** (0x10-byte entries, valid
IDs `0..0x2d`; payload size = low byte of `entry+0xc`; ID->index check `FUN_0001cf28 @
0x1cf28`). Two **register spaces** must not be conflated: deerfly-MCU regs (read over SPI,
e.g. reg `0x37` = sample, reg `0x02` = present-subreport flags) vs the elk host-facing hreg
registers below (read by the headset over Pulsar). Physical inputs originate on deerfly
(`input_sampling.c`, `thumbstick.c`, `pinch.c`, trigger min/max cal); captouch is
post-processed host-side (`update_captouch`).

**Deerfly sample (reg `0x37`, 61 bytes) — offsets CONFIRMED, semantic labels INFERRED**
(deerfly firmware is not in these dumps, so which analog = which axis and which bit = which
labelled button is set there, not here). All offsets are into the 61-byte buffer; citations
`FUN_000173bc @ 0x173bc`:

| off | size | → hreg | field (CONFIRMED packing / INFERRED meaning) |
|---|---|---|---|
| 0x00 | 4 | reg 2 (4B) | sample counter / timestamp (INFERRED) |
| 0x04 | bits0..4 | reg 4 (bits0-3) + reg 0x2b (bit4) | touch / proximity flags (remap mostly CONFIRMED; out2/out3 contested — see below; meaning INFERRED) |
| 0x05..0x14 | u16×several | reg 8 (10B) | capacitive-touch raw channels (INFERRED) |
| 0x0f..0x1a | u16×several | reg 0x21 (12B) | cap-touch raw channels (INFERRED) |
| 0x1b..0x20 | u8/u16 | reg 0x20 (6B) | sensor channels (INFERRED) |
| **0x21** | 1 (8 bits) | reg 9 (4B) | **buttons** (CONFIRMED this is a button byte; bit map below) |
| **0x22** | 1 (4 bits) | reg 9 | **buttons** (CONFIRMED) |
| **0x23** | 12-bit | reg 3 (3B) | **analog axis A** — trigger/grip/stickX/stickY (CONFIRMED analog; which-is-which INFERRED) |
| **0x25** | 12-bit | reg 3 | **analog axis B** (CONFIRMED analog; identity INFERRED) |
| 0x2d..0x30 | packed | reg 0x17 (8B) | analog/aux (INFERRED) |
| **0x31** | 12-bit | reg 0x17 | **analog axis C** (CONFIRMED analog; identity INFERRED) |
| **0x33** | 12-bit | reg 0x17 | **analog axis D** (CONFIRMED analog; identity INFERRED) |
| 0x35 | bits | reg 0x17 | aux (INFERRED) |
| **0x37** | 2 | reg 0x15 (2B) | **battery** mV (INFERRED unit/scale) |
| 0x39 | 4 | — | checksum over `[0x00:0x39]` (`FUN_00029f4c`; CRC/sum INFERRED) |

The **four clean 12-bit ADC analogs at buffer `0x23 / 0x25 / 0x31 / 0x33`** are exactly the
{trigger, grip, thumbstick-X, thumbstick-Y} set (12-bit matches the RA2E1 ADC; elk cal strings
`db.x.min/max`, `db.y.min/max` = stick X/Y, `inner/outer` + `Pinch (%d mN, %d)` = trigger/grip
confirm the controller has exactly these four analogs). Binding each offset to a specific axis
needs the deerfly firmware.

**Button bit remap into reg 9 (CONFIRMED math, `FUN_000173bc`)** from deerfly `b=buf[0x21]`,
`c=buf[0x22]`: out0=b.0, out1=b.2, out2=b.4, out3=c.2, out4=b.6, out5=b.1, out6=b.3, out7=b.5,
out8=b.7, out9=c.3, out10=c.0, out11=c.1 (12 button bits). Which output bit is A/B/X/Y/menu/
system/stick-click is set in deerfly (UNKNOWN here).

**Flag remap** from deerfly `buf[0x04]`: `reg4.out0=in.1`, `out1=in.2`, and `reg 0x2b = in.4` are
CONFIRMED (agree across two independent reads of `FUN_000173bc`). The `out2`/`out3` pair is
**contested**: one read gives `out2=in.0, out3=in.3`, the other `out2=in.3, out3=in.0` — the latter
ordering may actually be the parallel 10-bit edge write `FUN_0001f748(value,10)`, not the hreg-4
write `FUN_0001f464(4,…)`. `tools/pulsar_input.py` exposes both orderings (`touch_flags_reg4` vs
`touch_flags_edge10`) so one live capture settles it. (Meaning touch vs proximity is INFERRED.)

**IMU is a separate path (CONFIRMED):** elk pushes IMU to **reg 0xb** (12B, `FUN_00014c1c @
0x14c1c`) and **reg 0x16** (2B, `FUN_00014c38 @ 0x14c38`) from the elk-side ICM426xx/476xx
(`imu_thread.c`) — not part of the deerfly sample.

**For TouchFrame:** to read a controller's input over the dongle, subscribe to / poll the
hreg registers (buttons=9, analogs=3 & 0x17, touch flags=4 & 0x2b, cap-touch channels=8/0x20/
0x21, battery=0x15, IMU=0xb/0x16). There is no descriptor to parse and no packed report to
unpack; the deerfly byte offsets above are the pre-pack source, not on-air offsets.
- **IMU:** TDK ICM-42686 / ICM-47688 (`icm426xx_imu.c`, `icm476xx.c`, string `ICM47688`).
  Scales/timestamp units **UNKNOWN** (in the IMU config JSON, Q5).
- **Battery:** `GetBatteryStatus 0x2F` (prior work); host
  `syncboss_internal_input_get_battery_voltage` / `set_battery_percentage`.
- Report rate: at most one uplink per slot per beacon = **500 Hz per controller**
  (INFERRED from the 2000 µs beacon interval, Q1); actual streaming cadence UNKNOWN.

**Host -> controller commands (CONFIRMED names):**
- **Haptics:** `syncboss_input_set_haptic`, `set_multi_haptics`, `send_haptic_syncbuffer`,
  `append_haptic_syncbuffer`, `send_pcm_haptics` (PCM waveform streaming). Controller side:
  `pcm_haptics_manager.c`, `haptics_ux.c`.
- **LED strobe / camera sync (CONFIRMED):** host `pulsar_manager_set_led_timing`,
  `set_led_ontime_us`, `set_led_period_delay_us`, `refresh_controller_led_config`,
  `syncboss_input_set_led_ontime_us`, `syncboss_led_set_on_time_and_current(_v2)`.
  Controller side `irled_manager.c` / `sync_trigger.c` with a PWM synctrig driven off the
  shared Pulsar clock; config validated by `"IR LED configuration rejected: p=%lu, ot=%lu,
  d=%li"` (**p = period, ot = on-time (~15–100 µs exposure window), d = delay/phase**). This
  is exactly the LED-phase-vs-camera-exposure knob TouchFrame needs for 6DoF (Gate B).
  IR-LED config notification struct: `ntf_reg_irled_config_t`
  (`controller_process_irled_config_ntf_data` in libsyncboss). LED masks/groups:
  `syncboss_led_group_ids_on_off`, `led_on_off`, `trigger_start_stop`, `single_trigger`.

---

## Q5 — Calibration (CONFIRMED paths; values on device)

- **IMU + input calibration** live on the controller and are read by the host:
  `syncboss_input_get_calibration_data(id, type, buf, len)`; controller user-cal in
  `user_calibration_*.c` (shared / input-MCU / hreg-host), committed to flash ("Committing
  calibration"). IMU parameters as JSON: host `syncboss_imu_config_get_json(_with_id)`,
  `syncboss_imu_get_parameters_json`.
- **Thumbstick user cal:** `syncboss_input_{get,set,clear}_thumbstick_user_calibration`
  (`syncboss_input_thumbstick_calibration_t`); trigger min/max on deerfly.
- **LED 3D positions / normals:** NOT in the controller's own readable cal in these images.
  Per `docs/FEASIBILITY.md`, the Frame/Quest tracker takes LED `modelPoints` / `modelNormals`
  from a per-controller **`lighthouse_config` JSON** keyed by controller serial
  (`GetSN 0x03`). For TouchFrame this means the LED geometry is a static per-unit table we
  supply to the tracker, not something streamed live. Exact on-device storage of LED geometry
  is **UNKNOWN** (may only exist in Meta's cloud/headset cal store).

---

## Q6 — "Pulsar" host version check (CONFIRMED; value pinned, bypassable)

- **The version value is `0x1701` (CONFIRMED).** The controller's Pulsar protocol/CL version
  is a 16-bit little-endian field = on-air bytes **`01 17`**: **major/CL version = `0x01` (1)**
  and **`pulsar_protocol_sub_version` = `0x17` (23)**. It is the **only** `0x1701` immediate in
  the controller image and is **absent from `syncboss`** (no literal) — load-bearing evidence it
  is the controller's own protocol generation (git `edbf4671d29b`).
  - Written by the CL device init `elk-app FUN_00018a24`, at **`0x18b90`:
    `movw r3,#0x1701 ; strh r3,[r4,#8]`** into the controller's connection record at
    **RAM `0x20004ec0+8`** (`+8`=`0x01`, `+9`=`0x17`; `+0/+4`=64-bit peer ID, `+0xc`=slot,
    `+0xd`=slot-count).
  - Echoed outward in the connection-response builder (`elk-app FUN_00023aa8`, from **`0x23bc4`**:
    writes `0x19`,`0x11`, then reads the connection record `0x20004ec0` and copies its fields,
    including the `+8` version, into the outgoing packet).
  - Cross-checks: this is exactly the discovery-advert info word `[1..4] = 01 17 hw hw` (Q1) and
    the telemetry fields "`cl version: %u`" / "`pulsar_protocol_sub_version`"
    (`syncboss 0x5ce10` / `0x5e564`).
- **The seek-stop reaction is CONFIRMED.** Event enum index `0x10` = `INVALID_HOST_PULSAR_VERION`
  (name table ~elk-app line 9814). Its handler is the **"seek" state handler** installed as a
  state-machine callback at flash **`0x33210`** (record base `0x33200`, 0x14-byte records
  `{state*, state*, name*, key, handler}`; name string "seek" @`0x2c8b0`); the unwind table
  gives its real entry **`0x14964`** (Ghidra misnames it `FUN_00014960` — bytes `0x14960..63`
  are the previous function's literal pool). On event `0x10` it allocates a log slot
  (`bl 0x25bc4`), stores msg ptr `0x2c881` ("Invalid host Pulsar version detected, stopping
  seek"), logs via `0x295fc`, returns action **5**, and tail-branches to the seek-stop
  transition **`0x20b88`** (which indexes the RAM state table `0x20000390`, stride 0x14). It also
  emits `incompatible_version` LL counters. This is a numeric compatibility gate, **not**
  cryptographic.
- **Where the inbound host version is compared is NOT pinned (honest gap, non-blocking).** The
  controller's connection-negotiation accept handler (`FUN_00023aa8`, case at `0x23af8`)
  validates only packet type (`[0]==1`), the 64-bit peer ID (`[3..10]` vs `0x20004ec0+0/+4`),
  endpoint (`[2]&7`: 2=CONN_NEG, 3=lock), and slot (`[11]`, assert str `0x303b9`) — it reads the
  `+8` version only to *send* it, never comparing an inbound value. The instruction that reads a
  host version and raises event `0x10` appears to live in the low-level region Ghidra left as raw
  bytes (~`0x20000..0x20600`, near the `"Received connection rejection from host"` handler, pool
  str `0x2f671` @ code ~`0x20598`); the disassembler returns nothing usable there. So it is
  unresolved whether the controller inspects an inbound host-version byte at all, or whether
  "stopping seek" is instead triggered after the **host** rejects the controller.
- **The analogous check on the real host is explicitly skippable**
  (`SYNCBOSS_DISABLE_FW_VERSION_CHECK`, `persist.vendor.syncbosshal.disable_fw_version_check`,
  "normal for self-tracked controllers") — evidence the gate is policy, not security.
- **For TouchFrame:** advertise Pulsar version **`0x1701`** (on-air `01 17`, i.e. major 1 /
  sub 23) wherever the host version goes in the connection-negotiation CL payload, and make the
  emulated host **never reject the controller** (emulate the skip-version-check path). Both
  failure modes are then covered: if the controller does compare an inbound version it matches
  its own `0x1701` generation; if the stop-seek is actually driven by a host rejection, our host
  never issues one. A live capture is the only way to decide which, but neither blocks bring-up.

---

## Sniffer recipes (`radio-fw`, `sniffer_config_t`)

Common to all three: `mode = 1` (Nrf_2Mbit), `balen = 4`, `big_endian = true`, `lflen = 8`,
`s1len = 0`, `statlen = 0`, `crc_len = 3`, `crc_poly = 0x108421`, `crc_init = 0xFFFFFF`,
`crc_skip_addr = false`, whitening off, 8-bit preamble. Program `base`/`prefix` with the
same register values the firmware uses (no bit swapping: both ends are nRF52 radios).

| link | frequency | base | prefix | s0len | maxlen | hop |
|---|---|---|---|---|---|---|
| 1. discovery (adverts) | 2 | `0xFACEB00C` | `0xAA` | 0 | 255 | none |
| 2. pairing | 26 | controller `DEVICEID[0]` = advert bytes 5..8 read as LE u32 | `0xAA` | 0 | 255 | none |
| 3a. connected, host beacons + downlink | per hop | host `netaddr` | `0xF0` | 1 | 255 (>= 130) | CSA#1, 2000 µs |
| 3b. connected, uplink | per hop | host `netaddr` | `0x01..0x05` (slot+1) | 1 | 255 | CSA#1, 2000 µs |
| 3c. connected, DM beacon (fixed rendezvous) | 2 | host `netaddr` | `0xF0` | 0 | 255 | none |

Notes for the connected link:
- `netaddr` is the one thing a sniffer cannot get from the air without luck (UNKNOWN per
  headset; stored in `/persist/pulsar/pulsar_host_address.bin`). Because the CRC covers the
  address, any candidate address can be verified offline against a captured packet.
- To see both directions at once the sniffer needs several logical addresses (AP for `0xF0`
  plus `0x01..0x05`, all on the same base); the current `sniffer_config_t` has one prefix.
- With a full map the 37-step CSA#1 sequence is fixed per `netaddr` (37 is prime, so every
  channel is visited once per 74 ms); a static `hop_list` of 37 entries at 2 ms dwell works
  only if started in phase. Better: park on 3c or any one channel, catch a beacon, then
  follow using payload byte 5 (`unmapped`), bytes 0..4 (map) and `hop`.

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
# helpers used above:
#   tools/ghidra/scan.py    peripheral-address / constant finder (CRC poly, discovery AA)
#   tools/ghidra/disasm.py  capstone Thumb disasm with literal-pool annotation
#   tools/ghidra/xref.py    literal-pool xrefs to a string
#   tools/ghidra/getfn.py   pull a function body out of a *.decomp.c dump by address
```
All scripts read the flattened images and `images.json` from the gitignored
`artifacts/work/` produced by step 1; the `*.decomp.c` dumps also stay there.

## Open items (priority for the next pass)
1. ~~`PairingData` (0x11) decrypted payload layout + AES-key KDF from the X25519 secret.~~
   **CLOSED** (Q2 "Pairing data layout + key derivation", CONFIRMED both sides). Result:
   link key is host-chosen and sent encrypted (not derived); CCM wrapping key = first 16
   bytes of the X25519 shared secret (truncation); payload = `[8-byte clear IV][24-byte
   CCM(20)]`, plaintext = `[4-byte base addr][16-byte AES key]`; stored by `FUN_000038e8`;
   `WriteAESKey 0x14` is a stub. This closes the last Gate A UNKNOWN — no live capture
   needed for pairing. Only loose end (non-blocking, static-only): the exact extra effect of
   the `FUN_000093c0` 0/1 flag beyond selecting the 0x11 vs 0x1d store path — Ghidra type
   propagation did not settle on that function, but it does not change the 0x11 layout.
2. ~~Connected-link PCNF0/1 and access-address derivation~~ — closed (Q1 "Radio
   configuration per link"). Remaining: the host `netaddr` value itself (per headset, not on
   air) — get it from a live capture (address search) or the headset's
   `/persist/pulsar/pulsar_host_address.bin`; how the Android side generates it (UNKNOWN).
3. ~~Slot length, beacon cadence, hop rule, ack scheme~~ — closed (Q1 "Timing"). Remaining
   for a live capture: confirm uplink slot anchor (350 µs + offset after the beacon start),
   DM-beacon cadence and the 4000 µs branch, beacon payload byte 0 bit 0 and byte 14
   meaning, advert words at bytes 1..4 / 13..30, pairing-link framing.
4. CCM nonce — **structure + negotiation CONFIRMED; steady-state packing still needs one live
   MIC check** (Q3/Q4). Confirmed: the 13-byte nonce is `packetCounter[5 LE, incl. direction
   bit] || IV[8]` (nRF HW-CCM; host CCM helper is `syncboss FUN_0001b1a4`, not the elk-app
   `0x1b1a4` which is a battery routine), and the **negotiation** nonce is an 8-byte random IV
   (RNG `FUN_000185d8` into config `+0x88`) with counter 0, sent in the clear in the
   negotiation packet (`FUN_00047604`). The earlier `session_nonce<<48|timestamp @ 0x2409c`
   lead was wrong: `0x2409c` is the beacon scheduler (`FUN_00023e54`, `n·2000+ts` window), not
   the nonce builder. Remaining (needs a live capture, non-blocking): confirm which steady-state
   packing is live — hypothesis (a) the saved random IV (`+0x99`) reused with an advancing
   counter, or (b) the Q1 session-nonce-in-counter packing. `pulsar_crypto.py scan --iv <IV from
   negotiation>` decides it in one packet. Tool already leads with (a); see Q3/Q4.
5. ~~Host Pulsar version value the controller accepts.~~ **CLOSED** (Q6, value CONFIRMED).
   The controller's own Pulsar protocol version = **`0x1701`** (on-air `01 17`: major 1,
   `pulsar_protocol_sub_version` 23), the only such immediate in the controller image and
   absent from `syncboss`; set at `elk-app 0x18b90` (`FUN_00018a24`) into connection record
   `0x20004ec0+8`, echoed outward by `FUN_00023aa8` @ `0x23bc4`. Dongle should advertise
   `0x1701` and never reject the controller (emulate the skippable host-side check). Remaining
   (static-only, needs a live capture; non-blocking): the exact controller instruction that
   reads an *inbound* host version and raises event `0x10` — it sits in a raw-byte region
   (~`0x20000..0x20600`) Ghidra did not disassemble, so it is unconfirmed whether the
   controller inspects an inbound version at all vs. stopping seek on a host-issued rejection.
6. ~~HID report descriptor bytes.~~ **CLOSED** (Q4 "Controller -> host input", CONFIRMED).
   Result: there is **no HID report descriptor and no packed report** in this firmware — the
   controller exposes input as individual host-registers read over Pulsar. Assembler
   `FUN_000173bc @ 0x173bc` reads the deerfly 61-byte sample (SPI reg 0x37), checksums it, and
   re-packs into hreg regs: buttons=9, analogs (trigger/grip/stickX/stickY, four 12-bit ADCs
   at deerfly buf 0x23/0x25/0x31/0x33)=regs 3 & 0x17, touch/prox flags=4 & 0x2b, cap-touch
   channels=8/0x20/0x21, battery=0x15, IMU=0xb/0x16 (full table + bit remaps in Q4). Remaining
   (static-only, needs the Renesas "deerfly" firmware or a live dump, non-blocking): the
   axis identity of the four analogs, the button-bit -> labelled-button map, and the exact
   meaning/scale of the touch flags, cap-touch channels, and the reg-0x15 battery unit.
