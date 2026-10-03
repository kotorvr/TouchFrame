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

Residual UNKNOWN to close before trusting pairing end-to-end: the exact byte layout of
the `PairingData` (0x11) payload the controller decrypts and what it stores (base address
+ AES key + which fields), and whether the AES key is derived from the ECDH secret or sent
under it. Addresses to continue: controller ECDH at `elk-spl FUN_0000934c @ 0x934c`
(calls Curve25519 scalarmult), pairing-state reset `FUN_000039bc @ 0x39bc`, pairing packet
dispatch references `device_pairing_packet_handlers.c` from code near `elk-spl 0x3b0c`.

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
`[0] type = 2`, `[1..4]` 32-bit info word (`0x01, 0x17, hw, hw` at build time; content
INFERRED version/hw), `[5..12]` 64-bit **device ID (FICR DEVICEID)**, `[13..16]` 32-bit word
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

**Message IDs (INFERRED, prior public work; corroborated by `x25519.c`/`device_pairing.c`):**
`SetupX25519Keys = 0x12` (host pub key out, controller pub key back), `PairingData = 0x11`
(host sends the link key material encrypted under the ECDH shared secret; first bytes of the
decrypted payload = new base address), `WriteAESKey = 0x14`, `Reset = 0x15`. These ride the
SPL command framing (len, cmd, seq, payload, CRC).

**Host side (syncboss + libsyncboss):** `pulsar_manager_pair`,
`pulsar_manager_enumerate_advertising_devices`, `syncboss_input_pair`,
`syncboss_starlet_enter_pairing_mode`, `syncboss_set_host_pulsar_pairing_info` /
`get_host_pulsar_pairing_info` (structs `syncboss_set_host_pairing_info_t` /
`syncboss_host_pairing_info_t`). Host AES key: `/data/misc/pulsar_aes_key.bin`, default
fallback. `pulsar_host_init` console takes a "16-byte AES key as a hex string" and a
"16-bit session nonce" (`session_nonce`).

**Key derivation after X25519 / host auth:** no host auth (Gate A). Exact KDF from the
shared secret to the 16-byte AES key is **UNKNOWN** — the decrypted `PairingData` payload is
the next thing to decode (`FUN_0000934c` output path).

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
packet. The exact steady-state IV derivation (session nonce from beacon bytes 6–7, beacon
timestamp, per-packet counter — see Q1) is **INFERRED, not pinned**. It does not block decoding:
`tools/pulsar_crypto.py` tries the candidate packings and a correct 4-byte MIC confirms the right
one from the first captured packet once the key is known.

---

## Q4 — Live reports and host->controller commands

**Controller -> host input (INFERRED, self-describing):** input rides **Pulsar data
packets** parsed host-side by `process_beacon_mode_pulsar_data(... spi_data_pulsar_data_t
...)`. The controller advertises its payload layout as a **HID report descriptor** read over
the link: `pulsar_manager_read_sync(input_id, PULSAR_PKT_ID(hid_report_descriptor), ...)`
and a capabilities packet `pulsar_pkt_capabilities_t` / `PULSAR_PKT_ID(attachment_info)`.
So for TouchFrame the live report layout does **not** need to be hard-coded — the controller
emits a HID descriptor we can parse. Captouch is post-processed host-side
(`update_captouch`). Physical inputs originate on the Renesas "deerfly" co-processor
(`input_sampling.c`, `thumbstick.c`, `pinch.c`, trigger min/max cal) and are relayed by elk
over SPI (`input_mcu_thread.c`, `elk_buttons.c`).
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

## Q6 — "Pulsar" host version check (CONFIRMED, bypassable)

- Controller refuses hosts whose Pulsar version it dislikes: event
  `INVALID_HOST_PULSAR_VERION`, log `"Invalid host Pulsar version detected, stopping seek"`
  (elk-app). It also emits `incompatible_version` LL counters. This is a numeric
  compatibility gate, **not** a cryptographic one.
- Host advertises its version in the beacon/connection negotiation; we must present a value
  the controller accepts (value **UNKNOWN**; find it in the host beacon builder
  `pulsar_cl_host.c` / the device's accept check in `pulsar_cl_device.c` near
  `"Received connection rejection from host"`).
- The analogous check on the real host is explicitly skippable
  (`SYNCBOSS_DISABLE_FW_VERSION_CHECK`, `persist.vendor.syncbosshal.disable_fw_version_check`,
  "normal for self-tracked controllers"), which is further evidence the gate is policy, not
  security.

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
1. `PairingData` (0x11) decrypted payload layout + AES-key KDF from the X25519 secret
   (elk-spl `FUN_0000934c @ 0x934c`). Closes the last Gate A UNKNOWN.
2. ~~Connected-link PCNF0/1 and access-address derivation~~ — closed (Q1 "Radio
   configuration per link"). Remaining: the host `netaddr` value itself (per headset, not on
   air) — get it from a live capture (address search) or the headset's
   `/persist/pulsar/pulsar_host_address.bin`; how the Android side generates it (UNKNOWN).
3. ~~Slot length, beacon cadence, hop rule, ack scheme~~ — closed (Q1 "Timing"). Remaining
   for a live capture: confirm uplink slot anchor (350 µs + offset after the beacon start),
   DM-beacon cadence and the 4000 µs branch, beacon payload byte 0 bit 0 and byte 14
   meaning, advert words at bytes 1..4 / 13..30, pairing-link framing.
4. CCM 13-byte nonce byte order (`FUN_0001b1a4 @ 0x1b1a4`). Lead: device builds a 64-bit
   counter `session_nonce << 48 | beacon_timestamp + n·2000` (elk-app `0x2409c..0x240d6`,
   then `FUN_000239fc`).
5. Host Pulsar version value the controller accepts.
6. HID report descriptor bytes (dump one live, or decode `PULSAR_PKT_ID(hid_report_descriptor)`
   response builder on the controller).
