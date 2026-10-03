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
- Packet: 1-byte preamble, access address, 8-bit LENGTH, payload, 3-byte CRC. The LL sets
  `PCNF0` LFLEN=8, S0LEN=0, S1LEN=0 (seen in the TX/PER test path `syncboss FUN_00018058
  @ 0x18058`, which also uses the 0x55 preamble pattern). Whether the connected-link PCNF0
  adds an S0/S1 byte is **INFERRED=no** but not yet pinned to the live path — UNKNOWN.

**Access addresses (CONFIRMED constants):**
- **Discovery: `0xAA` prefix + base `0xFACEB00C`**, 2402 MHz. Constant present in
  `syncboss 0x1e2c4, 0x204d8, 0x208d8, 0x20a5c` and `elk-spl 0x7fc0, 0x8168` (discovery
  lives in the SPL/DM side and the host, not in elk-app). Matches prior public research.
- **Pairing on 2426 MHz** (INFERRED, prior work; consistent with 2426 being excluded from
  the data-channel set below). After the SPL switches to the connected link, the per-device
  access address comes from `device_id_0` / the pairing-provisioned base (INFERRED).

**Channel list + hopping (CONFIRMED):**
- `PULSAR_NUM_CHANNELS = 37`. `pulsar_ll_channels.c` logical-channel -> frequency lookup is
  `syncboss FUN_0001ac24 @ 0x1ac24`, table at `0x4fe70`. The 37 entries are nRF
  `FREQUENCY` values (MHz above 2400):
  `4 6 8 10 12 14 16 18 20 22 24  28 30 32 34 36 38 40 42 44 46 48 50 52 54 56 58 60 62 64 66 68 70 72 74 76 78`
  i.e. **2404–2478 MHz, 2 MHz spacing, skipping 2402 (discovery) and 2426 (pairing)**.
- Host distributes an active-channel bitmap and runs **adaptive FHSS** with a frequency
  blocklist: `adaptive_fhss.c`, `pulsar_host_get_ch_map` ("channel map distributed by the
  Host"), `"channel map: %05X%08X, active channels: %d"` (`syncboss FUN_00006dd8 @ 0x6dd8`),
  host blocklist via `vendor.syncbosshal.pulsar_blocklist`.

**Timing / who-transmits-first / ack (INFERRED, slot-based TDMA):**
- The **host transmits beacons**; devices receive in scheduled slots and reply. Device LL:
  `beacons_since_last_rx`, `PULSAR_DEVICE_MISSED_BEACONS_BEFORE_DC`, `beacon_time_handler`,
  `"Missed RX window {%lu,%lu,%lu}"`. Host CL: `pulsar_cl_host.c` `prepare_beacon_handler`,
  counters `beacons_tx/sent/skipped`, `idle_beacons`, `dm_beacons`.
- Slots: `PULSAR_NUM_DEVICE_SLOTS` + `PULSAR_NUM_AUXILIARY_DEVICE_SLOTS`
  (`ll_slot_config.c`, `endpoint_allocator.c`, `connection_tracker.c`). Beacon timestamp is
  `LL_BITS_IN_BEACON_TIMESTAMP` wide. Exact slot length in µs and the ack scheme are
  **UNKNOWN** (continue at `pulsar_cl_host.c` / `pulsar_worker.c` in syncboss).
- A 1 µs sync timer (`pulsar_sync_timer.c`, `"Timer precision must be 1 us"`) and a
  time translator (`time_translator.c`) align host and device clocks; this same clock
  drives the camera-sync LED strobe (Q4).

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

Open item (UNKNOWN): exact byte order of the 13-byte CCM nonce (how pktctr/dir/IV pack) —
read the `cfg+0x120..+0x12d` writes in `FUN_0001b1a4` against the device decrypt path.

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
- Report rate: **UNKNOWN** numerically (streaming cadence set by beacon slot timing).

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
2. Connected-link PCNF0/1 (S0/S1 presence) and per-device access-address derivation.
3. Slot length (µs), beacon cadence, ack scheme (`pulsar_cl_host.c`, `pulsar_worker.c`).
4. CCM 13-byte nonce byte order (`FUN_0001b1a4 @ 0x1b1a4`).
5. Host Pulsar version value the controller accepts.
6. HID report descriptor bytes (dump one live, or decode `PULSAR_PKT_ID(hid_report_descriptor)`
   response builder on the controller).
