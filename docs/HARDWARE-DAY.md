# Hardware day: nRF52840 dongle runbook

Everything here was built and checked without the dongle. This is the order to run once it arrives.
Nothing on this list needs the Frame except the Gate B section at the end. Sessions HW-1…HW-4 in
[MASTER-PLAN.md](MASTER-PLAN.md) §5 run this.

**Scope:** §0–5 are *listening* (sniffer). Host mode (the dongle pairs and drives a controller) also
needs the firmware TX path and the post-pairing command layer. Neither exists yet: sessions BUILD-1
and RE-1/RE-2.

**Pairing a controller to the dongle unpairs it from the Quest (CONFIRMED, [re/LINK.md](re/LINK.md)
§5.1).** A Touch Plus keeps a single host pairing record, so the relay stops for that controller
until you re-pair it in the Quest's controller settings, and the same goes the other way. Pair one
controller first, and keep the other on the Quest until HW-2 is solid.

**What a sniffed session still has to settle** (RE-1 open items): the on-air TL/notification
header bytes, the endpoint↔slot mapping, the steady-state CCM counter start/increment, and the
CRC trailer byte order. Capture one full connected session with the second dongle during HW-2.

**Before you start:**
- [ ] OTG adapter: the dongle is USB-A, the Frame is USB-C. Not needed for §0–5 on the PC.
- [ ] Ideally a second dongle: one host, one sniffer.
- [ ] Note the Quest build and controller firmware version. All RE is against OTA
      52433670048800520, and a Quest update reflashes the controllers.
- [ ] Devices free? The Quest/Frame may be on loan to another session. Ask before using them.

## 0. Flash the dongle (5 min)
```bash
radio-fw/build.sh            # already builds clean; rebuild to be sure
```
- Plug the dongle in. Press its small side **RESET** button; the red LED pulses = bootloader.
- `radio-fw/build.sh flash` (first time needs the button; later `radio.py dfu` reboots it itself).
- `python tools/radio.py ports` → a `TouchFrame radio` line. Green LED = USB up.

**First-flash checks (these are the only untested-on-silicon parts):**
- Does it enumerate as `1209:0001`? If not, check `preview_logs`/Device Manager; the descriptor or
  the USB power-event glue in `main.c` is the suspect.
- `radio.py status` returns a status line with `version: 1`.
- Host firmware (BUILD-1): the dongle enumerates as composite CDC + vendor HID (interface 2). On the Frame only HID works (no CDC ACM in its kernel).
- After pairing a controller (HW-2), re-flash with `build.sh flash` and check the pairing survives DFU. The store is at flash 0xDE000/0xDF000, assumed to be inside the bootloader's preserved app-data area (INFERRED).
- `radio.py dfu` (while running) reboots into the bootloader on its own (GPREGRET 0xB1). If it
  doesn't, the button still works; note it and move on.

## 1. Where is the link? (no Quest needed yet, but turn it on)
```bash
python tools/radio.py sweep --rounds 100
```
Quest on + controllers awake, then controllers asleep. Expect energy around 2402 (discovery) and
the 2404–2478 data channels. This proves RX works at all before chasing addresses.

## 2. Discovery (put a controller into pairing from the Quest)
```bash
python tools/radio.py sniff --preset discovery --out disc.jsonl
```
- CRC `ok` on real packets = the discovery preset (address, endianness, CRC-24) is right — a big
  confirmation of docs/PROTOCOL.md Q1.
- All `BAD`? Try `--crc-skip-addr`, then `--no-crc` (a wrong CRC setting still shows the bytes).
- Nothing at all? Try `--little-endian`, then re-check the channel from the sweep.
- `python tools/pulsar_analyze.py disc.jsonl --dump 20` — the advert is type 2, 32 bytes, the
  controller's 64-bit device ID at payload bytes 5–12 (PROTOCOL.md). **Record that device ID**: it
  is the pairing-channel base address.

## 3. Pairing (2426 MHz)
```bash
python tools/radio.py sniff --freq 26 --base <deviceID_low_u32> --prefix 0xAA --no-crc --out pair.jsonl
```
`<deviceID_low_u32>` = advert bytes 5–8 as a little-endian u32 (PROTOCOL.md Q1 pairing row).
`pulsar_analyze.py pair.jsonl` for the ping-pong framing.

The exchange is two commands (PROTOCOL.md Q2, confirmed from firmware): `SetupX25519Keys` (0x12,
the 32-byte public keys cross) then `PairingData` (0x11) — a 32-byte payload of `[0..7]` clear CCM
IV + `[8..31]` 24-byte ciphertext/MIC, which the host encrypts under the **first 16 bytes of the
X25519 shared secret** and which decrypts to `[0..3]` the connected-link base address + `[4..19]`
the 16-byte link AES key. So the sniffer sees the IV and ciphertext but not the key (the X25519
private half stays on the devices). For the dongle to act as host it picks the key and sends 0x11;
`WriteAESKey` (0x14) is a no-op stub and need not be sent.

## 4. Connected link
The base is the host **network address** (netaddr), not visible on air. Get it one of two ways:
- Read `/persist/pulsar/pulsar_host_address.bin` off the Quest (adb) — the 4 bytes are the netaddr.
- **Address search:** the CRC covers the address, so a wrong base yields all-`BAD`. Park on 2402 for
  the DM beacons, or step a candidate base and watch the CRC-ok rate in `pulsar_analyze.py`.

Then follow the link (hears host + controllers, retunes with the hop):
```bash
python tools/radio.py sniff --connected 0x<netaddr> --out conn.jsonl
```
Watch the status line: `follow: N beacons … LOCKED` means it's tracking the hop. `--no-follow`
parks on one channel if you'd rather. `pulsar_analyze.py conn.jsonl` splits host (`addr` 1) from
controllers (`addr` 2+) and shows the 2 ms beacon cadence and uplink slots.

## 5. Decode a connected packet (optional, offline, needs the key)

> **Mostly not possible against a real Quest (AUDIT-1, [re/AUDIT.md](re/AUDIT.md) A2–A8).**
> - A real Quest pairs with **0x1d**: the link key is the X25519 shared secret[:16], per device and
>   never on air. The global `pulsar_aes_key.bin` is only the fallback, and DEV-1 found it doesn't
>   even exist on this Quest.
> - The nonce model below is wrong. The negotiation IV is `session_nonce<<48 | beacon_ts48` with
>   counter 0. The steady IV comes from the controller's connection request, with a per-slot
>   counter. CCM is uplink only; beacons and downlink are plaintext.
> - `pulsar_crypto.py scan` will be fixed (A8), but expect §5 to work only on **our own dongle's
>   sessions** (HW-2), where we chose the key. Sniffing a Quest is still useful for plaintext
>   beacons, timing and framing (§1–4).
The AES key never crosses the air. With the headset's `/data/misc/pulsar_aes_key.bin` (or the
documented default) in hand:

The CCM nonce is a per-packet counter + an **8-byte random session IV** (PROTOCOL.md Q3, confirmed
from firmware). That IV is sent in the clear, once, in the connection-negotiation packet: its
first 8 payload bytes. **Caveat (open contradiction, PROTOCOL Q3 note):** the function that makes
that IV builds a blob exactly the shape of `PairingData` 0x11, so the IV may only be on air on
2426 MHz during a pairing. If you can't find a negotiation packet on the connected link, re-pair a
controller from the Quest while sniffing §3 and take the IV from the 0x11 payload's first 8 bytes. Grab those, then let `scan` sweep the counter against the fixed IV:
```bash
python tools/pulsar_crypto.py scan --key <32 hex> --capture conn.jsonl --iv <8 bytes from negotiation>
```
A verifying 4-byte MIC confirms the key, the IV, the counter and the capture at once. If you did
*not* capture the negotiation packet, run `scan` without `--iv` to try the (firmware-contradicted,
last-ditch) `--session`-derived fallbacks. `decode` takes one packet with explicit `--counter`/`--iv`
for iterating — the negotiation packet itself is `--counter 0 --iv <those 8 bytes>`.

Once decrypted, input is **not** a single packed report (PROTOCOL.md Q4, #6): the controller
exposes buttons/triggers/stick/touch as individual host-registers assembled from a 61-byte
"deerfly" sample. `tools/pulsar_input.py` parses that sample/those registers into named fields and
verifies the deerfly checksum offline — field *values* are decoded; a few *semantics* (which analog
is which axis, button-bit labels, battery scale) stay inferred until confirmed against a live dump.

## Host mode (dongle acts as host — needs the dongle; sequence is pinned)
Pairing is fully specified (PROTOCOL.md Q2, #1): send `SetupX25519Keys` (0x12) to exchange public
keys, derive the X25519 secret, then send `PairingData` (0x11) carrying `[4-byte base addr][16-byte
link key]` CCM-wrapped under the first 16 bytes of the secret (`WriteAESKey` 0x14 is a stub — skip
it). `tools/pulsar_host.py` builds and self-verifies those frames offline. Advertise host Pulsar
version **`0x1701`** (on-air `01 17`) and never reject the controller (PROTOCOL.md Q6, #5).
Not ready yet: the firmware has no TX path (BUILD-1), and after pairing the host must negotiate the
connection and read registers / set LEDs / send haptics in formats RE-1 and RE-2 are still pinning
(PROTOCOL open items 8–10).

## 6. Gate B: do the Frame cameras see Touch Plus LEDs? (needs the Frame + a Touch Plus)
This does **not** need the dongle; it reuses the relay. It is the one open question for 6DoF.

**Read this first: with the relay, only a "yes" counts.** The Quest strobes the Touch Plus LEDs for
~15–100 µs on *its own* camera schedule. They are lit during a Frame controller-frame exposure only
by coincidence, roughly 1% of frames, in bursts when the two frame rates beat. So run it **10+
minutes** and look for *any* `[ContrLedsStats]` line for device 41. One hit means the Frame can see
and match Touch Plus LEDs. No hits proves nothing. The decisive run is session HW-3, with the dongle
holding the LEDs on (MASTER-PLAN §3.2, §6).
```bash
python tools/touchplus_config.py           # writes artifacts/touchplus/touchplus_{left,right}.json
FRAME_HOST=steamos@<ip> tools/frame.sh gateb on left
```
- Switch the **left Frame controller OFF** (one tracking slot per hand; §9.3).
- Hold the left Touch Plus (relayed from the Quest) in view of the Frame; move it.
- `tools/frame.sh gateb log` → `[ContrLedsStats 1]` lines mean XRService matched LEDs to the Touch
  Plus model: **Gate B passes**. `cvclone` lines give the pose error vs the relay.
- `tools/frame.sh gateb off` when done.
- The LED model here is Meta's factory nominal from the OTA (`touchplus_config.py`, 8 LEDs). If
  blobs appear but PnP is poor, the per-unit model may differ; dump the controller's own model over
  the radio later.

## Build/verify anytime (no hardware)
```bash
radio-fw/build.sh                 # firmware
python tools/radio.py --help      # (fake-dongle tested)
python tools/pulsar_crypto.py selftest   # CCM decode (RFC 3610 + round-trip)
python tools/pulsar_host.py selftest     # pairing-packet builder (X25519 + 0x11 round-trip)
python tools/pulsar_input.py selftest    # input decoder (CRC-32 + remaps round-trip)
cd driver && bash test/run.sh     # config parser vs real + generated configs
```
