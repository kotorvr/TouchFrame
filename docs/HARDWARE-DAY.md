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

**HW-1 should capture a Quest connecting a controller, to *validate* the TL header.** REVIEW-RE
pinned it statically (R0, [re/REVIEW-RE.md](re/REVIEW-RE.md)). The capture confirms it and
settles the CL length accounting and whether the idle `[00][seq]` packet is needed. The header was
the last firmware stub. Downlink is
**plaintext** (AUDIT A4), so sniffing a real Quest's beacons/downlink while a controller powers on
shows the host's register reads/writes in clear: the enumeration of `0x20`, `0x24`, `0x32`, … and the
cmd 9 "data ready" write (PERIPHERALS §1.2). Our dongle then sends the same headers. The
controller's replies to *our* dongle are under *our* key, which gives the uplink side.
Use `radio.py sniff --connected <netaddr>` (netaddr by address search, §4), then power-cycle a
controller.

**Before any Frame camera run, regenerate the Touch Plus configs**
(`python tools/touchplus_config.py`): the model name changed (RE-3b, FRAME-TRACKER §9.6). On-device
tests T1–T3 in [re/FRAME-MODEL.md](re/FRAME-MODEL.md) §6 can run during HW-1, with no dongle needed.

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

## Host mode (dongle acts as host): firmware ready, run in HW-2
The firmware implements the whole host (BUILD-1 + BUILD-1b, to [re/REVIEW-RE.md](re/REVIEW-RE.md)):
- pairing: `0x25` SetupX25519, then `0x22` PairingData with our own key, then Reset `0x2a`;
- connection negotiation, with one accept on slots 1..4;
- the TL header for register reads/writes and notifications;
- input/IMU events, LED (cmd 0x28) and haptics (0xa0/0x97).
See radio-fw/README.md "Host mode" for the commands
(`radio.py host --pair any`, `pairings`, `forget`, `ping`).

Settle these on the first live session, with the second dongle sniffing (radio-fw/README "Needs
hardware"):
- whether the idle TL packet is needed: try without, then `radio.py host --tl-idle`;
- which beacon period the steady CCM counter starts in;
- whether the 14-byte accept is enough;
- whether controllers react to missing beacon acks;
- HID throughput on the Frame;
- whether pairings survive DFU.

**HW-3 LED-timing checks** (driver/RADIO.md, docs/re/FRAME-MODEL.md §6 T3):
- Does XRService keep logging "Not having enough IMU data for controller frame … Current timestamp"
  once our IMU feed is healthy? If the line stops, the phase loop loses its direct drift measurement
  and relies on pose-validity sentinels. Check that it still holds lock for 10+ minutes.
- Record the logged `seed_offset_us`, i.e. which exposure point the stamp marks, and set
  `radio_led_seed_offset_us`.
- Time to first lock, seeded vs blind.
- If lock keeps slipping, raise it with the user before going further. A direct exposure-schedule
  feed was out of scope (RE-3 was blocked), and whether to revisit that is the user's call.

Not implemented: PCM haptics (0x9d). No real "disconnect" message is known: a dropped controller's
slot frees when it goes quiet.

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
