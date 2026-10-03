# Hardware day: nRF52840 dongle runbook

Everything here was built and checked without the dongle. This is the order to run once it arrives.
Nothing on this list needs the Quest or the Frame except the Gate B section at the end.

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
The AES key never crosses the air. With the headset's `/data/misc/pulsar_aes_key.bin` (or the
documented default) in hand:

The CCM nonce is a per-packet counter + an **8-byte random session IV** (PROTOCOL.md Q4, confirmed
from firmware). That IV is sent in the clear, once, in the connection-negotiation packet — its
first 8 payload bytes. Grab those, then let `scan` sweep the counter against the fixed IV:
```bash
python tools/pulsar_crypto.py scan --key <32 hex> --capture conn.jsonl --iv <8 bytes from negotiation>
```
A verifying 4-byte MIC confirms the key, the IV, the counter and the capture at once. If you did
*not* capture the negotiation packet, run `scan` without `--iv` to try the (firmware-contradicted,
last-ditch) `--session`-derived fallbacks. `decode` takes one packet with explicit `--counter`/`--iv`
for iterating — the negotiation packet itself is `--counter 0 --iv <those 8 bytes>`.

## 6. Gate B: do the Frame cameras see Touch Plus LEDs? (needs the Frame + a Touch Plus)
This does **not** need the dongle — it reuses the relay. It is the one open question for 6DoF.
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
python tools/pulsar_crypto.py selftest
cd driver && bash test/run.sh     # config parser vs real + generated configs
```
