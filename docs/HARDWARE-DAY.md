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

## 4. Connected link
The base is the host **network address**, not visible on air. Two ways in:
- **Park on 2402** and catch the periodic DM beacons (`--preset discovery`, they use S0=0). Beacon
  byte 5 = current channel, bytes 0–4 = channel map, bytes 8–13 = timestamp (PROTOCOL.md beacon
  table). This alone shows cadence and hop state.
- **Follow the hop** once the netaddr is known: `--base <netaddr> --prefix 0xF0 --hop data`. To find
  the netaddr, read `/persist/pulsar/pulsar_host_address.bin` off the Quest (adb), or brute-force
  the low byte: the CRC covers the address, so `pulsar_analyze.py` CRC-ok rate confirms a guess.

## 5. Decode a connected packet (optional, offline, needs the key)
The AES key never crosses the air. With the headset's `/data/misc/pulsar_aes_key.bin` (or the
documented default) in hand:
```bash
python tools/pulsar_crypto.py scan --key <32 hex> --capture conn.jsonl --session <beacon bytes 6-7>
```
A verifying 4-byte MIC confirms the key, the nonce layout and the capture at once. `decode` takes
one packet with explicit counter/IV for iterating.

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
