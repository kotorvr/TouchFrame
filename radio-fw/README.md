# radio-fw: nRF52840 Dongle firmware

Firmware for the Nordic **nRF52840 Dongle (PCA10059)**. Today it is a raw-radio **sniffer** for the
Quest ↔ Touch Plus "Pulsar" link (`docs/PROTOCOL.md`). Host mode (being the controllers' "Quest")
comes later in the same firmware.

The firmware itself is small:
- `src/sniffer.c`: RADIO in Nordic-proprietary mode. Packets go straight into a 64-slot ring by
  EasyDMA. Each one is stamped by TIMER0 (1 µs) at the address match, with RSSI and CRC status.
  Optional channel hopping.
- `src/main.c`: USB CDC (TinyUSB) and the command link. It forwards packets while the port is open.
- `src/link.h`: the wire format, shared with `tools/radio.py`.

It links at `0x1000`, so the dongle's MBR and its open USB bootloader stay intact. No J-Link is needed.

## Build
Toolchain: Arm GNU Toolchain, GNU make, Nordic `nrfutil` with `nrf5sdk-tools`, Python with
`pyserial`. On Windows:
```bash
winget install -e --id Arm.ArmGnuToolchain
winget install -e --id ezwinports.make
winget install -e --id NordicSemiconductor.nrfutil
nrfutil install nrf5sdk-tools
python -m pip install pyserial
```
Then, from Git Bash:
```bash
radio-fw/build.sh            # fetches deps on first run -> build/touchframe-radio.zip
```

## Flash
- **First time:** plug the dongle in and press its small sideways **RESET** button. The red LED
  pulses, which means bootloader mode.
- **Later:** the running firmware reboots itself into the bootloader on command.

```bash
radio-fw/build.sh flash      # = python tools/radio.py dfu --package radio-fw/build/touchframe-radio.zip
python tools/radio.py ports  # -> COMx  TouchFrame radio
```
LEDs: green = USB is up, blue blinks with captured packets.

## Use
```bash
python tools/radio.py sweep --rounds 50              # peak RSSI per MHz: where is the link active?
python tools/radio.py sniff --preset discovery       # 2402 MHz, 0xAA + 0xFACEB00C, CRC-24 on
python tools/radio.py sniff --preset discovery --no-crc --out disc.jsonl
python tools/radio.py sniff --freq 26 --no-crc       # pairing channel (address is a guess)
python tools/radio.py sniff --base 0x... --prefix 0x.. --hop data --dwell-ms 20
```
- Each line shows time, MHz, RSSI, CRC (`ok`/`BAD`, or `---` when CRC is off), length, and the raw
  bytes as stored by the radio: `[LENGTH][payload]`. With `--no-crc` the payload is followed by the 3 CRC bytes.
- `--out` appends JSON lines `{t_us, mhz, rssi, crc_ok, data}` for offline analysis.
- `dropped` in the status lines means the PC didn't keep up with the dongle's 64-packet ring.

## First session with real hardware
1. Flash, then `radio.py status` (should report `running: false`).
2. `radio.py sweep --rounds 100` with the Quest on and controllers awake, then again with them asleep.
   This shows where the link is.
3. Discovery: put a controller in pairing mode (Quest: pair a new controller) and run
   `sniff --preset discovery`.
   - If CRC is always `BAD`, try `--crc-skip-addr`, then `--no-crc`, to tell a CRC setting problem
     from a wrong address.
   - If nothing arrives at all, try `--little-endian`.
4. Pairing (2426 MHz), then the connected link on the data channels. The addresses and timing come
   from docs/PROTOCOL.md's open items.
