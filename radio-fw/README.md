# radio-fw: nRF52840 Dongle firmware

Firmware for the Nordic **nRF52840 Dongle (PCA10059)**. It has three modes that share one USB link
(`src/link.h`, PC side `tools/radio.py`):
- a raw-radio **sniffer** for the Quest ↔ Touch Plus "Pulsar" link (`docs/PROTOCOL.md`);
- a Pulsar **host** that replaces the Quest for the controllers: it sends beacons, pairs
  controllers, connects them and streams their events to the PC (link v3);
- a **fake controller** for a second dongle, so host mode can be tested over the air before a real
  controller is available.

It links at `0x1000`, so the dongle's MBR and its open USB bootloader stay intact. No J-Link is needed.

## Layout
| file | what |
|---|---|
| `src/link.h` | the USB wire format (COBS frames; link v3), mirrored by `tools/radio.py` (both assert struct sizes) |
| `src/main.c` | USB (TinyUSB: CDC-ACM + vendor HID on one device), command dispatch, the modes, self-test, NVMC flash glue |
| `src/sniffer.c` | v2 sniffer: RADIO packets into a ring by EasyDMA, TIMER0 stamps, beacon-follow hop |
| `src/host_core.c` | **portable** host: 2000 µs beacon scheduler with the CSA#1 hop, DM beacons, uplink slots, pairing, connections, downlink queue/ARQ, the v3 commands |
| `src/ctrl_core.c` | **portable** fake controller: advertising, the SPL pairing exchange, seek/follow, uplinks in its slot; real or placeholder connected-link formats |
| `src/pulsar_ll.c`, `pulsar_hop.c` | beacon header, DM schedule, CSA#1 hop, CCM nonces, slot offsets |
| `src/pulsar_pair.c` | discovery advert, pairing frames, PairingData wrap/unwrap |
| `src/pulsar_cl.c` | connected-link messages: `cl_real` (accept, TL header, LED / haptic payloads, notification chunks) and `cl_placeholder` (ours, loopback only) |
| `src/crypto.c` | portable AES-128, Pulsar AES-CCM, X25519 (no Nordic closed libraries) |
| `src/store.c` | **portable** flash log: the host identity and up to 8 pairings |
| `src/radio_engine.c`, `clock.c`, `hal.c` | the nRF52840 side: PPI-triggered TX/RX ops, the 64-bit µs clock, HW CCM, RNG |

The portable cores reach the radio only through `radio_op.h`. The same code runs on the dongle and in
`test/sim.c`, which simulates the air at 1 µs resolution with each node on its own drifting clock.

## Build
Toolchain: Arm GNU Toolchain, GNU make, Nordic `nrfutil` with `nrf5sdk-tools`, Python with
`pyserial` (and `hidapi` for `--hid`). On Windows:
```bash
winget install -e --id Arm.ArmGnuToolchain
winget install -e --id ezwinports.make
winget install -e --id NordicSemiconductor.nrfutil
nrfutil install nrf5sdk-tools
python -m pip install pyserial hidapi
```
Then, from Git Bash:
```bash
radio-fw/build.sh            # fetches deps on first run -> build/touchframe-radio.zip
```

## Test (no hardware)
```bash
radio-fw/test/run.sh
```
Uses clang or gcc from PATH, or the LLVM-MinGW that `build.sh` finds. It runs:
- hop rule and beacon parsing against an independent Python model;
- AES / CCM / X25519 against RFC vectors and the `cryptography` package;
- byte formats against `tools/pulsar_host.py` / `pulsar_input.py`: beacon header, DM countdown,
  advert, nonces, PairingData, the accept and request, TL packets, LED / haptic payloads, and
  fragmented notification chunk streams;
- the flash store: a model test, power cuts after any word, and no synchronous erase while linked;
- the simulator at drift 15/-15, 0/0 and 100/-100 ppm. It covers pair, connect, stream, registers,
  LED, haptics, 10% loss, outage, stored pairings across a dongle reboot, argument checks, and the
  real formats end to end: a refused PairingData, Reset, the accept in slot 1..4, TL reads / writes /
  failures, notification input and IMU, a fragmented LED echo, the hand, and the LED re-sent after
  a reconnect;
- link v3: link.h against radio.py, then full sessions against `tools/fake_dongle.py`, including HID
  framing.

## Flash
- **First time:** plug the dongle in and press its small sideways **RESET** button. The red LED
  pulses, which means bootloader mode.
- **Later:** the running firmware reboots itself into the bootloader on command.

```bash
radio-fw/build.sh flash      # = python tools/radio.py dfu --package radio-fw/build/touchframe-radio.zip
python tools/radio.py ports  # -> COMx  TouchFrame radio
python tools/radio.py selftest   # AES, X25519 timing, HW CCM == software CCM, RNG, clock
```
LEDs: green = USB is up, blue blinks with captured packets / input events.

## USB link
The device is a composite USB device (VID:PID 1209:0001) with the same COBS stream on both interfaces:
- **CDC-ACM** (interfaces 0–1): the serial port. The default on Windows.
- **HID** (interface 2, vendor page 0xFF00): 64-byte reports `[n][n bytes][pad]`. The Frame has no
  `cdc_acm`, so its driver uses hidraw (`radio.py --hid`). Two controllers at 500 Hz fit the
  ~63 KB/s HID budget only with `--compact`.

link.h's header comment is the driver author's guide: modes, tags and results, the clock, slots,
identity, HID details.

## Host mode
```bash
python tools/radio.py hello                      # version, caps: which on-air formats are real
python tools/radio.py host --pair any            # beacons + pair the first controller in pairing mode
python tools/radio.py host                       # later runs: stored pairings reconnect by themselves
python tools/radio.py pairings                   # what the dongle has in flash
python tools/radio.py forget all [--identity-too]
python tools/radio.py ping                       # dongle-clock <-> PC time sync quality
```
- **Identity.** By default the dongle keeps its identity (netaddr + link key, generated once at
  random, never all-zero) and its pairings in flash (`LINK_HOST_STORED`). Pairings survive power
  cycles and Frame reboots. `--identity FILE` makes the PC own them instead, and nothing goes to
  flash.
- **Pairing a Touch Plus to the dongle replaces its Quest bond.** The controller keeps one host
  record (docs/re/LINK.md §5.1). Re-pair to go back.
- **Flash store.** It uses pages `0xDE000`/`0xDF000`, inside the bootloader's app-data area, so it
  should survive DFU (the SDK default; check this on hardware). Erases run as 1 ms partial-erase
  slices, at most one per 20 ms, so connected controllers miss at most one beacon in a row. While
  any controller is linked a write that would need a synchronous erase fails instead (a controller
  drops after 25 missed beacons = 50 ms, docs/re/REVIEW-RE.md R9).
- **Slots** are 1..4. Slot 0 (TX prefix 1) is where seeking controllers ask to connect; it is never
  assigned (R1).

## Loopback rig (two dongles)
```bash
python tools/radio.py --port COM_A host --placeholder --pair any   # host (flash identity), placeholder CL formats
python tools/radio.py --port COM_B fake                            # plays a Touch Plus: pairs, connects, streams

# skip pairing: both sides take netaddr + key from the same file
python tools/radio.py --port COM_A host --identity f.json --auto-accept   # real formats (no --placeholder)
python tools/radio.py --port COM_B fake --paired --identity f.json --real-conn   # real request + negotiation
```
The fake speaks the real pairing exchange and, with `--real-conn`, the real connected link all the
way (request, accept, TL registers, notification input / IMU). Without it, the placeholder formats:
TouchFrame's own invention, only ever used between our two dongles.

## What is real, what is a stub, what needs hardware
**Implemented to the pinned formats** (docs/PROTOCOL.md, docs/re/LINK.md, docs/re/PERIPHERALS.md,
and docs/re/REVIEW-RE.md, which takes precedence):
- beacon header and 2000 µs scheduling; channels 0/17/36 always in the map (seek, R10);
- CSA#1 hop and DM beacons on 2402 (5..24-period spacing, announced 3/2/1 periods ahead);
- uplink slots: prefixes 0x01..0x05 at 350 + {0, 225, 525, 825, 1125} µs; beacon bit `1 << S` (R4);
- discovery listen and the pairing exchange on 2426: SetupX25519Keys `0x25`, PairingData `0x22`,
  then Reset `0x2a` (R6); replies `[status][seq][data]` matched by seq, bit 7 = failed (R5); a
  refused `0x22` redoes `0x25` (R15);
- uplink-only CCM (in hardware) with the legacy and steady-state nonces; the steady counter counts
  beacon periods since the accept (R7), direction 0 (R8);
- the connection request and ONE accept: `[2] = (fmt << 3) | 2`, `[11] = S`, `[12]` = IV flag,
  `[13]` = 1 (R1-R3);
- the TL header (R0): register reads / writes with per-controller seq, re-sent every beacon until
  answered (1 s timeout), implicit write acks, reg 0 notifications reassembled across uplinks (R13)
  into EVT_INPUT / EVT_IMU; reg 0x2a ignored;
- on connect: cmd 1 (the hand, R11), cmd 0x32 (IMU scale), cmd 9, and the last LED config again
  (R16). Never cmd 0xa1 (R12);
- LED cmd 0x28 and haptics 0xa0 / 0x97, with the limits (period ≥ 700 µs, on-time ≤ 75 µs).

**Stubs** (answer `LINK_ERR_PENDING_RE`): PCM haptics (0x9d, 3-bit ADPCM). No real disconnect
message is known: CMD_DISCONNECT stops handling a real controller, which stays on the link until
CMD_CONNECT takes it back or it loses the beacons.

**Needs hardware** (docs/HARDWARE-DAY.md):
- the TX-to-ADDRESS timing constant;
- HW CCM equivalence (`selftest`);
- how the pairing link is opened;
- whether the 14-byte accept alone suffices, without the 26-byte record body;
- the period the steady counter starts in (searched around), and the direction bit (learned);
- whether controllers need the idle TL packet on empty beacons (`host --tl-idle`);
- HID throughput on the Frame;
- that flash pairings survive DFU.

## Sniffer
```bash
python tools/radio.py sweep --rounds 50              # peak RSSI per MHz: where is the link active?
python tools/radio.py sniff --preset discovery       # 2402 MHz, 0xAA + 0xFACEB00C, CRC-24 on
python tools/radio.py sniff --preset discovery --no-crc --out disc.jsonl
python tools/radio.py sniff --freq 26 --base 0x<deviceid_lo> --out pair.jsonl   # pairing
python tools/radio.py sniff --connected 0x<netaddr> --out conn.jsonl            # follow the link
```
- **Several addresses at once.** `--connected` sets host AP1=`0xF0` and controller slots
  AP2..AP6=`0x01..0x05`, so one capture holds both sides of the link.
- **Hop following.** `--connected` locks onto the 500 Hz beacon and retunes with the CSA #1 hop.
  The status line shows `follow: N beacons, M blind, LOCKED`. `--no-follow` parks on one channel;
  `--with-adverts` also keeps logical address 0.
- **Output.** Each line shows time, MHz, the matched logical address (`a1` host, `a2`..
  controllers), RSSI, CRC, length and the raw bytes `[S0][LENGTH][payload]`. `--out` appends JSON
  lines for `tools/pulsar_analyze.py`. `dropped` means the PC fell behind the 64-packet ring.

The full hardware-day runbook is docs/HARDWARE-DAY.md.
