# TouchFrame

Quest 3 **Touch Plus** controllers on a standalone **Steam Frame**, working like first-party controllers: 6DoF, all inputs, haptics, Touch bindings in every SteamVR/OpenXR game.

Work in progress. See [docs/FEASIBILITY.md](docs/FEASIBILITY.md) for findings, the phase plan and the current state.

## Layout
- `driver/`: SteamVR (OpenVR) driver `driver_touchframe`, built natively on the Frame (aarch64). It presents two `oculus_touch` controllers with Quest 3 render models. Input comes from a pluggable source; today that's a UDP relay (`driver/src/protocol.h`).
- `tools/frame.sh`: build, install, restart and log on the Frame over SSH.
- `tools/sim_sender.py`: fake controller source for testing the driver without a Quest.
- `tools/payload_extract.py`: pull partitions out of an Android A/B OTA `payload.bin` (used to read the Quest's own controller firmware for protocol research).

## Quick start (relay/sim)
```bash
tools/frame.sh build
tools/frame.sh install
tools/frame.sh restart
python tools/sim_sender.py <frame-ip>
```

## Legal
No Meta or Valve firmware, binaries or models are in this repo or ever will be. Research tools read them from your own devices or the matching official OTA. `driver/vendor/openvr_driver.h` is Valve's OpenVR header (BSD-3-Clause).
