# TouchFrame

Quest 3 **Touch Plus** controllers on a standalone **Steam Frame**, working like first-party controllers: 6DoF, all inputs, haptics, Touch bindings in every SteamVR/OpenXR game.

Work in progress. See [docs/FEASIBILITY.md](docs/FEASIBILITY.md) for findings, the phase plan and the current state.

## Layout
- `driver/`: SteamVR (OpenVR) driver `driver_touchframe`, built natively on the Frame (aarch64). It presents two `oculus_touch` controllers with Quest 3 render models, hand skeletons and haptics. Input comes from a pluggable source; today that's a UDP relay (`driver/src/protocol.h`).
- `quest-bridge/`: the Quest-side relay app (native OpenXR). It streams the controllers to the Frame and plays haptics.
- `tools/install.sh`: one-command install/uninstall of both sides from a PC.
- `tools/frame.sh`: build, install, restart, calibrate and log on the Frame over SSH.
- `tools/quest.sh`: install, start/stop and status for the bridge on the Quest, with a keep-awake watchdog.
- `tools/sim_sender.py`: fake controller source for testing the driver without a Quest.
- `tools/payload_extract.py`: pull partitions out of an Android A/B OTA `payload.bin` (used to read the Quest's own controller firmware for protocol research).

## Quick start (relay)
A Quest 3 on a shelf acts as the controllers' radio and tracker. Full guide: [docs/INSTALL.md](docs/INSTALL.md).

```bash
FRAME_HOST=steamos@<frame-ip> tools/install.sh   # driver on the Frame + bridge on the adb-connected Quest
tools/frame.sh calibrate                         # once: hold the right Touch and a Frame controller together
tools/quest.sh status                            # anytime: is the relay up?
```

Without a Quest: `tools/install.sh frame`, then `python tools/sim_sender.py <frame-ip>`.

## Legal
No Meta or Valve firmware, binaries or models are in this repo or ever will be. Research tools read them from your own devices or the matching official OTA. The driver's hand skeleton reads SteamVR's own hand animation from the Frame's SteamVR install at runtime. `driver/vendor/openvr_driver.h` is Valve's OpenVR header (BSD-3-Clause).
