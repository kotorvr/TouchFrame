# Installing the TouchFrame relay

The relay puts Quest 3 Touch Plus controllers on a standalone Steam Frame. A Quest 3 headset sits on a shelf as the controllers' radio and tracker, and its bridge app streams their state over Wi-Fi to the `driver_touchframe` SteamVR driver on the Frame. Haptics go back the same way. This is Phase 1 of [FEASIBILITY.md](FEASIBILITY.md); the native radio and camera tracking come later.

```
Touch Plus ──radio──> Quest 3 (shelf, quest-bridge) ──UDP 28430──> Steam Frame (driver_touchframe) ──> SteamVR games
                          <──────────── haptics, 1 Hz heartbeat ────────────
```

## What you need

**Hardware**
- A Steam Frame.
- A Quest 3 (or 3S/Pro/2) with its Touch controllers paired, on the same network as the Frame. It stays plugged in on a shelf, with a view of where you play.

**Steam Frame**
- SSH access as `steamos`. Developer mode lets you add your public key to `~/.ssh/authorized_keys`.
- `cmake`, `ninja` and a C++ compiler. Current SteamOS on the Frame ships them.

**PC** (Windows with Git Bash, Linux or macOS)
- `bash`, `ssh`, `tar`, Python 3.
- Android platform-tools (`adb`), with USB debugging enabled on the Quest (Meta developer mode).
- To build the bridge APK:
  - the Android SDK with build-tools, `platforms;android-34` and an NDK;
  - a JDK;
  - the Khronos OpenXR loader prefab (`org.khronos.openxr:openxr_loader_for_android`, unzip the `.aar`).
  - `tools/build_bridge.py` looks in `C:\Android\...` by default. Override with `ANDROID_HOME`, `ANDROID_NDK`, `JAVA_HOME` and `OPENXR_PREFAB`.

The Frame host defaults to `steamos@192.168.0.195`. Set `FRAME_HOST=steamos@<frame-ip>` and, if your key isn't `~/.ssh/id_rsa_frame_devkit`, `FRAME_KEY=<path>`. With several adb devices connected, set `QUEST_SERIAL`.

## Install (one command, from the PC)

```bash
FRAME_HOST=steamos@<frame-ip> tools/install.sh
```

The script runs two halves:
- **Frame:** copies `driver/` over, builds it natively (aarch64), registers it with `vrpathreg adddriver`, and restarts SteamVR. The restart interrupts whatever is running in VR; set `NO_RESTART=1` to do it yourself later.
- **Quest:** builds and installs `com.kotorvr.touchbridge`, points it at the Frame (`debug.touchframe.target`), and starts it together with the keep-awake watchdog (see below).

Run one half on its own with `tools/install.sh frame` or `tools/install.sh quest`.

**Installing on the Frame without a PC:** clone the repo on the Frame (anywhere except `~/touchframe-src`), then run:

```bash
FRAME_HOST=local tools/install.sh frame
```

### Calibrate once

The Quest and the Frame each track in their own space. Calibration finds the transform between them:
1. Wear the Frame. It only tracks its own controllers while worn.
2. Run `tools/frame.sh calibrate`.
3. For about 20 s, hold the right Touch and a Frame controller together in one hand, and turn and move them through big motions.

The result (typically under 1 cm RMS) goes to SteamVR's settings, and the driver picks it up live. Redo it if you move the Quest.

## Everyday use

The Quest needs no attention once started. `tools/quest.sh start` runs the bridge plus a watchdog that keeps the unworn headset awake:
- **Keep-awake:** it re-sends the `prox_close` broadcast whenever the virtual proximity sensor stops reading CLOSE, and wakes the headset if it fell asleep.
- **Relaunch:** it relaunches the bridge if it died, but only while the Horizon home is in front. It never takes focus from another app. Set `NO_RELAUNCH=1` to turn relaunching off.
- **Lifetime:** it runs on the Quest as the adb shell user, so it survives unplugging the PC, but not a reboot. After a reboot, run `tools/quest.sh start` again.

| Command | What it does |
|---|---|
| `tools/quest.sh status` | Bridge, watchdog, power and proximity state, plus the bridge's last status line |
| `tools/quest.sh log` | Follows the bridge and watchdog logs |
| `tools/quest.sh start [ip[:port]]` | (Re)starts everything, optionally with a new Frame address |
| `tools/quest.sh stop` | Stops the bridge and the watchdog |
| `tools/frame.sh log` | The driver's lines from SteamVR's `vrserver.txt` |
| `tools/frame.sh skeleton watch` | Live finger curl per hand, as games see it |

A healthy bridge logs a status line like this every 5 s:

```
status: session focused, target 192.168.0.195:28430, sent 3610 (72/s), L tracked, R tracked, driver linked rtt 14.2 ms, ...
```

- `driver waiting` or `lost`: the Frame isn't answering. Check that SteamVR is running and the driver is installed (`tools/frame.sh log`), and the IP.
- `L off` / `R off`: the controllers are asleep (press a button on each), or they were set down and the Quest switched to hand tracking (pick them up). The log shows `left/right hand profile: none` when that happens.
- `session visible`/`idle` instead of `focused`: another app or a system dialog is in front on the Quest.

The bridge recovers by itself from Wi-Fi drops, SteamVR restarts and a lost OpenXR session.

## What games get
- **Devices:** two `oculus_touch` controllers with Quest 3 render models, so games use their Touch bindings.
- **Inputs:** every button, touch, stick, trigger and grip, plus haptics.
- **Battery:** shown when a source reports it (the relay can't yet).
- **Hand skeleton:** `/input/skeleton/left|right`, for games like Half-Life: Alyx.
  - Finger curl is estimated from the controls: trigger and its touch sensor curl the index; grip curls middle, ring and pinky; touching any thumb surface (A/B/X/Y, stick, thumbrest) lowers the thumb.
  - Both motion ranges are provided: with the controller, the fingers stop at the handle.
  - The poses come from SteamVR's own hand animation on the Frame, read at runtime.
  - Turn it off with `driver_touchframe.skeleton = false` in `steamvr.vrsettings`.

## Uninstall

```bash
tools/install.sh uninstall          # both; or: tools/install.sh uninstall frame|quest
```

- **Quest:** stops the bridge and watchdog, uninstalls the APK and clears the target property. The headset's virtual proximity stays CLOSE until you put the headset on, reboot, or run `adb shell am broadcast -a com.oculus.vrpowermanager.automation_disable`.
- **Frame:** unregisters the driver, restarts SteamVR and deletes `~/touchframe-src`. The calibration stays in SteamVR's settings (section `driver_touchframe`), ready for a reinstall.

## Testing without a Quest

```bash
python tools/sim_sender.py <frame-ip>
```

This sends fake controllers: both hands circle, the trigger ramps and buttons cycle. It also prints haptics and the driver's heartbeat. The button cycle includes the system button, which toggles the SteamVR dashboard.
