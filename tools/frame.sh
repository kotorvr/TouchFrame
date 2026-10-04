#!/usr/bin/env bash
# Steam Frame helper over SSH (the Frame's adbd has no TCP mode).
#   tools/frame.sh build       copy driver/ to the Frame and build it natively (aarch64)
#   tools/frame.sh install     register the built driver with SteamVR (vrpathreg)
#   tools/frame.sh uninstall   unregister it
#   tools/frame.sh restart     restart SteamVR (interrupts whatever is running in VR)
#   tools/frame.sh calibrate [left|right] [seconds]
#                              align the relay space: hold that Touch + a Frame controller together
#   tools/frame.sh skeleton [ref|watch]
#                              check the hand skeleton against SteamVR's poses / watch finger curl
#   tools/frame.sh gateb on [left|right] | off | log
#                              Gate B with the relay: put that relay Touch Plus into the camera
#                              tracker with its LED model (tools/touchplus_config.py) and an IMU
#                              synthesized from its relay pose. Same-hand Frame controller must be OFF.
#                              Restarts SteamVR. docs/HARDWARE-DAY.md §6 (relay: only a "yes" counts)
#   tools/frame.sh log         TouchFrame lines from vrserver.txt
#   tools/frame.sh shell CMD   run a command
# FRAME_HOST=local runs everything on this machine (when the repo is checked out on the Frame).
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="${FRAME_HOST:-$(cat ../EchoFramePCVR/artifacts/frame_host 2>/dev/null || echo steamos@192.168.0.195)}"
KEY="${FRAME_KEY:-$HOME/.ssh/id_rsa_frame_devkit}"
SSH=(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=5 "$HOST")
if [ "$HOST" = local ]; then
  SSH=(bash -c)
  # build replaces ~/touchframe-src wholesale; never let that be this checkout.
  [ "$(pwd -P)" != "$(cd ~ && pwd -P)/touchframe-src" ] || { echo "check the repo out somewhere other than ~/touchframe-src" >&2; exit 1; }
fi
VRPATHREG='LD_LIBRARY_PATH=/opt/steamvr/bin/linuxarm64 /opt/steamvr/bin/linuxarm64/vrpathreg'
DRIVER_DIR='$HOME/touchframe-src/driver/build/touchframe'

case "${1:-}" in
  build)
    tar -cf - driver | "${SSH[@]}" 'rm -rf ~/touchframe-src && mkdir -p ~/touchframe-src && tar -xf - -C ~/touchframe-src &&
      cd ~/touchframe-src/driver && nice -n 19 cmake -S . -B build -G Ninja >/dev/null && nice -n 19 cmake --build build' ;;
  install)
    "${SSH[@]}" "$VRPATHREG adddriver $DRIVER_DIR && $VRPATHREG show | grep -A3 -i external" ;;
  uninstall)
    "${SSH[@]}" "$VRPATHREG removedriver $DRIVER_DIR; $VRPATHREG show | grep -A3 -i external" ;;
  restart)
    "${SSH[@]}" 'XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user restart steamvr.service' ;;
  calibrate)
    "${SSH[@]}" "XDG_RUNTIME_DIR=/run/user/\$(id -u) $DRIVER_DIR/bin/linuxarm64/tf_calibrate ${2:-right} ${3:-20}" ;;
  skeleton)
    "${SSH[@]}" "XDG_RUNTIME_DIR=/run/user/\$(id -u) $DRIVER_DIR/bin/linuxarm64/tf_skeldump ${2:-ref} ${3:-20}" ;;
  gateb)
    case "${2:-}" in
      on)
        hand="${3:-left}"
        [ "$hand" = left ] || [ "$hand" = right ] || { echo "hand: left or right" >&2; exit 1; }
        cfg="artifacts/touchplus/touchplus_${hand}.json"
        [ -f "$cfg" ] || python tools/touchplus_config.py
        "${SSH[@]}" 'mkdir -p ~/touchframe-cv && cat > ~/touchframe-cv/touchplus_'"$hand"'.json' < "$cfg"
        Hand="$(tr '[:lower:]' '[:upper:]' <<< "${hand:0:1}")${hand:1}"
        "${SSH[@]}" "XDG_RUNTIME_DIR=/run/user/\$(id -u) systemctl --user stop steamvr.service; python3 - <<EOF
import json, os
p = os.path.expanduser('~/.config/openvr/config/steamvr.vrsettings')
s = json.load(open(p))
d = s.setdefault('driver_touchframe', {})
d.update(cv_clone_serial='TouchFrame_$Hand', cv_clone_config=os.path.expanduser('~/touchframe-cv/touchplus_$hand.json'),
         cv_clone_role='${hand}_hand', cv_clone_device_id=41, cv_clone_imu='synth', cv_clone_probe=False,
         cv_clone_csv=os.path.expanduser('~/touchframe-cv/gateb_$hand.csv'))
json.dump(s, open(p, 'w'), indent=3)
print('driver_touchframe:', d)
EOF
XDG_RUNTIME_DIR=/run/user/\$(id -u) systemctl --user start steamvr.service"
        echo "Gate B on ($hand). Switch the $hand Frame controller OFF, wear the Frame, move the $hand Touch Plus; then: tools/frame.sh gateb log" ;;
      off)
        "${SSH[@]}" "XDG_RUNTIME_DIR=/run/user/\$(id -u) systemctl --user stop steamvr.service; python3 - <<'EOF'
import json, os
p = os.path.expanduser('~/.config/openvr/config/steamvr.vrsettings')
s = json.load(open(p))
s.setdefault('driver_touchframe', {})['cv_clone_serial'] = ''
json.dump(s, open(p, 'w'), indent=3)
EOF
XDG_RUNTIME_DIR=/run/user/\$(id -u) systemctl --user start steamvr.service" ;;
      log)
        "${SSH[@]}" 'grep -h cvclone ~/.local/share/Steam/logs/vrserver.txt | tail -${N:-20};
          x=$(ls -t $(find ~/.local/share/Steam/logs -iname "*xrservice*" -type f 2>/dev/null) 2>/dev/null | head -1);
          echo "== $x"; [ -n "$x" ] && grep -h -E "ContrLedsStats|initializing controller|Now we will start tracking controller 41|controller 41" "$x" | tail -${N:-20}' ;;
      *) echo "usage: tools/frame.sh gateb on [left|right] | off | log" >&2; exit 1 ;;
    esac ;;
  log)
    "${SSH[@]}" 'grep -E "touchframe|TouchFrame" ~/.local/share/Steam/logs/vrserver.txt | tail -${N:-40}' ;;
  shell)
    shift; "${SSH[@]}" "$@" ;;
  *)
    sed -n '2,18p' "$0"; exit 1 ;;
esac
