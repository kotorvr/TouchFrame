#!/usr/bin/env bash
# Steam Frame helper over SSH (the Frame's adbd has no TCP mode).
#   tools/frame.sh build       copy driver/ to the Frame and build it natively (aarch64)
#   tools/frame.sh install     register the built driver with SteamVR (vrpathreg)
#   tools/frame.sh uninstall   unregister it
#   tools/frame.sh restart     restart SteamVR (interrupts whatever is running in VR)
#   tools/frame.sh log         TouchFrame lines from vrserver.txt
#   tools/frame.sh shell CMD   run a command
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="${FRAME_HOST:-$(cat ../EchoFramePCVR/artifacts/frame_host 2>/dev/null || echo steamos@192.168.0.195)}"
KEY="${FRAME_KEY:-$HOME/.ssh/id_rsa_frame_devkit}"
SSH=(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=5 "$HOST")
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
  log)
    "${SSH[@]}" 'grep -E "touchframe|TouchFrame" ~/.local/share/Steam/logs/vrserver.txt | tail -${N:-40}' ;;
  shell)
    shift; "${SSH[@]}" "$@" ;;
  *)
    sed -n '2,9p' "$0"; exit 1 ;;
esac
