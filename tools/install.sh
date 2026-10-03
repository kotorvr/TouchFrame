#!/usr/bin/env bash
# One-command TouchFrame relay setup, run from the PC (Git Bash on Windows works).
#   tools/install.sh [all|frame|quest]         install (default: both)
#   tools/install.sh uninstall [all|frame|quest]
#
# frame: build driver_touchframe natively on the Steam Frame over SSH, register it with
#        SteamVR, restart SteamVR (interrupts whatever is running in VR).
# quest: build the bridge APK, install it on the adb-connected Quest 3, point it at the
#        Frame and start it with the keep-awake watchdog.
# Settings: FRAME_HOST (user@ip, or "local" when running on the Frame itself), FRAME_KEY,
# QUEST_SERIAL, NO_RESTART=1 (skip the SteamVR restart). See docs/INSTALL.md.
set -euo pipefail
cd "$(dirname "$0")/.."

need() { command -v "$1" > /dev/null || { echo "missing: $1 ($2)" >&2; exit 1; }; }

frame_install() {
  echo "== Frame: build, register, restart SteamVR"
  if [ "${FRAME_HOST:-}" != local ]; then need ssh "OpenSSH client"; fi
  tools/frame.sh shell 'test -x /opt/steamvr/bin/linuxarm64/vrpathreg && command -v cmake ninja > /dev/null' \
    || { echo "Frame unreachable, or cmake/ninja/SteamVR missing there (see docs/INSTALL.md)" >&2; exit 1; }
  tools/frame.sh build
  tools/frame.sh install
  [ -n "${NO_RESTART:-}" ] || tools/frame.sh restart
  sleep 8
  N=10 tools/frame.sh log || true
}

frame_uninstall() {
  echo "== Frame: unregister, restart SteamVR, remove the build"
  tools/frame.sh uninstall || true
  [ -n "${NO_RESTART:-}" ] || tools/frame.sh restart
  tools/frame.sh shell 'rm -rf ~/touchframe-src'
  echo "(calibration stays in SteamVR's settings, section driver_touchframe, for a reinstall)"
}

quest_install() {
  echo "== Quest: build and install the bridge, start it"
  need adb "Android platform-tools"
  need python "Python 3"
  adb ${QUEST_SERIAL:+-s "$QUEST_SERIAL"} get-state > /dev/null \
    || { echo "no Quest on adb (USB debugging on? QUEST_SERIAL if several devices)" >&2; exit 1; }
  tools/quest.sh install
  tools/quest.sh start
  sleep 6
  tools/quest.sh status
}

quest_uninstall() {
  echo "== Quest: stop and remove the bridge"
  tools/quest.sh uninstall
}

action=install
if [ "${1:-}" = uninstall ]; then action=uninstall; shift; fi
case "${1:-all}" in
  all)
    if [ $action = install ]; then frame_install; quest_install
    else quest_uninstall; frame_uninstall; fi ;;
  frame | quest) "${1}_$action" ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac

if [ $action = install ]; then
  echo
  echo "Done. Next: tools/frame.sh calibrate (hold the right Touch and a Frame controller together"
  echo "while wearing the Frame), then pick up the Touch controllers."
fi
