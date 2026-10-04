#!/usr/bin/env bash
# One-command TouchFrame setup, run from the PC (Git Bash on Windows works).
#   tools/install.sh [all|frame|quest|radio]   install (default: frame + quest, the relay)
#   tools/install.sh uninstall [all|frame|quest|radio]
#
# frame: build driver_touchframe natively on the Steam Frame over SSH, register it with
#        SteamVR, restart SteamVR (interrupts whatever is running in VR).
# quest: build the bridge APK, install it on the adb-connected Quest 3, point it at the
#        Frame and start it with the keep-awake watchdog.
# radio: the Touch Plus radio dongle on the Frame (after `frame`): copy the XRService LED-model
#        configs and Meta IMU calibration to ~/.config/touchframe, check the dongle's hidraw node
#        (VID:PID 1209:0001; no udev rule: 0664 root:input) and group input; with
#        MODE=radio_camera|radio_3dof also switch driver_touchframe.mode and restart SteamVR.
#        uninstall radio: mode back to relay (pairings in ~/.config/touchframe stay).
# Settings: FRAME_HOST (user@ip, or "local" when running on the Frame itself), FRAME_KEY,
# QUEST_SERIAL, NO_RESTART=1 (skip the SteamVR restart), MODE. See docs/INSTALL.md.
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

radio_set_mode() {  # radio_set_mode MODE: edit SteamVR's settings with SteamVR stopped
  # SteamVR rewrites its settings on exit, so a running SteamVR is stopped first and started
  # again; NO_RESTART=1 leaves a running SteamVR alone (and the mode unchanged).
  local keep=0
  [ -z "${NO_RESTART:-}" ] || keep=1
  tools/frame.sh shell "export XDG_RUNTIME_DIR=/run/user/\$(id -u)
running=0
if systemctl --user -q is-active steamvr.service; then
  if [ $keep = 1 ]; then
    echo '  SteamVR is running and NO_RESTART is set: driver_touchframe.mode unchanged'
    exit 0
  fi
  running=1
  systemctl --user stop steamvr.service
fi
python3 - <<EOF
import json, os
p = os.path.expanduser('~/.config/openvr/config/steamvr.vrsettings')
s = json.load(open(p))
s.setdefault('driver_touchframe', {})['mode'] = '$1'
json.dump(s, open(p, 'w'), indent=3)
print('  driver_touchframe.mode = $1')
EOF
[ \$running = 0 ] || systemctl --user start steamvr.service"
}

radio_install() {
  echo "== Frame: Touch Plus radio dongle"
  case "${MODE:-}" in "" | radio_camera | radio_3dof) ;; *) echo "MODE: radio_camera or radio_3dof" >&2; exit 1 ;; esac
  # XRService LED-model configs (model_number ..._Roy_EV1.5, docs/re/FRAME-MODEL.md) and Meta's
  # per-unit IMU calibration, both from tools/touchplus_config.py.
  [ -f artifacts/touchplus/touchplus_left.json ] || { need python "Python 3"; python tools/touchplus_config.py; }
  tools/frame.sh shell 'mkdir -p ~/.config/touchframe'
  for f in touchplus_left.json touchplus_right.json touchplus_left_meta_cal.json touchplus_right_meta_cal.json; do
    [ -f "artifacts/touchplus/$f" ] || { echo "  (no artifacts/touchplus/$f)"; continue; }
    tools/frame.sh shell "cat > ~/.config/touchframe/$f" < "artifacts/touchplus/$f"
    echo "  ~/.config/touchframe/$f"
  done
  # The driver opens the dongle's vendor HID interface itself (driver_touchframe.radio_transport
  # "hidraw" = find VID:PID 1209:0001 in /sys/class/hidraw). Nothing to install: just check.
  tools/frame.sh shell 'bash -s' <<'EOF'
me=$(id -un)
found=""
for d in /sys/class/hidraw/hidraw*; do
  [ -r "$d/device/uevent" ] || continue
  hid=$(sed -n 's/^HID_ID=//p' "$d/device/uevent" | tr '[:lower:]' '[:upper:]')
  case "$hid" in *:00001209:00000001) found="$found /dev/${d##*/}" ;; esac
done
if [ -z "$found" ]; then
  echo "  dongle: not plugged in (no hidraw device 1209:0001); the driver picks it up when it appears"
  echo "          (the Frame has one USB-C port: use a hub)"
fi
for n in $found; do
  echo "  dongle: $(ls -l "$n")"
  if [ -r "$n" ] && [ -w "$n" ]; then echo "  $n: read/write OK for $me"
  else echo "  $n: NOT read/writable by $me (expected 0664 root:input with $me in group input)"; fi
done
if id -nG | tr ' ' '\n' | grep -qx input; then echo "  $me is in group input"
else echo "  WARNING: $me is not in group input: the driver can't open the dongle (no udev rule is installed)"; fi
EOF
  if [ -n "${MODE:-}" ]; then radio_set_mode "$MODE"
  else echo "  driver_touchframe.mode unchanged (MODE=radio_camera or radio_3dof switches it)"; fi
}

radio_uninstall() {
  echo "== Frame: driver_touchframe.mode back to relay"
  radio_set_mode relay
  echo "  (the radio pairing state and configs stay in ~/.config/touchframe)"
}

action=install
if [ "${1:-}" = uninstall ]; then action=uninstall; shift; fi
case "${1:-all}" in
  all)
    if [ $action = install ]; then frame_install; quest_install
    else quest_uninstall; frame_uninstall; fi ;;
  frame | quest | radio) "${1}_$action" ;;
  *) sed -n '2,18p' "$0"; exit 1 ;;
esac

if [ $action = install ] && [ "${1:-all}" = radio ]; then
  echo
  echo "Done. Pair a controller: set driver_touchframe.radio_pair_hand (left|right) and bump"
  echo "radio_pair_version in SteamVR's settings, then hold the controller's pairing buttons."
elif [ $action = install ]; then
  echo
  echo "Done. Next: tools/frame.sh calibrate (hold the right Touch and a Frame controller together"
  echo "while wearing the Frame), then pick up the Touch controllers."
fi
