#!/usr/bin/env bash
# Quest 3 relay helper over adb (the headset on the shelf that runs quest-bridge).
#   tools/quest.sh install          build the bridge APK and install it
#   tools/quest.sh start [ip[:port]]
#                                   point the bridge at the Frame (default: the Frame host's IP,
#                                   port 28430), start the keep-awake watchdog, launch the bridge
#   tools/quest.sh stop             stop the watchdog and the bridge
#   tools/quest.sh status           bridge, watchdog, power and link state
#   tools/quest.sh log              follow the bridge and watchdog logs
#   tools/quest.sh uninstall        stop everything, remove the APK and the watchdog
# QUEST_SERIAL picks the adb device when several are connected. NO_RELAUNCH=1 makes the
# watchdog only keep the headset awake, never relaunch the bridge.
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1  # Git Bash on Windows: don't rewrite /data/... paths
PKG=com.kotorvr.touchbridge
WD=/data/local/tmp/touchframe_watchdog.sh
PIDFILE=/data/local/tmp/touchframe_watchdog.pid
ADB=(adb ${QUEST_SERIAL:+-s "$QUEST_SERIAL"})

frame_ip() {
  local h="${FRAME_HOST:-$(cat ../EchoFramePCVR/artifacts/frame_host 2>/dev/null || echo steamos@192.168.0.195)}"
  echo "${h#*@}"
}

stop_watchdog() {
  "${ADB[@]}" shell "p=\$(cat $PIDFILE 2>/dev/null); rm -f $PIDFILE; [ -n \"\$p\" ] && kill \$p 2>/dev/null; true"
}

case "${1:-}" in
  install)
    python tools/build_bridge.py
    "${ADB[@]}" install -r build/touchbridge.apk ;;
  start)
    target="${2:-$(frame_ip)}"
    [[ "$target" == *:* ]] || target="$target:28430"
    "${ADB[@]}" shell setprop debug.touchframe.target "$target"
    # Fresh copy (CRs stripped in case git checked it out with Windows line endings).
    tr -d '\r' < tools/quest-watchdog.sh | "${ADB[@]}" shell "cat > $WD && chmod 755 $WD"
    stop_watchdog
    "${ADB[@]}" shell am broadcast -a com.oculus.vrpowermanager.prox_close > /dev/null
    "${ADB[@]}" shell input keyevent KEYCODE_WAKEUP
    "${ADB[@]}" shell am start -n $PKG/android.app.NativeActivity > /dev/null
    "${ADB[@]}" shell "setsid nohup sh $WD $([ -n "${NO_RELAUNCH:-}" ] && echo 0 || echo 1) < /dev/null > /dev/null 2>&1 &"
    echo "bridge -> $target; watchdog running. tools/quest.sh status in a few seconds." ;;
  stop)
    stop_watchdog
    "${ADB[@]}" shell am force-stop $PKG
    # Virtual proximity stays CLOSE (other tools may rely on it); hand it back to the real
    # sensor with: adb shell am broadcast -a com.oculus.vrpowermanager.automation_disable
    echo "stopped bridge and watchdog" ;;
  status)
    "${ADB[@]}" shell "
      echo \"target:    \$(getprop debug.touchframe.target)\"
      p=\$(pidof $PKG); if [ -n \"\$p\" ]; then echo \"bridge:    running (pid \$p)\"; else echo 'bridge:    not running'; fi
      w=\$(cat $PIDFILE 2>/dev/null); if [ -n \"\$w\" ] && kill -0 \$w 2>/dev/null; then echo \"watchdog:  running (pid \$w)\"; else echo 'watchdog:  not running'; fi
      echo \"power:     \$(dumpsys power 2>/dev/null | grep -m1 mWakefulness= | tr -d ' ')\"
      echo \"proximity: \$(dumpsys vrpowermanager 2>/dev/null | grep -m1 'Virtual proximity state' | sed 's/.*: //') (virtual), \$(dumpsys vrpowermanager 2>/dev/null | grep -m1 '^State:' | sed 's/.*: //')\"
      echo \"front:     \$(dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity | sed 's/.* u0 //; s/ .*//')\"
      echo \"last:      \$(logcat -d -s TouchBridge:I | grep 'status:' | tail -1 | sed 's/.*status: //')\"
      logcat -d -s TouchFrameWatchdog:I | tail -3 | sed 's/^/watchdog:  /'
    " ;;
  log)
    "${ADB[@]}" logcat -s TouchBridge:I TouchFrameWatchdog:I ;;
  uninstall)
    stop_watchdog
    "${ADB[@]}" shell "am force-stop $PKG; rm -f $WD; setprop debug.touchframe.target ''"
    "${ADB[@]}" uninstall $PKG || true ;;
  *)
    sed -n '2,12p' "$0"; exit 1 ;;
esac
