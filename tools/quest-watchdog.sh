#!/system/bin/sh
# TouchFrame keep-awake watchdog for the shelf Quest. tools/quest.sh pushes it to
# /data/local/tmp and starts it detached as the adb shell user, so it keeps running after
# the PC disconnects (until reboot or `tools/quest.sh stop`). Every 10 s it:
#   - wakes the headset if it fell asleep;
#   - re-sends the prox_close broadcast if the virtual proximity sensor isn't CLOSE any more
#     (it's sticky, but an automation_disable broadcast or a standby/wake cycle clears it,
#     and then the real sensor sees "unworn" and the headset sleeps);
#   - relaunches the bridge if it died, unless another app is in front (arg 1 = 0 turns
#     relaunching off).
# Log: adb logcat -s TouchFrameWatchdog
PKG=com.kotorvr.touchbridge
PIDFILE=/data/local/tmp/touchframe_watchdog.pid
RELAUNCH=${1:-1}

echo $$ > $PIDFILE
say() { log -t TouchFrameWatchdog "$*"; }
say "started (pid $$, relaunch=$RELAUNCH)"

while [ "$(cat $PIDFILE 2>/dev/null)" = "$$" ]; do
  case "$(dumpsys power 2>/dev/null | grep -m1 mWakefulness=)" in
    *Awake*) ;;
    *) input keyevent KEYCODE_WAKEUP; say "headset was asleep: woke it" ;;
  esac
  if ! dumpsys vrpowermanager 2>/dev/null | grep -m1 -q "Virtual proximity state: CLOSE"; then
    am broadcast -a com.oculus.vrpowermanager.prox_close > /dev/null
    say "virtual proximity was not CLOSE: sent prox_close"
  fi
  if [ "$RELAUNCH" = 1 ] && ! pidof $PKG > /dev/null; then
    top=$(dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity)
    case "$top" in
      *com.oculus.vrshell* | *com.oculus.systemux* | *com.oculus.shellenv* | "")
        am start -n $PKG/android.app.NativeActivity > /dev/null
        say "bridge was not running: relaunched it" ;;
    esac
  fi
  sleep 10
done
say "stopped"
