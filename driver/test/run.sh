#!/usr/bin/env bash
# Host-side tests for the portable parts of the driver (no SteamVR, no Frame, no dongle needed).
# Uses clang++ / g++ from PATH, or LLVM-MinGW installed by winget on Windows. The radio tests run
# the driver's RadioSource against tools/fake_dongle.py over TCP (driver/test/fake_dongle_server.py).
#   driver/test/run.sh          everything
#   QUICK=1 driver/test/run.sh  skip the fake-dongle runs (~1 min)
set -euo pipefail
cd "$(dirname "$0")/.."
CXX=${CXX:-}
if [ -z "$CXX" ]; then
  for c in clang++ g++ "$HOME"/AppData/Local/Microsoft/WinGet/Packages/MartinStorsjo.LLVM-MinGW.UCRT_*/*/bin/clang++; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then CXX=$c; break; fi
  done
fi
PY=${PY:-$(command -v python3 || command -v python)}
FLAGS="-std=c++17 -O1 -Wall -Wextra -Wno-unused-parameter -Isrc -Ivendor -D_USE_MATH_DEFINES"
LIBS=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) FLAGS="$FLAGS -pthread -static"; LIBS="-lws2_32";; *) FLAGS="$FLAGS -pthread";; esac
B=build/test
mkdir -p $B
RADIO="src/radio_source.cpp src/radio_transport.cpp src/radio_link.cpp src/time_sync.cpp src/radio_decode.cpp src/led_phase.cpp"

# XRService controller configs.
"$CXX" $FLAGS test/parse_config_test.cpp src/cv_tracker.cpp -o $B/parse_config_test
cfgs=(../artifacts/touchplus/touchplus_left.json ../artifacts/touchplus/touchplus_right.json)
if [ -e "${cfgs[0]}" ]; then
  ./$B/parse_config_test "${cfgs[@]}"
else
  echo "skip Touch Plus configs: run tools/touchplus_config.py first"
fi
# The real Frame capture (if present) must also parse.
real=../artifacts/frame/configs/xrservice_config_483c39e041f4.txt
[ -e "$real" ] && ./$B/parse_config_test "$real"

# The link mirror against the firmware's header.
"$CXX" $FLAGS -Wno-invalid-offsetof test/link_check_test.cpp -o $B/link_check_test
./$B/link_check_test

# COBS/HID framing, time sync, decoding, haptics, and the LED phase loop against a camera model.
"$CXX" $FLAGS -O2 test/radio_unit_test.cpp $RADIO -o $B/radio_unit_test $LIBS
./$B/radio_unit_test

"$CXX" $FLAGS test/radio_fake_test.cpp $RADIO -o $B/radio_fake_test $LIBS
"$CXX" $FLAGS test/radio_backend_test.cpp src/radio_backend.cpp src/cv_source.cpp src/cv_tracker.cpp src/xr_log.cpp \
  $RADIO -o $B/radio_backend_test $LIBS

scratch=$B/scratch
rm -rf $scratch && mkdir -p $scratch
if [ -n "${QUICK:-}" ]; then
  ./$B/radio_backend_test $scratch
  echo "driver host tests passed (QUICK: fake-dongle runs skipped)"
  exit 0
fi

# fake_dongle over TCP: one server per scenario; "ready PORT" on its first line.
pids=()
cleanup() { for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
serve() {  # serve NAME ARGS... -> sets PORT
  local log=$scratch/fake_$1.log; shift
  "$PY" test/fake_dongle_server.py --port 0 --seconds 120 "$@" > "$log" 2>&1 &
  pids+=($!)
  for _ in $(seq 100); do
    PORT=$(sed -n 's/^ready \([0-9]*\).*/\1/p' "$log" | head -1)
    [ -n "$PORT" ] && return 0
    sleep 0.1
  done
  echo "fake_dongle_server didn't start:"; cat "$log"; exit 1
}
serve raw --framing raw --drift-ppm 12.5
./$B/radio_fake_test tcp:127.0.0.1:$PORT basic 12.5 $scratch/state_raw.json
serve hid --framing hid --drift-ppm -20
./$B/radio_fake_test tcphid:127.0.0.1:$PORT basic -20 $scratch/state_hid.json
serve reboot --framing raw --reboot-at 4
./$B/radio_fake_test tcp:127.0.0.1:$PORT reboot 12.5 $scratch/state_reboot.json
serve backend --framing raw
./$B/radio_backend_test $scratch tcp:127.0.0.1:$PORT $scratch/state_backend.json
echo "driver host tests passed"
