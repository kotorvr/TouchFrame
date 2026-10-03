#!/usr/bin/env bash
# Host-side tests for the portable parts of the driver (no SteamVR, no Frame needed).
# Uses clang++ / g++ from PATH, or LLVM-MinGW installed by winget on Windows.
set -euo pipefail
cd "$(dirname "$0")/.."
CXX=${CXX:-}
if [ -z "$CXX" ]; then
  for c in clang++ g++ "$HOME"/AppData/Local/Microsoft/WinGet/Packages/MartinStorsjo.LLVM-MinGW.UCRT_*/*/bin/clang++; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then CXX=$c; break; fi
  done
fi
FLAGS="-std=c++17 -O1 -Wall -Wextra -Wno-unused-parameter -Isrc -Ivendor -D_USE_MATH_DEFINES"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) FLAGS="$FLAGS -DCLOCK_MONOTONIC_RAW=4 -pthread -static";; *) FLAGS="$FLAGS -pthread";; esac
mkdir -p build/test
"$CXX" $FLAGS test/parse_config_test.cpp src/cv_tracker.cpp -o build/test/parse_config_test
cfgs=(../artifacts/touchplus/touchplus_left.json ../artifacts/touchplus/touchplus_right.json)
if [ -e "${cfgs[0]}" ]; then
  ./build/test/parse_config_test "${cfgs[@]}"
else
  echo "skip Touch Plus configs: run tools/touchplus_config.py first"
fi
# The real Frame capture (if present) must also parse.
real=../artifacts/frame/configs/xrservice_config_483c39e041f4.txt
[ -e "$real" ] && ./build/test/parse_config_test "$real"
echo "driver host tests passed"
