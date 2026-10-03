#!/usr/bin/env bash
# Host-side tests for the portable firmware logic (no dongle needed): the Pulsar hop rule and
# beacon parsing, checked against an independent Python model. Uses clang/gcc from PATH or the
# LLVM-MinGW that build.sh finds.
set -euo pipefail
cd "$(dirname "$0")/.."
CC=${CC:-}
if [ -z "$CC" ]; then
  for c in clang gcc "$HOME"/AppData/Local/Microsoft/WinGet/Packages/MartinStorsjo.LLVM-MinGW.UCRT_*/*/bin/clang; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then CC=$c; break; fi
  done
fi
mkdir -p build/test
"$CC" -std=c11 -Wall -Wextra -O1 -static test/hop_test.c src/pulsar_hop.c -o build/test/hop_test.exe
python test/test.py "$PWD/build/test/hop_test.exe"
echo "radio-fw host tests passed"
