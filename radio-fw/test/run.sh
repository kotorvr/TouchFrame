#!/usr/bin/env bash
# Host-side tests for the portable firmware logic (no dongle needed): the Pulsar hop rule and
# beacon parsing, checked against an independent Python model; link v3 (link.h vs tools/radio.py,
# and a host session against tools/fake_dongle.py); crypto and byte formats vs the Python tools; and the
# host <-> fake-controller loopback simulator (test/sim.c). Uses clang/gcc from PATH or the
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
"$CC" -std=c11 -Wall -Wextra -Wconversion -O2 -static test/crypto_test.c src/crypto.c -o build/test/crypto_test.exe
build/test/crypto_test.exe
python test/test_crypto.py "$PWD/build/test/crypto_test.exe"
"$CC" -std=c11 -Wall -Wextra -Wconversion -Wno-sign-conversion -O2 -static -Isrc test/store_test.c src/store.c -o build/test/store_test.exe
build/test/store_test.exe
CORE="src/store.c src/host_core.c src/ctrl_core.c src/pulsar_cl.c src/pulsar_pair.c src/pulsar_ll.c src/pulsar_hop.c src/crypto.c"
"$CC" -std=c11 -Wall -Wextra -Wconversion -O1 -static -Isrc test/ll_test.c src/pulsar_ll.c src/pulsar_hop.c   src/pulsar_pair.c src/crypto.c -o build/test/ll_test.exe
python test/test_ll.py "$PWD/build/test/ll_test.exe"
"$CC" -std=gnu11 -Wall -Wextra -Wconversion -Wno-sign-conversion -O2 -static -Isrc test/sim.c $CORE -o build/test/sim.exe
for ppm in "15 -15" "0 0" "100 -100"; do build/test/sim.exe $ppm; done
python test/test_link.py
echo "radio-fw host tests passed"
