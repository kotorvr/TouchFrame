#!/usr/bin/env bash
# Build (and optionally flash) the dongle firmware. Usage: ./build.sh [make targets...]
#   ./build.sh          build build/touchframe-radio.zip
#   ./build.sh flash    build, reboot the dongle into its bootloader, flash it
set -euo pipefail
cd "$(dirname "$0")"

[ -d third_party/nrfx ] || ./fetch_deps.sh

# Windows installs (winget) that are not on Git Bash's PATH by default.
for d in "/c/Program Files (x86)/Arm GNU Toolchain arm-none-eabi"/*/bin \
         "/c/Program Files/Arm GNU Toolchain arm-none-eabi"/*/bin \
         "$HOME"/AppData/Local/Microsoft/WinGet/Packages/ezwinports.make_*/bin \
         "$HOME"/AppData/Local/Microsoft/WinGet/Packages/NordicSemiconductor.nrfutil_*; do
  [ -d "$d" ] && PATH="$d:$PATH"
done
export PATH

exec make "$@"
