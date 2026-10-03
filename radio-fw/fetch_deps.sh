#!/usr/bin/env bash
# Fetch pinned third-party sources into radio-fw/third_party (gitignored).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p third_party
fetch() {  # name url tag
  if [ ! -d "third_party/$1" ]; then
    git clone -q --depth 1 --branch "$3" "$2" "third_party/$1"
  fi
  echo "$1 $(git -C third_party/$1 describe --tags --always)"
}
fetch nrfx    https://github.com/NordicSemiconductor/nrfx.git     v3.14.0
fetch tinyusb https://github.com/hathach/tinyusb.git              0.21.0
fetch cmsis   https://github.com/ARM-software/CMSIS_5.git         5.9.0
