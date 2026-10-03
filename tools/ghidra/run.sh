#!/usr/bin/env bash
# Drive Ghidra headless over the extracted nRF52 images.
#   tools/ghidra/run.sh <image-name> <vectorHex> [funcsFile]
# Example:
#   python tools/ghidra/extract_images.py
#   python tools/ghidra/fde_starts.py
#   tools/ghidra/run.sh syncboss 0x1100 artifacts/work/syncboss.funcs
#
# Imports artifacts/work/<name>.bin at the right base, runs SetupCortexM.java to
# add memory/labels and seed functions, auto-analyzes, then ExportDecomp.java
# writes decompiled C to artifacts/work/<name>.decomp.c (gitignored).
set -euo pipefail
export JAVA_HOME="C:/Users/kaibo/tools/jdk-21.0.12.1+1"
GHIDRA="C:/Users/kaibo/tools/ghidra_12.1.4_PUBLIC"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$ROOT/artifacts/work"
PROJ="$ROOT/artifacts/ghidra_proj"
SCRIPTS="$ROOT/tools/ghidra"
mkdir -p "$PROJ"

NAME="$1"; VEC="$2"; FUNCS="${3:-}"
IMG="$WORK/$NAME.bin"
# base = vector - 0x100 for dAeH images, 0 for raw syncboss
IMGJSON_WIN=$(cygpath -w "$WORK/images.json")
BASE=$(python -c "import json,sys;print(hex(json.load(open(sys.argv[1]))['$NAME']['base']))" "$IMGJSON_WIN")

SETUP_ARGS=("$VEC")
[ -n "$FUNCS" ] && SETUP_ARGS+=("$FUNCS")

"$GHIDRA/support/analyzeHeadless.bat" "$PROJ" "tf_$NAME" \
  -import "$IMG" \
  -processor "ARM:LE:32:Cortex" \
  -loader BinaryLoader -loader-baseAddr "$BASE" \
  -scriptPath "$SCRIPTS" \
  -preScript SetupCortexM.java "${SETUP_ARGS[@]}" \
  -postScript ExportDecomp.java "$WORK/$NAME.decomp.c" \
  -deleteProject
