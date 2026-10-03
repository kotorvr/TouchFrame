#!/usr/bin/env bash
# Run DumpByStrings on a Frame binary in artifacts/ghidra_proj_frame (Git Bash on Windows).
# usage: tools/ghidra/run_frame.sh import|process <binary> <outfile.c> <needles.txt> [hexaddr | xhexaddr ...]
#   import : import + auto-analyse artifacts/frame/<binary> into project <binary-without-ext>
#   process: reuse the analysed program (fast)
# Inputs/outputs live in artifacts/ (gitignored). Never commit Valve binaries or their decompilation.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
W() { cygpath -w "$1"; }
export JAVA_HOME="${JAVA_HOME:-C:\\Users\\kaibo\\tools\\jdk-21.0.12.1+1}"
GH="${GHIDRA:-/c/Users/kaibo/tools/ghidra_12.1.4_PUBLIC}"
mode="$1"; bin="$2"; out="$3"; needles="$4"; shift 4
proj="${bin%%.*}"
if [ "$mode" = import ]; then
  src="-import $(W "$ROOT/artifacts/frame/$bin") -overwrite -max-cpu 16"
else
  src="-process $bin -noanalysis -readOnly"
fi
cmd //c "$(W "$GH/support/analyzeHeadless.bat") $(W "$ROOT/artifacts/ghidra_proj_frame") $proj $src -scriptPath $(W "$ROOT/tools/ghidra") -postScript DumpByStrings.java $(W "$out") $(W "$needles") $*" < /dev/null
