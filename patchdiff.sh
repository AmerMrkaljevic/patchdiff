#!/usr/bin/env bash
# patchdiff.sh -- the full old-vs-new pipeline in one command: Ghidra
# headless analysis + function extraction on both binaries, then rank what
# changed by how security-relevant it looks.
#
# Usage:
#   GHIDRA_HOME=/path/to/ghidra ./patchdiff.sh old_binary new_binary [workdir] [-- bindiff_lite args]
#
# Example:
#   GHIDRA_HOME=~/tools/ghidra_11.3.2_PUBLIC ./patchdiff.sh \
#       firmware-1.2.3.bin firmware-1.2.4.bin /tmp/patchdiff-work
set -euo pipefail

if [ -z "${GHIDRA_HOME:-}" ]; then
    echo "error: set GHIDRA_HOME to your Ghidra install directory" >&2
    exit 1
fi
HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"
if [ ! -x "$HEADLESS" ]; then
    echo "error: $HEADLESS not found or not executable" >&2
    exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OLD_BIN="$1"; NEW_BIN="$2"
WORKDIR="${3:-$(mktemp -d)}"
shift $(( $# >= 3 ? 3 : 2 ))   # "$@" is now whatever's left to pass to bindiff_lite.py
# Ghidra's -import creates the .gpr *inside* this directory but won't create
# the directory itself -- without this, analyzeHeadless aborts with
# "Directory not found" on a workdir that doesn't already have it.
mkdir -p "$WORKDIR/project"

extract() {
    local bin="$1" tag="$2"
    local out="$WORKDIR/$tag.jsonl"
    echo "analyzing $bin ..." >&2
    "$HEADLESS" "$WORKDIR/project" "proj_$tag" -import "$bin" -overwrite \
        -postScript extract_functions.py "$out" \
        -scriptPath "$SCRIPT_DIR" > "$WORKDIR/$tag.ghidra.log" 2>&1 \
        || { echo "Ghidra failed on $bin -- see $WORKDIR/$tag.ghidra.log" >&2; exit 1; }
    grep -q "wrote" "$WORKDIR/$tag.ghidra.log" \
        || { echo "extract_functions.py did not report success -- see $WORKDIR/$tag.ghidra.log" >&2; exit 1; }
    echo "$out"
}

OLD_JSON=$(extract "$OLD_BIN" old)
NEW_JSON=$(extract "$NEW_BIN" new)

python3 "$SCRIPT_DIR/bindiff_lite.py" "$OLD_JSON" "$NEW_JSON" "$@"
