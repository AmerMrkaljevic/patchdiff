#!/usr/bin/env bash
# Compiles the bundled example pair so you have something to run patchdiff.sh
# against immediately. The only difference between the two sources is one
# line in validate_mss() -- see the diff for yourself:
#   diff examples/vulnerable.c examples/patched.c
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
gcc -O0 -g -o vulnerable vulnerable.c
gcc -O0 -g -o patched patched.c
echo "built ./examples/vulnerable and ./examples/patched"
