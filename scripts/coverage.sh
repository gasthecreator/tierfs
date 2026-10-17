#!/bin/bash
# Line coverage of the device side (what `make linux-test` exercises), as a signal for finding untested code, not as a target.
# Runs on Linux (CI) and macOS. Usage: scripts/coverage.sh   (builds into build/, so run it in a clean checkout or after `make clean`)
set -euo pipefail
cd "$(dirname "$0")/.."
make linux-test SAN="--coverage -O0" >/dev/null
echo "line coverage by file (device-side tests only; the Mac side is covered by make test):"
for f in core/devicestore core/securechannel core/pairings core/crypto core/deviceclient backend/device_server; do
  obj=$(ls build/*"$(basename "$f")"*.gcno 2>/dev/null | head -1) || true
  [ -n "$obj" ] || continue
  gcov -n -o build "$f.cpp" 2>/dev/null | awk -v f="$f.cpp" '$0 ~ "File .*" f "\x27" {on=1; next} on && /Lines executed/ {sub(/executed:/,"",$2); print "  " f ": " $2; on=0}'
done
