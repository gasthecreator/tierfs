#!/bin/bash
# Builds a tiny tree containing a symlink that escapes the root, then runs the
# protocol abuse tests against a fresh backend. Loopback only.
cd "$(dirname "$0")/.."
T=$(mktemp -d)
mkdir -p "$T/sub" && echo hi > "$T/hello.txt" && ln -s /etc "$T/link-out"
./build/tierfs-backend "$T" 9098 2>build/attack-backend.log & BP=$!
sleep 1
python3 -I scripts/attack.py 9098; rc=$?
kill $BP 2>/dev/null; rm -rf "$T"
grep -i "sanitizer\|runtime error" build/attack-backend.log && rc=1
exit $rc
