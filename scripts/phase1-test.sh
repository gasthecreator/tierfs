#!/bin/bash
# End-to-end Phase 1 test. Touches only ~/tierfs/testdata and ~/tierfs/scratch-mnt.
set -u
cd "$(dirname "$0")/.."
PORT=9099
MNT=$PWD/scratch-mnt
SRC=$PWD/testdata/sample
pass=0; fail=0
check() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }

cleanup() {
  umount "$MNT" 2>/dev/null; pkill -f "build/tierfs -f" 2>/dev/null
  pkill -f tierfs-backend 2>/dev/null; sleep 1
}
cleanup; mkdir -p "$MNT" build

./build/tierfs-backend "$SRC" $PORT 2> build/backend.log &
sleep 1
./build/tierfs -f -o host=127.0.0.1,port=$PORT,timeout=1500 "$MNT" > build/driver.log 2>&1 &
sleep 4

mount | grep -q "$MNT"; check "mounted" $?
[ "$(ls "$MNT" | sort | tr '\n' ' ')" = "big.bin hello.txt " ]; check "readdir lists both files" $?
[ "$(cat "$MNT/hello.txt")" = "$(cat "$SRC/hello.txt")" ]; check "small file content matches" $?
[ "$(stat -f %Su "$MNT/hello.txt")" = "$(whoami)" ]; check "owner is current user (not root)" $?
[ "$(stat -f %Sm -t %Y "$MNT/hello.txt")" != "1969" ]; check "mtime is not 1969" $?
[ "$(stat -f %z "$MNT/big.bin")" = "$(stat -f %z "$SRC/big.bin")" ]; check "big file size matches" $?

# Full-file integrity (3 MB spans several 1 MiB protocol reads)
[ "$(shasum -a 256 < "$MNT/big.bin")" = "$(shasum -a 256 < "$SRC/big.bin")" ]; check "big file sha256 matches" $?

# Partial read in the middle, crossing a 1 MiB boundary
a=$(dd if="$MNT/big.bin" bs=1 skip=1048570 count=20 2>/dev/null | shasum -a 256)
b=$(dd if="$SRC/big.bin" bs=1 skip=1048570 count=20 2>/dev/null | shasum -a 256)
[ "$a" = "$b" ]; check "partial read across 1 MiB boundary matches" $?

# Missing file and write attempts
cat "$MNT/nope" >/dev/null 2>&1; [ $? -ne 0 ]; check "missing file errors" $?
( echo x > "$MNT/new.txt" ) 2>/dev/null; [ $? -ne 0 ]; check "write is refused (read-only)" $?

# Backend dies: reads must fail fast, not hang
pkill -f tierfs-backend; sleep 1
start=$(date +%s)
# macOS has no `timeout`; perl's alarm kills the child after 15s (exit 142).
perl -e 'alarm 15; exec @ARGV' cat "$MNT/hello.txt" >/dev/null 2>build/offline.err; rc=$?
elapsed=$(( $(date +%s) - start ))
echo "      (offline read: exit=$rc after ${elapsed}s: $(head -c 80 build/offline.err))"
[ $rc -ne 0 ] && [ $rc -ne 127 ] && [ $rc -ne 142 ] && [ $elapsed -le 8 ]; check "offline read fails fast (no hang)" $?

# Backend returns: driver reconnects by itself
./build/tierfs-backend "$SRC" $PORT 2>> build/backend.log &
sleep 1
[ "$(cat "$MNT/hello.txt" 2>/dev/null)" = "$(cat "$SRC/hello.txt")" ]; check "reconnects after backend restart" $?

cleanup
echo "---- $pass passed, $fail failed"
[ $fail -eq 0 ]
