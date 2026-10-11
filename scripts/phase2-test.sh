#!/bin/bash
# Phase 2: persistent metadata cache. Touches only ~/tierfs/build and scratch-mnt.
set -u
cd "$(dirname "$0")/.."
PORT=9097; MNT=$PWD/scratch-mnt; LIVE=$PWD/build/live; CACHE=$PWD/build/testcache2
pass=0; fail=0
check() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
stop_driver() { umount "$MNT" 2>/dev/null; pkill -f "build/tierfs -f" 2>/dev/null; sleep 1.5; }
stop_backend() { pkill -f "tierfs-backend $LIVE" 2>/dev/null; sleep 1; }
start_backend() { ./build/tierfs-backend "$LIVE" $PORT 2>>build/p2-backend.log & sleep 1; }
start_driver() { ./build/tierfs -f -o host=127.0.0.1,port=$PORT,timeout=1000,cache="$1" "$MNT" >>build/p2-driver.log 2>&1 & sleep 4; }
cleanup() { stop_driver; stop_backend; }
trap cleanup EXIT
cleanup; rm -rf "$LIVE" "$CACHE" build/p2-*.log; mkdir -p "$MNT" "$LIVE/docs/deep"
cp testdata/sample/hello.txt testdata/sample/cold.bin "$LIVE/"
echo "readme" > "$LIVE/docs/readme.md"; echo "deep" > "$LIVE/docs/deep/f.txt"

echo "== populate cache while online"
start_backend; start_driver "$CACHE"
ls -lR "$MNT" > /dev/null
[ -s "$CACHE/meta.db" ] || [ -s "$CACHE/meta.db-wal" ]; check "cache database created on disk" $?
stop_driver; stop_backend

echo "== fresh mount, backend DEAD, same cache"
start_driver "$CACHE"
mount | grep -q "$MNT"; check "mount succeeds with backend down" $?
[ "$(ls "$MNT" | sort | tr '\n' ' ')" = "cold.bin docs hello.txt " ]; check "root listing served from disk cache" $?
[ "$(ls "$MNT/docs/deep")" = "f.txt" ]; check "nested listing served from disk cache" $?
[ "$(stat -f %z "$MNT/cold.bin")" = "200000" ]; check "stat served from disk cache" $?
perl -e 'alarm 15; exec @ARGV' cat "$MNT/cold.bin" >/dev/null 2>build/p2-err; rc=$?
grep -q "Input/output error" build/p2-err && [ $rc -ne 142 ]; check "content read fails with EIO (not ENOENT, no hang)" $?
cat "$MNT/never-existed" 2>&1 | grep -q "No such file"; check "unlisted path still says ENOENT offline" $?
stop_driver

echo "== deletion on server propagates into the cache"
start_backend; rm -rf "$LIVE/docs"; rm "$LIVE/cold.bin"
start_driver "$CACHE"
ls "$MNT" >/dev/null 2>&1      # online readdir refreshes the cache
stop_driver; stop_backend
start_driver "$CACHE"
[ "$(ls "$MNT" | tr '\n' ' ')" = "hello.txt " ]; check "deleted files gone from offline listing" $?
stat "$MNT/docs/deep/f.txt" >/dev/null 2>&1; [ $? -ne 0 ]; check "deleted subtree gone from offline stat" $?
stop_driver

echo "== cold start: backend dead AND no cache"
rm -rf "$PWD/build/emptycache2"
start_driver "$PWD/build/emptycache2"
mount | grep -q "$MNT"; check "cold offline mount completes (does not hang mount_nfs)" $?
ps aux | grep -v grep | grep -q "mount_nfs.*$(basename "$MNT")"; [ $? -ne 0 ]; check "no mount_nfs process left stuck" $?
perl -e 'alarm 15; exec @ARGV' ls "$MNT" >/dev/null 2>build/p2-err; rc=$?
grep -q "Input/output error" build/p2-err && [ $rc -ne 142 ]; check "cold offline listing fails fast with EIO (not an empty dir)" $?
stop_driver
rm -rf "$PWD/build/emptycache2"

echo "== corrupt cache is rebuilt"
start_backend
mkdir -p build/badcache && echo "garbage garbage" > build/badcache/meta.db
start_driver "$PWD/build/badcache"
got=$(cat "$MNT/hello.txt" 2>&1); [ "$got" = "$(cat "$LIVE/hello.txt")" ]; rc=$?
[ $rc -ne 0 ] && echo "      (got: $got | mounts: $(mount | grep -c "$MNT") | backend: $(pgrep -f "tierfs-backend $LIVE" | wc -l | tr -d " "))"
check "works with corrupt cache file" $rc
grep -q "unreadable; rebuilt" build/p2-driver.log; check "corruption was reported and recovered" $?
rm -rf build/badcache
stop_driver

echo "---- $pass passed, $fail failed"
[ $fail -eq 0 ]
