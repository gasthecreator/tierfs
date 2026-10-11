#!/bin/bash
# Chunk cache through the real mount, with real tools. Touches only build/ and scratch-mnt.
set -u
cd "$(dirname "$0")/.."
PORT=9095; MNT=$PWD/scratch-mnt; LIVE=$PWD/build/live3
pass=0; fail=0
check() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
stop_driver() { umount "$MNT" 2>/dev/null; pkill -f "build/tierfs -f" 2>/dev/null; sleep 2; }
stop_backend() { pkill -f "tierfs-backend $LIVE" 2>/dev/null; sleep 1; }
start_backend() { ./build/tierfs-backend "$LIVE" $PORT 2>>build/p2b-backend.log & sleep 1; }
# usage: start_driver <cachedir> <statsfile> [extra -o opts]
start_driver() { ./build/tierfs -f -o host=127.0.0.1,port=$PORT,timeout=1500,cache="$1",stats="$2"${3:+,$3} "$MNT" >>build/p2b-driver.log 2>&1 & sleep 4; }
stat_of() { grep "^$2=" "$1" | cut -d= -f2; }
cleanup() { stop_driver; stop_backend; }
trap cleanup EXIT
cleanup; rm -rf "$LIVE" build/p2b-* build/gitwork build/clone* build/cache_*; mkdir -p "$MNT" "$LIVE/src"
head -c 6291456 /dev/urandom > "$LIVE/big.bin"
cat > "$LIVE/src/hello.c" <<'C'
#include <stdio.h>
int main(void) { puts("compiled from the mount"); return 0; }
C
# a small bare git repo with a multi-MB binary, packed (git mmaps packfiles)
git init -q build/gitwork && ( cd build/gitwork && git config user.email t@t && git config user.name t &&
  echo one > a.txt && head -c 2500000 /dev/urandom > blob.bin && git add . && git commit -qm one &&
  echo two >> a.txt && git commit -qam two && git tag v1 )
git clone -q --bare build/gitwork "$LIVE/repo.git" && git -C "$LIVE/repo.git" gc -q 2>/dev/null
WANT=$(shasum -a 256 < "$LIVE/big.bin")

echo "== cold read, populates the persistent chunk cache"
start_backend; start_driver "$PWD/build/cache_a" "$PWD/build/p2b-stats1"
[ "$(shasum -a 256 < "$MNT/big.bin")" = "$WANT" ]; check "6 MB file reads correctly through the mount" $?
stop_driver
f=$(stat_of build/p2b-stats1 fetches); pf=$(stat_of build/p2b-stats1 prefetch_fetches)
echo "      (fetches=$f prefetch_fetches=$pf)"
[ $((f + pf)) -ge 6 ] && [ $((f + pf)) -le 8 ]; check "each of the 6 chunks fetched about once (no duplicates)" $?

echo "== remount, backend DEAD: data comes from the chunk cache"
stop_backend
start_driver "$PWD/build/cache_a" "$PWD/build/p2b-stats2"
[ "$(shasum -a 256 < "$MNT/big.bin")" = "$WANT" ]; check "whole file readable offline after remount (bytes identical)" $?
stop_driver
[ "$(stat_of build/p2b-stats2 fetches)" = "0" ]; check "zero network fetches while offline" $?

echo "== partly cached file + backend dead: failure must be loud, never a silently short file"
start_backend
start_driver "$PWD/build/cache_b" "$PWD/build/p2b-stats3" readahead=0
dd if="$MNT/big.bin" of=/dev/null bs=1048576 count=2 2>/dev/null     # chunks 0 and 1 only
stop_driver; stop_backend
start_driver "$PWD/build/cache_b" "$PWD/build/p2b-stats4" readahead=0
cat "$MNT/big.bin" > build/p2b-out 2> build/p2b-err; rc=$?
echo "      (cat exit=$rc, wrote $(stat -f %z build/p2b-out) of 6291456 bytes: $(head -c 70 build/p2b-err))"
[ $rc -ne 0 ]; check "cat exits non-zero on a mid-file failure" $?
grep -q "Input/output error" build/p2b-err; check "error says Input/output error" $?
cp "$MNT/big.bin" build/p2b-cp 2> build/p2b-cperr; [ $? -ne 0 ]; check "cp exits non-zero (does not report a truncated copy as success)" $?
[ "$(dd if="$MNT/big.bin" bs=1048576 count=2 2>/dev/null | shasum -a 256)" = "$(dd if="$LIVE/big.bin" bs=1048576 count=2 2>/dev/null | shasum -a 256)" ]; check "the cached first 2 MB still read fine" $?
stop_driver

echo "== real tools on the mount"
start_backend
start_driver "$PWD/build/cache_c" "$PWD/build/p2b-stats5"
cc "$MNT/src/hello.c" -o build/p2b-hello 2>build/p2b-ccerr && [ "$(./build/p2b-hello)" = "compiled from the mount" ]; check "clang compiles a source file read from the mount" $?
git --git-dir="$MNT/repo.git" log --oneline 2>build/p2b-giterr | grep -q two; check "git log on a repo inside the mount" $?
git --git-dir="$MNT/repo.git" fsck --full >build/p2b-fsck 2>&1; rc=$?
echo "      (git fsck exit=$rc: $(tail -1 build/p2b-fsck | head -c 70))"
[ $rc -eq 0 ]; check "git fsck --full (reads and mmaps every object) passes" $?
git clone -q "file://$MNT/repo.git" build/clone 2>build/p2b-cloneerr; rc=$?
[ $rc -eq 0 ] && [ "$(git -C build/clone rev-parse v1)" = "$(git -C build/gitwork rev-parse v1)" ] && cmp -s build/clone/blob.bin build/gitwork/blob.bin; check "git clone from the mount reproduces the repo byte-for-byte" $?
stop_driver

echo "== clone again fully OFFLINE from the warm cache"
stop_backend
start_driver "$PWD/build/cache_c" "$PWD/build/p2b-stats6"
rm -rf build/clone2; git clone -q "file://$MNT/repo.git" build/clone2 2>build/p2b-cloneerr2; rc=$?
[ $rc -eq 0 ] && cmp -s build/clone2/blob.bin build/gitwork/blob.bin; check "git clone works with the backend dead (served from cache)" $?
stop_driver

echo "== readahead through the mount (informational timing; driver is a sanitizer build)"
rm -rf build/cache_d build/cache_e
start_backend; stop_backend
TIERFS_DELAY_MS=30 ./build/tierfs-backend "$LIVE" $PORT 2>>build/p2b-backend.log & sleep 1
for ra in 0 4; do
  rm -rf build/cache_r; start_driver "$PWD/build/cache_r" "$PWD/build/p2b-stats-r$ra" readahead=$ra
  s=$(python3 -c 'import time;print(time.time())')
  cat "$MNT/big.bin" > /dev/null
  python3 -c "import time;print('      readahead=$ra: cat of 6 MB took %.2fs' % (time.time()-$s))"
  stop_driver
done
stop_backend

echo "---- $pass passed, $fail failed"
[ $fail -eq 0 ]
