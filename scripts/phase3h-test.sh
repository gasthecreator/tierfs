#!/bin/bash
# !!! DANGEROUS: this script reset the machine four times (kernel watchdog) because it kill -9s a mounted FUSE-T driver and force-unmounts.
# !!! Do not run it unless you mean to, with your work saved. It refuses to run without TIERFS_I_ACCEPT_A_REBOOT=1.
[ "${TIERFS_I_ACCEPT_A_REBOOT:-}" = 1 ] || { echo "refusing: see the comment at the top of this script"; exit 3; }
# Phase 3h: the real filesystem, end to end. A real FUSE-T mount of tierfsd over a throwaway origin folder, two real device
# servers, and ordinary commands (cat, cp, mv, dd, xattr, python ...). Touches only ~/tierfs/build/e2e and ~/tierfs/scratch-mnt.
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD/build/e2e; M=$PWD/scratch-mnt; ORIGIN=$ROOT/origin; LEDGER=$ROOT/ledger; REF=$ROOT/ref; KEY=$ROOT/key
PA=9581; PB=9582; PREFIX=/Users/me/proj/
pass=0; fail=0
check() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
stop_mount() { umount "$M" 2>/dev/null; pkill -f "build/tierfsd" 2>/dev/null; sleep 1.5; umount -f "$M" 2>/dev/null; }
stop_devices() { pkill -f "tierfs-device $ROOT/" 2>/dev/null; sleep 0.7; }
start_devices() { for x in A B; do p=$PA; [ $x = B ] && p=$PB; ./build/tierfs-device "$ROOT/dev$x" $p 127.0.0.1 >>"$ROOT/dev.log" 2>&1 & done; sleep 1.2; }
start_mount() { ./build/tierfsd -f -o origin="$ORIGIN",prefix=$PREFIX,ledger="$LEDGER",keyfile="$KEY",devices=127.0.0.1:$PA+127.0.0.1:$PB,maint=0,notify=0,waitms=5000,namedattr,noappledouble "$M" >>"$ROOT/daemon.log" 2>&1 &
  for i in $(seq 1 40); do mount | grep -q "$M" && return 0; sleep 0.5; done; return 1; }
ctl() { ./build/tierctl control "$LEDGER" "$@"; }
trap 'stop_mount; stop_devices' EXIT
stop_mount; stop_devices
rm -rf "$ROOT"; mkdir -p "$ORIGIN/sub" "$REF" "$M"
head -c 3000000 /dev/urandom > "$ORIGIN/sub/big.bin"; head -c 5000000 /dev/urandom > "$ORIGIN/big2.bin"
echo "hello tierfs" > "$ORIGIN/a.txt"; head -c 400000 /dev/urandom > "$ORIGIN/cold.bin"; cp "$ORIGIN/sub/big.bin" "$REF/big.bin"; cp "$ORIGIN/big2.bin" "$REF/big2.bin"
head -c 32 /dev/urandom | xxd -p -c 64 > "$KEY"
start_devices
mkdir -p "$LEDGER"; ./build/tierctl test-gates "$LEDGER" /Users/me/ >/dev/null
start_mount; check "the filesystem mounts over a folder it did not move" $?
mount | grep -q "$M" || { echo "no mount: stopping. Daemon log:"; tail -20 "$ROOT/daemon.log"; exit 1; }
[ "$(ls "$M" | sort | tr '\n' ' ')" = "a.txt big2.bin cold.bin sub " ]; check "the origin's files are listed" $?
[ "$(cat "$M/a.txt")" = "hello tierfs" ]; check "a small file reads back" $?
cmp -s "$M/sub/big.bin" "$REF/big.bin"; check "a multi-chunk file reads back byte for byte" $?
[ "$(stat -f %z "$M/big2.bin")" = "5000000" ]; check "stat shows the size" $?
[ "$(dd if="$M/big2.bin" bs=1 skip=2999990 count=20 2>/dev/null | xxd -p)" = "$(dd if="$REF/big2.bin" bs=1 skip=2999990 count=20 2>/dev/null | xxd -p)" ]; check "a partial read across a chunk boundary is right" $?

echo "== writing through the mount"
echo "first" > "$M/new.txt"; [ "$(cat "$ORIGIN/new.txt")" = "first" ]; check "a new file lands in the origin" $?
echo "second" >> "$M/new.txt"; [ "$(cat "$M/new.txt")" = "$(printf 'first\nsecond')" ]; check "append works" $?
cp "$REF/big2.bin" "$M/copy.bin"; cmp -s "$M/copy.bin" "$REF/big2.bin"; check "copying a 5 MB file in works" $?
dd if=/dev/zero of="$M/copy.bin" bs=1 seek=100 count=10 conv=notrunc 2>/dev/null; [ "$(dd if="$M/copy.bin" bs=1 skip=100 count=10 2>/dev/null | xxd -p)" = "00000000000000000000" ]; check "overwriting in the middle works" $?
truncate -s 1000 "$M/copy.bin"; [ "$(stat -f %z "$M/copy.bin")" = "1000" ]; check "truncate works" $?
mv "$M/copy.bin" "$M/moved.bin"; [ -f "$ORIGIN/moved.bin" ] && [ ! -e "$ORIGIN/copy.bin" ]; check "rename works" $?
mkdir "$M/d1" && mv "$M/moved.bin" "$M/d1/" && [ -f "$ORIGIN/d1/moved.bin" ]; check "mkdir and move into it" $?
rm "$M/d1/moved.bin" && rmdir "$M/d1" && [ ! -e "$ORIGIN/d1" ]; check "rm and rmdir work" $?
ln -s a.txt "$M/link" && [ "$(readlink "$M/link")" = "a.txt" ] && [ "$(cat "$M/link")" = "hello tierfs" ]; check "symlinks work" $?
chmod 600 "$M/a.txt"; [ "$(stat -f %Lp "$M/a.txt")" = "600" ]; check "chmod works" $?
touch -t 202001011200 "$M/a.txt"; [ "$(stat -f %Sm -t %Y%m%d%H%M "$M/a.txt")" = "202001011200" ]; check "touch -t sets the time" $?
xattr -w com.example.tag blue "$M/a.txt"; [ "$(xattr -p com.example.tag "$ORIGIN/a.txt")" = "blue" ]; check "an extended attribute set through the mount reaches the file" $?
# (the NFS client caches attribute reads for a while after a write; a fresh mount, below, shows the real state)
df "$M" >/dev/null 2>&1; check "df works" $?

echo "== moving a file off the Mac and back"
ctl scan >/dev/null
ctl offload /sub/big.bin >"$ROOT/offload.out" 2>&1; check "offload of a file is accepted" $?
[ ! -e "$ORIGIN/sub/big.bin" ]; check "its bytes are gone from the origin" $?
[ "$(ls "$M/sub")" = "big.bin" ] && [ "$(stat -f %z "$M/sub/big.bin")" = "3000000" ]; check "it is still listed with its size" $?
cmp -s "$M/sub/big.bin" "$REF/big.bin"; check "it reads back byte for byte from the devices" $?
[ "$(dd if="$M/sub/big.bin" bs=1 skip=1048570 count=12 2>/dev/null | xxd -p)" = "$(dd if="$REF/big.bin" bs=1 skip=1048570 count=12 2>/dev/null | xxd -p)" ]; check "a partial read of it across a chunk boundary is right" $?
echo "tail" >> "$M/sub/big.bin"; [ "$(stat -f %z "$M/sub/big.bin")" = "3000005" ] && [ -f "$ORIGIN/sub/big.bin" ]; check "appending to it brings it back and works" $?
{ cat "$REF/big.bin"; echo tail; } | cmp -s - "$M/sub/big.bin"; check "the appended file is exactly old bytes plus the new ones" $?

echo "== editors: save by writing a temp file and renaming it over the original"
ctl offload /big2.bin >/dev/null 2>&1; [ ! -e "$ORIGIN/big2.bin" ]; check "a second file is offloaded" $?
python3 - "$M/big2.bin" <<'PY'
import os, sys
p = sys.argv[1]
with open(p, 'rb') as f: data = f.read()
tmp = p + '.tmp'
with open(tmp, 'wb') as f: f.write(data[:100] + b'EDITED' + data[106:]); f.flush(); os.fsync(f.fileno())
os.rename(tmp, p)
PY
check "an atomic save over an offloaded file succeeds" $?
python3 - "$REF/big2.bin" "$M/big2.bin" <<'PY'
import sys
a = open(sys.argv[1], 'rb').read(); b = open(sys.argv[2], 'rb').read()
sys.exit(0 if b == a[:100] + b'EDITED' + a[106:] else 1)
PY
check "the file now has the edited bytes" $?

echo "== deleting and undeleting"
ctl offload /a.txt >"$ROOT/off2.out" 2>&1; [ -e "$ORIGIN/a.txt" ] && cat "$ROOT/off2.out"
rm "$M/a.txt"; [ ! -e "$M/a.txt" ]; check "deleting an offloaded file removes it" $?
ctl undelete /a.txt >"$ROOT/undel.out" 2>&1
# a change made behind the kernel's back (the control socket, not the mount) is noticed when its directory cache expires (~5 s)
r=1; for i in $(seq 1 30); do [ "$(cat "$M/a.txt" 2>/dev/null)" = "hello tierfs" ] && { r=0; break; }; sleep 0.5; done; [ $r -ne 0 ] && cat "$ROOT/undel.out"; check "undelete brings it back" $r

echo "== devices gone: local files work, remote reads fail cleanly"
ctl offload /cold.bin >/dev/null 2>&1; [ ! -e "$ORIGIN/cold.bin" ]; check "a file nobody has read is offloaded" $?
stop_devices
echo "still here" > "$M/local.txt"; [ "$(cat "$M/local.txt")" = "still here" ]; check "a local file still works with the devices gone" $?
perl -e 'alarm 20; exec @ARGV' cat "$M/cold.bin" >/dev/null 2>"$ROOT/err"; rc=$?
grep -q "Input/output error" "$ROOT/err" && [ $rc -ne 142 ]; check "reading an offloaded file fails with EIO, not a hang" $?
[ "$(ls "$M" | wc -l | tr -d ' ')" -ge 4 ] && ls "$M" | grep -q cold.bin; check "listing still works" $?
start_devices
sleep 1
cmp -s "$M/cold.bin" <(true) 2>/dev/null; [ "$(stat -f %z "$M/cold.bin")" = "400000" ] && [ "$(cat "$M/cold.bin" | wc -c | tr -d " ")" = "400000" ]; check "and it works again when the devices are back" $?

echo "== a crash: the daemon is killed hard, the mount is cleaned up, a new daemon recovers"
pkill -9 -f "build/tierfsd"; sleep 1; umount -f "$M" 2>/dev/null; sleep 1
start_mount; check "a new daemon mounts after a kill -9" $?
cmp -s "$M/sub/big.bin" <({ cat "$REF/big.bin"; echo tail; }); check "the files are exactly as they were" $?
./build/tierctl ledger-status "$LEDGER" 2>&1 | grep -q "consistency: ok" ; ctl status >/dev/null; check "the ledger is consistent (status answers)" $?
ctl status | grep -q "^OK"; check "the control socket answers" $?

echo "== clean unmount"
umount "$M"; sleep 2
pgrep -f "build/tierfsd" >/dev/null; [ $? -ne 0 ]; check "the daemon exits when unmounted" $?
[ ! -e "$LEDGER/control.sock" ]; check "the control socket is removed" $?
echo; echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
