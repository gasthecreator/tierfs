#!/bin/bash
# For each candidate errno, mount with a DEAD backend and show what apps see.
cd "$(dirname "$0")/.."; MNT=$PWD/scratch-mnt
for spec in "0:default(EHOSTUNREACH/ETIMEDOUT)" 5:EIO 35:EAGAIN 70:ESTALE 57:ENOTCONN 50:ENETDOWN 64:EHOSTDOWN 16:EBUSY 6:ENXIO 19:ENODEV 60:ETIMEDOUT; do
  n=${spec%%:*}; name=${spec#*:}
  ./build/tierfs-backend testdata/sample 9099 2>/dev/null & BP=$!; sleep 1
  ./build/tierfs -f -o host=127.0.0.1,port=9099,timeout=800,neterr=$n "$MNT" >/dev/null 2>&1 &
  sleep 3
  ls "$MNT" >/dev/null 2>&1   # warm: metadata fetched while backend alive
  kill $BP; wait $BP 2>/dev/null; sleep 1
  r1=$(perl -e 'alarm 10; exec @ARGV' cat "$MNT/hello.txt" 2>&1 | sed 's#.*: ##')
  r2=$(perl -e 'alarm 10; exec @ARGV' ls "$MNT/" 2>&1 | sed 's#.*: ##')
  r3=$(perl -e 'alarm 10; exec @ARGV' stat "$MNT/hello.txt" 2>&1 | sed 's#.*: ##' | head -c 40)
  printf '%-34s cat: %-28s ls: %-24s stat: %s\n' "$name" "$r1" "$r2" "$r3"
  umount "$MNT" 2>/dev/null; pkill -f "build/tierfs -f"; sleep 1
done
