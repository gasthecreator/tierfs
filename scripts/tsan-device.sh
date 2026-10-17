#!/bin/bash
# ThreadSanitizer run of the device store, server and client (all three instrumented).
cd "$(dirname "$0")/.." || exit 1
OS=${OPENSSL_DIR:-/opt/homebrew/opt/openssl@3}
D=build/tsand; rm -rf $D; mkdir -p $D
FLAGS=(-std=c++17 -g -O1 -fsanitize=thread "-I$OS/include" -Icore -Itests)
LIBS=("$OS/lib/libcrypto.a" -lsqlite3)
build() { out=$1; shift; c++ "${FLAGS[@]}" "$@" "${LIBS[@]}" -o $D/$out 2>$D/$out.log || { echo "BUILD FAILED: $out"; tail -3 $D/$out.log; exit 1; }; }
build store_test tests/devicestore_test.cpp core/devicestore.cpp core/crypto.cpp
build helper tests/device_helper.cpp core/devicestore.cpp core/crypto.cpp
build net_test tests/devicenet_test.cpp core/deviceclient.cpp core/securechannel.cpp core/devicestore.cpp core/crypto.cpp
build server backend/device_server.cpp core/securechannel.cpp core/devicestore.cpp core/crypto.cpp
for b in store_test helper net_test server; do [ -x $D/$b ] || { echo "missing $b"; exit 1; }; done
echo "built 4 instrumented binaries"
pkill -f tierfs-device
TIERFS_DEVICE_HELPER=./$D/helper perl -e 'alarm 200; exec @ARGV' ./$D/store_test > $D/s.out 2> $D/s.err; rc=$?
echo "store test: exit=$rc, checks passed=$(grep -c '^PASS' $D/s.out), failed=$(grep -c '^FAIL' $D/s.out), TSan warnings=$(grep -c 'WARNING: ThreadSanitizer' $D/s.err)"
TIERFS_SERVER_LOG=$D/server.err TIERFS_DEVICE_SERVER=./$D/server perl -e 'alarm 280; exec @ARGV' ./$D/net_test > $D/n.out 2> $D/n.err; rc2=$?
echo "net test:   exit=$rc2, checks passed=$(grep -c '^PASS' $D/n.out), failed=$(grep -c '^FAIL' $D/n.out), TSan warnings in client=$(grep -c 'WARNING: ThreadSanitizer' $D/n.err), in server=$(grep -c 'WARNING: ThreadSanitizer' $D/server.err)"
pkill -f tsand/server
[ $rc -eq 0 ] && [ $rc2 -eq 0 ] && ! grep -q 'WARNING: ThreadSanitizer' $D/s.err $D/n.err $D/server.err
