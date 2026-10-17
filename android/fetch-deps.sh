#!/bin/bash
# Fetches the two libraries the Android agent is built with, each checked against a hash that is pinned HERE (not read from the download):
#   sqlite    the SQLite amalgamation, from sqlite.org; pinned to the SHA3-256 sqlite.org publishes for that file (download.html)
#   openssl   the OpenSSL source tarball, from github.com/openssl/openssl; pinned to the SHA-256 published next to it
# Usage: android/fetch-deps.sh sqlite|openssl|all      Prints the directory each one was unpacked to, as SQLITE_DIR=... / OPENSSL_SRC=... lines.
# Nothing is executed from what is downloaded. To move to a newer version, change the four lines below after checking the new hashes at the sources.
set -euo pipefail
cd "$(dirname "$0")/.."
DL=build/android/dl
SQLITE_VERSION_DIR=sqlite-amalgamation-3540100
SQLITE_URL=https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip
SQLITE_SHA3_256=92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30
OPENSSL_VERSION=3.6.5
OPENSSL_URL=https://github.com/openssl/openssl/releases/download/openssl-3.6.5/openssl-3.6.5.tar.gz
OPENSSL_SHA256=a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98
mkdir -p "$DL"

fetch() {   # url, file
  [ -f "$2" ] || curl -fsSL -o "$2.part" "$1" && { [ -f "$2" ] || mv "$2.part" "$2"; }
}

want=${1:-all}
if [ "$want" = sqlite ] || [ "$want" = all ]; then
  zip=$DL/$SQLITE_VERSION_DIR.zip
  fetch "$SQLITE_URL" "$zip"
  got=$(python3 -c "import hashlib,sys; print(hashlib.sha3_256(open(sys.argv[1],'rb').read()).hexdigest())" "$zip")
  [ "$got" = "$SQLITE_SHA3_256" ] || { echo "the SQLite download does not match the pinned SHA3-256 ($got)" >&2; rm -f "$zip"; exit 1; }
  [ -f "$DL/sqlite/$SQLITE_VERSION_DIR/sqlite3.c" ] || { rm -rf "$DL/sqlite"; mkdir -p "$DL/sqlite"; unzip -q "$zip" -d "$DL/sqlite"; }
  echo "SQLITE_DIR=$PWD/$DL/sqlite/$SQLITE_VERSION_DIR"
fi
if [ "$want" = openssl ] || [ "$want" = all ]; then
  tgz=$DL/openssl-$OPENSSL_VERSION.tar.gz
  fetch "$OPENSSL_URL" "$tgz"
  got=$(shasum -a 256 "$tgz" | cut -d' ' -f1)
  [ "$got" = "$OPENSSL_SHA256" ] || { echo "the OpenSSL download does not match the pinned SHA-256 ($got)" >&2; rm -f "$tgz"; exit 1; }
  [ -f "$DL/openssl-$OPENSSL_VERSION/Configure" ] || tar -xzf "$tgz" -C "$DL"
  echo "OPENSSL_SRC=$PWD/$DL/openssl-$OPENSSL_VERSION"
fi
