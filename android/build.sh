#!/bin/bash
# Builds the Android agent (an APK) without Gradle: NDK clang for the native device server, javac + d8 + aapt2 for the app, apksigner for the signature.
#
#   android/build.sh                          fetches SQLite and OpenSSL (android/fetch-deps.sh, hashes pinned), builds arm64-v8a, signs with a throwaway debug key
#   ABIS="arm64-v8a x86_64 armeabi-v7a" android/build.sh      more architectures (each needs its own OpenSSL build; that is the slow part)
#   SQLITE_DIR=... OPENSSL_SRC=... android/build.sh           use your own copies instead of fetching them
#   RELEASE_KEYSTORE=/path/key.jks RELEASE_KEY_ALIAS=name [RELEASE_STOREPASS_FILE=...] android/build.sh      sign with your own key (see android/README.md)
#
# Output: build/android/out/tierfs-agent.apk. Nothing here touches the Mac build.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
SDK=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}
NDK=${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:-$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)}}
BT=${BUILD_TOOLS:-$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)}   # (the 34.0.0 d8 crashes on JDK 25: the newest is used)
PLATFORM=${PLATFORM_JAR:-$(ls -d "$SDK"/platforms/android-3[4-9]*/android.jar 2>/dev/null | sort -V | head -1)}
API=26
ABIS=${ABIS:-arm64-v8a}
OUT=$ROOT/build/android/out
OBJ=$ROOT/build/android/obj
[ -d "$NDK" ] && [ -d "$BT" ] && [ -f "$PLATFORM" ] || { echo "need the Android SDK (ndk, build-tools, a platform): set ANDROID_SDK_ROOT" >&2; exit 2; }
mkdir -p "$OUT" "$OBJ"
case "$(uname -s)" in Darwin) HOST=darwin-x86_64;; Linux) HOST=linux-x86_64;; *) echo "unsupported build host" >&2; exit 2;; esac
TC=$NDK/toolchains/llvm/prebuilt/$HOST/bin
export PATH=$TC:$PATH

if [ -z "${SQLITE_DIR:-}" ]; then eval "$("$ROOT/android/fetch-deps.sh" sqlite)"; fi
SQ=$ROOT/build/android/sqlite   # (copied so that paths with spaces in SQLITE_DIR cannot split the compiler flags)
mkdir -p "$SQ" && cp "$SQLITE_DIR/sqlite3.c" "$SQLITE_DIR/sqlite3.h" "$SQ/"
echo "== sqlite: $(grep -m1 'define SQLITE_VERSION ' "$SQ/sqlite3.c") sha256 $(shasum -a 256 "$SQ/sqlite3.c" | cut -c1-16)..."

# Per ABI: clang target, OpenSSL Configure target, library directory
abi_triple() { case $1 in arm64-v8a) echo aarch64-linux-android;; x86_64) echo x86_64-linux-android;; armeabi-v7a) echo armv7a-linux-androideabi;; *) echo "unknown ABI $1" >&2; exit 2;; esac; }
abi_ossl() { case $1 in arm64-v8a) echo android-arm64;; x86_64) echo android-x86_64;; armeabi-v7a) echo android-arm;; esac; }

build_openssl() {   # ABI -> prints the directory holding libcrypto.a and include/
  local abi=$1 dir=$ROOT/build/android/openssl-$1
  if [ "$abi" = arm64-v8a ]; then   # (a tree built in place by an earlier version of this script)
    for t in "${OPENSSL_SRC:-}" "$ROOT/build/android/openssl-3.6.5"; do [ -n "$t" ] && [ -f "$t/libcrypto.a" ] && { echo "$t"; return; }; done
  fi
  if [ ! -f "$dir/libcrypto.a" ]; then
    if [ -z "${OPENSSL_SRC:-}" ]; then eval "$("$ROOT/android/fetch-deps.sh" openssl)"; fi
    mkdir -p "$dir"
    echo "== openssl: building libcrypto for $abi" >&2
    (cd "$dir" && ANDROID_NDK_ROOT=$NDK "$OPENSSL_SRC/Configure" "$(abi_ossl "$abi")" -D__ANDROID_API__=$API no-shared no-tests no-apps no-docs no-ssl no-dtls no-comp no-engine no-legacy no-module >/dev/null \
      && make build_generated >/dev/null && make -j8 libcrypto.a >/dev/null)
  fi
  echo "$dir"
}

rm -rf "$OUT/lib"
for ABI in $ABIS; do
  TRIPLE=$(abi_triple "$ABI")
  CXX=$TC/$TRIPLE$API-clang++
  CC=$TC/$TRIPLE$API-clang
  OSSL=$(build_openssl "$ABI")
  echo "== native ($ABI): libtierfsdevice.so"
  O=$OBJ/$ABI
  mkdir -p "$O" "$OUT/lib/$ABI"
  [ -f "$O/sqlite3.o" ] && [ "$O/sqlite3.o" -nt "$SQ/sqlite3.c" ] || $CC -O2 -fPIC -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DQS=0 -c "$SQ/sqlite3.c" -o "$O/sqlite3.o"
  OSSL_INC="-I$OSSL/include"
  # (a build made outside the source tree has the generated headers in $OSSL/include and the rest in the source tree)
  if [ -n "${OPENSSL_SRC:-}" ] && [ "$OSSL" != "$OPENSSL_SRC" ]; then OSSL_INC="$OSSL_INC -I$OPENSSL_SRC/include"; fi
  CXXF="-std=c++17 -O2 -fPIC -Wall -Wextra $OSSL_INC -I$SQ -I$ROOT/core"
  for f in core/devicestore.cpp core/crypto.cpp core/securechannel.cpp core/discovery.cpp core/pairings.cpp; do $CXX $CXXF -c "$f" -o "$O/$(basename "$f").o"; done
  $CXX $CXXF -Wno-unused-function -c android/native/jni_shim.cpp -o "$O/jni_shim.o"
  $CXX -shared -o "$OUT/lib/$ABI/libtierfsdevice.so" "$O"/jni_shim.o "$O"/devicestore.cpp.o "$O"/crypto.cpp.o "$O"/securechannel.cpp.o "$O"/discovery.cpp.o \
    "$O"/pairings.cpp.o "$O"/sqlite3.o "$OSSL/libcrypto.a" -llog -static-libstdc++ -Wl,-z,max-page-size=16384 -Wl,--build-id=none
done

echo "== app: classes.dex"
rm -rf "$OUT/classes" && mkdir -p "$OUT/classes"
javac --release 11 -Xlint:all -classpath "$PLATFORM" -d "$OUT/classes" android/java/dev/tierfs/agent/*.java
"$BT/d8" --min-api $API --lib "$PLATFORM" --output "$OUT" $(find "$OUT/classes" -name '*.class')

echo "== apk"
rm -f "$OUT/base.apk" "$OUT/unaligned.apk" "$OUT/aligned.apk" "$OUT/tierfs-agent.apk"
"$BT/aapt2" link -o "$OUT/base.apk" -I "$PLATFORM" --manifest android/AndroidManifest.xml --min-sdk-version $API --target-sdk-version 34
cp "$OUT/base.apk" "$OUT/unaligned.apk"
(cd "$OUT" && zip -q -u unaligned.apk classes.dex && for ABI in $ABIS; do zip -q -u -0 unaligned.apk "lib/$ABI/libtierfsdevice.so"; done)
"$BT/zipalign" -f -p 16384 "$OUT/unaligned.apk" "$OUT/aligned.apk"
if [ -n "${RELEASE_KEYSTORE:-}" ]; then
  : "${RELEASE_KEY_ALIAS:?set RELEASE_KEY_ALIAS to the alias of the key in the keystore}"
  PASSARG=(--ks-pass "${RELEASE_STOREPASS_FILE:+file:$RELEASE_STOREPASS_FILE}")
  [ -n "${RELEASE_STOREPASS_FILE:-}" ] || PASSARG=(--ks-pass stdin)   # (asked for, never put on a command line or in a file here)
  "$BT/apksigner" sign --ks "$RELEASE_KEYSTORE" --ks-key-alias "$RELEASE_KEY_ALIAS" "${PASSARG[@]}" --out "$OUT/tierfs-agent.apk" "$OUT/aligned.apk"
  echo "signed with your key ($RELEASE_KEY_ALIAS)"
else
  KS=$ROOT/build/android/debug.keystore
  [ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -storepass android -keypass android -alias debug -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=tierfs debug" >/dev/null 2>&1
  "$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android --out "$OUT/tierfs-agent.apk" "$OUT/aligned.apk"
  echo "signed with a throwaway debug key: for sideloading to your own phone only"
fi
"$BT/apksigner" verify --print-certs "$OUT/tierfs-agent.apk" | head -3
echo "built $OUT/tierfs-agent.apk ($(du -h "$OUT/tierfs-agent.apk" | cut -f1)); ABIs: $ABIS"
