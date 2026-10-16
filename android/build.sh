#!/bin/bash
# Builds the Android agent (an APK) without Gradle: NDK clang for the native device server, javac + d8 + aapt2 for the app, apksigner with a throwaway debug key.
#
#   SQLITE_DIR=/path/with/sqlite3.c+h  OPENSSL_SRC=/path/to/openssl-3.x  android/build.sh
#
# SQLITE_DIR: the SQLite amalgamation (sqlite.org/download.html, "sqlite-amalgamation"). OPENSSL_SRC: an unpacked OpenSSL 3.x source tree, built here for
# android-arm64 (static libcrypto only). Output: build/android/out/tierfs-agent.apk. Nothing here touches the Mac build.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
SDK=${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}
NDK=${ANDROID_NDK_ROOT:-$SDK/ndk/25.1.8937393}
BT=${BUILD_TOOLS:-$SDK/build-tools/36.0.0}   # (the 34.0.0 d8 crashes on JDK 25)
PLATFORM=${PLATFORM_JAR:-$SDK/platforms/android-34/android.jar}
API=26
OUT=$ROOT/build/android/out
OBJ=$ROOT/build/android/obj
mkdir -p "$OUT" "$OBJ"
: "${SQLITE_DIR:?set SQLITE_DIR to the directory holding sqlite3.c and sqlite3.h}"
: "${OPENSSL_SRC:?set OPENSSL_SRC to an unpacked OpenSSL 3.x source tree}"
TC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin
CXX=$TC/aarch64-linux-android$API-clang++
CC=$TC/aarch64-linux-android$API-clang
export PATH=$TC:$PATH

SQ=$ROOT/build/android/sqlite   # (copied so that paths with spaces in SQLITE_DIR cannot split the compiler flags)
mkdir -p "$SQ" && cp "$SQLITE_DIR/sqlite3.c" "$SQLITE_DIR/sqlite3.h" "$SQ/"
echo "== sqlite: $(grep -m1 'define SQLITE_VERSION ' "$SQ/sqlite3.c") sha256 $(shasum -a 256 "$SQ/sqlite3.c" | cut -c1-16)..."
if [ ! -f "$OPENSSL_SRC/libcrypto.a" ]; then
  echo "== openssl: building libcrypto for android-arm64"
  (cd "$OPENSSL_SRC" && ANDROID_NDK_ROOT=$NDK ./Configure android-arm64 -D__ANDROID_API__=$API no-shared no-tests no-apps no-docs no-ssl no-dtls no-comp no-engine no-legacy no-module >/dev/null \
    && make build_generated >/dev/null && make -j8 libcrypto.a >/dev/null)
fi

echo "== native: libtierfsdevice.so"
[ -f "$OBJ/sqlite3.o" ] || $CC -O2 -fPIC -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DQS=0 -c "$SQ/sqlite3.c" -o "$OBJ/sqlite3.o"
CXXF="-std=c++17 -O2 -fPIC -Wall -Wextra -I$OPENSSL_SRC/include -I$SQ -I$ROOT/core"
for f in core/devicestore.cpp core/crypto.cpp core/securechannel.cpp core/discovery.cpp; do $CXX $CXXF -c "$f" -o "$OBJ/$(basename "$f").o"; done
$CXX $CXXF -Wno-unused-function -c android/native/jni_shim.cpp -o "$OBJ/jni_shim.o"
mkdir -p "$OUT/lib/arm64-v8a"
$CXX -shared -o "$OUT/lib/arm64-v8a/libtierfsdevice.so" "$OBJ"/jni_shim.o "$OBJ"/devicestore.cpp.o "$OBJ"/crypto.cpp.o "$OBJ"/securechannel.cpp.o "$OBJ"/discovery.cpp.o \
  "$OBJ"/sqlite3.o "$OPENSSL_SRC/libcrypto.a" -llog -static-libstdc++ -Wl,-z,max-page-size=16384 -Wl,--build-id=none

echo "== app: classes.dex"
rm -rf "$OUT/classes" && mkdir -p "$OUT/classes"
javac --release 11 -Xlint:all -classpath "$PLATFORM" -d "$OUT/classes" android/java/dev/tierfs/agent/*.java
"$BT/d8" --min-api $API --lib "$PLATFORM" --output "$OUT" $(find "$OUT/classes" -name '*.class')

echo "== apk"
rm -f "$OUT/base.apk" "$OUT/unaligned.apk" "$OUT/tierfs-agent.apk"
"$BT/aapt2" link -o "$OUT/base.apk" -I "$PLATFORM" --manifest android/AndroidManifest.xml --min-sdk-version $API --target-sdk-version 34
cp "$OUT/base.apk" "$OUT/unaligned.apk"
(cd "$OUT" && zip -q -u unaligned.apk classes.dex && zip -q -u -0 unaligned.apk lib/arm64-v8a/libtierfsdevice.so)
"$BT/zipalign" -f -p 16384 "$OUT/unaligned.apk" "$OUT/aligned.apk"
KS=$ROOT/build/android/debug.keystore
[ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -storepass android -keypass android -alias debug -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=tierfs debug" >/dev/null 2>&1
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android --out "$OUT/tierfs-agent.apk" "$OUT/aligned.apk"
"$BT/apksigner" verify "$OUT/tierfs-agent.apk"
echo "built $OUT/tierfs-agent.apk ($(du -h "$OUT/tierfs-agent.apk" | cut -f1))"
