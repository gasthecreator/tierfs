# tierfs agent for Android

A phone (or tablet) as a storage device for tierfs. It runs **the same device server as the Mac and Linux build** (`backend/device_server.cpp`: the store, the wire
protocol, the secure channel, the pairing files), compiled with the NDK and started from a small Java app. Nothing about the protocol is re-implemented: the code that
is tested and mutation-tested on the Mac is the code on the phone (ADR-0015).

## What it does
- **Switch on/off** from one screen; while on, a foreground service (own process, wake lock) serves encrypted chunks on the port you chose (default 9100).
- **Always paired**: switching on creates the pairing secret; the server refuses to listen on the network without one (the same rule as on the Mac). The pairing code is
  shown only on the phone's screen (`FLAG_SECURE`: no screenshots, no recent-apps preview) and is cleared when the app leaves the foreground.
- **Announces itself** on the local network as `_tierfs._tcp` (Android's `NsdManager`, the same record as `core/discovery.hpp`: `v=1`, `auth=1`, `kid=<key id>`), so
  a Mac with `devices=mdns:NAME@keyid` finds it when its address changes. If announcing fails the app still works; the Mac then needs the address.
- **Private storage**: the store lives in the app's internal storage (app-private, not backed up: `allowBackup=false`). Everything in it is encrypted by the Mac
  before it arrives; the pairing secret is a 0600 file next to it.

## Pair it with a Mac
1. On the phone: **Switch on**, then **Show pairing code**. The screen lists the phone's address(es).
2. On the Mac (same network): `tierctl pair <phone address>:9100 --store keychain`, and type the code.
3. `tierctl discover --store keychain` then shows it, and the daemon can use `devices=mdns:<name>@<key id>` or `<address>:9100@<key id>`.

## Build
Needs the Android SDK/NDK (as installed by Android Studio; NDK 25 and build-tools 36 were used), JDK, an unpacked OpenSSL 3.x source tree and the SQLite amalgamation:
```bash
SQLITE_DIR=/path/with/sqlite3.c+h OPENSSL_SRC=/path/to/openssl-3.6.5 android/build.sh     # -> build/android/out/tierfs-agent.apk (arm64-v8a, debug-signed)
```
The script cross-compiles `libcrypto.a` for android-arm64 on first use, builds `libtierfsdevice.so`, compiles the Java with `javac`/`d8`, links with `aapt2`, aligns for
16 KB pages, and signs with a throwaway debug key (`build/android/debug.keystore`). No Gradle, no network. Verify an OpenSSL tarball against OpenSSL's published SHA-256
before building it. The APK is for sideloading to your own phone (`adb install -r`); it is debug-signed and not for distribution.

## Test it (manual; needs an emulator or phone)
```bash
adb install -r build/android/out/tierfs-agent.apk
adb forward tcp:19100 tcp:9100                        # (an emulator's network is not reachable from the Mac; a phone on Wi-Fi needs no forward)
# switch on in the app, show the code, then:
tierctl pair 127.0.0.1:19100 --store dir:/tmp/ks      # type the code
make build/android_smoke
TIERFS_ANDROID_DEVICE=127.0.0.1:19100@<key id> TIERFS_ANDROID_KEYSTORE=/tmp/ks ./build/android_smoke
```
`android_smoke` offloads a file to the phone and a local device, then reads it back from the phone alone. The Mac-side behaviour of the server code is covered by `make test`.

## Limits (be honest)
- **Not a replacement for a backup, and a phone is a poor only copy**: it can be lost or wiped. tierfs keeps at least two copies before a file leaves the Mac for this reason.
- Android may stop a foreground service under extreme memory pressure or if the person force-stops the app; nothing restarts it by itself (`START_NOT_STICKY`): switch it on again.
  Battery optimisation and Doze can still delay network access on some phones; exempt the app if the Mac cannot reach it while the screen is off. No start at boot.
- Tested on an arm64 API 34 **emulator** only (switching on and off, pairing, offload, read-back from the phone alone, restart, force-stop). Not tested on hardware, on other
  Android versions, over real Wi-Fi, or with a real `NsdManager` announcement being found from a Mac (an emulator's network is NATed).
- Android 15+ phones: 16 KB page size alignment is applied; not exercised. x86_64 and 32-bit ABIs are not built.
- The store needs a filesystem that can lock files: it cannot live on the shared "emulated" storage (`flock` is not implemented there). The agent uses internal storage.
- `fsync` is the flush on Linux/Android (`F_FULLFSYNC` is macOS-only); phone storage hardware is trusted to honour it.
