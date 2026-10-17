# tierfs agent for Android

A phone (or tablet) as a storage device for tierfs. It runs **the same device server as the Mac and Linux build** (`backend/device_server.cpp`: the store, the wire
protocol, the secure channel, the pairing files), compiled with the NDK and started from a small Java app. Nothing about the protocol is re-implemented: the code that
is tested and mutation-tested on the Mac is the code on the phone (ADR-0015).

## What it does
- **Switch on/off** from one screen; while on, a foreground service (own process, wake lock) serves encrypted chunks on the port you chose (default 9100). The choice is saved: if Android stops
  the service it is started again as it was (it stays off if you switched it off), and **Switch on again when the phone starts** brings it back after a restart or an update of the app.
- **Always paired**: switching on creates the pairing secret; the server refuses to listen on the network without one (the same rule as on the Mac). The pairing code is
  shown only on the phone's screen (`FLAG_SECURE`: no screenshots, no recent-apps preview) and is cleared when the app leaves the foreground.
- **One pairing per Mac** (ADR-0016): *Add another Mac* makes a code for it (with or without the right to delete), *Paired Macs* lists them and revokes one: that Mac is refused at once, the others carry on.
- **Announces itself** on the local network as `_tierfs._tcp` (Android's `NsdManager`, the same record as `core/discovery.hpp`: `v=1`, `auth=1`, `kid=<key id>`, one record per pairing), so
  a Mac with `devices=mdns:NAME@keyid` finds it when its address changes. If announcing fails the app still works; the Mac then needs the address.
- **Where the store lives**: the app's internal storage by default (app-private, not backed up: `allowBackup=false`); optionally the app's folder on shared storage / a memory card
  (*Keep the store on shared storage*). Shared storage cannot lock files, so the lock file stays in internal storage (`--lock-dir`). Changing the place starts a new, empty store (the app says so first).
  Everything in the store is encrypted by the Mac before it arrives; the pairing secrets are 0600 files next to it.
- **Background limits**: *Allow it to run in the background* asks Android to exempt the app from battery optimisation (you decide in Android's own dialog).
- **Deleted data waits in a trash** on the phone for 7 days (ADR-0017), so a phone's free space after a garbage collection comes back a week later.

## Pair it with a Mac
1. On the phone: **Switch on**, then **Show pairing code**. The screen lists the phone's address(es).
2. On the Mac (same network): `tierctl pair <phone address>:9100 --store keychain`, and type the code.
3. `tierctl discover --store keychain` then shows it, and the daemon can use `devices=mdns:<name>@<key id>` or `<address>:9100@<key id>`.

## Build
Needs the Android SDK/NDK (as installed by Android Studio), a JDK, `curl`, `python3`. SQLite and OpenSSL are fetched by `android/fetch-deps.sh` with hashes pinned in the script (SQLite against
the SHA3-256 that sqlite.org publishes for the file; OpenSSL against its published SHA-256):
```bash
android/build.sh                                              # -> build/android/out/tierfs-agent.apk (arm64-v8a, signed with a throwaway debug key)
ABIS="arm64-v8a x86_64 armeabi-v7a" android/build.sh          # more architectures (each builds its own libcrypto: the slow part)
SQLITE_DIR=... OPENSSL_SRC=... android/build.sh               # your own copies instead
```
The script builds `libtierfsdevice.so` for each ABI, compiles the Java with `javac`/`d8`, links with `aapt2`, aligns for 16 KB pages and signs. No Gradle. The debug-signed APK is for sideloading to your
own phone (`adb install -r`).

**Signing with your own key** (an APK signed with the debug key cannot be updated by one signed with another key, and anyone can make a debug-signed copy):
```bash
keytool -genkeypair -keystore ~/tierfs-release.jks -alias tierfs -keyalg RSA -keysize 3072 -validity 9125      # once; keep the file and its password safe, they cannot be recovered
RELEASE_KEYSTORE=~/tierfs-release.jks RELEASE_KEY_ALIAS=tierfs android/build.sh                                # asks for the password on stdin
```
The key is never read from or written to the repository, and the password is only ever passed on standard input (or read from a file you name with `RELEASE_STOREPASS_FILE`).
CI builds all three ABIs (debug-signed) to catch breakage; it does not publish anything.

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
- Android can still stop the service under pressure, and some makers' battery managers are stricter than Android's own: after a stop it is started again (`START_STICKY`) and after a restart if you asked for that,
  but a force-stop from Settings keeps it off until you open the app. Battery optimisation and Doze can delay network access on some phones; allow the app to run in the background.
- Tried on an arm64 API 34 **emulator** only: switch on and off, pairing, several Macs and revoking one, offload to the phone and read back from it alone, a restart of the service after a crash, start at boot after
  a reboot, the store on shared storage, the battery dialog. Not tried on hardware, on other Android versions (API 26 is the minimum; API 30 could not be tried here for lack of disk space), over real Wi-Fi, with a real
  `NsdManager` announcement being found from a Mac (an emulator's network is NATed), or on a 16 KB-page device (the libraries are aligned for it).
- x86_64 and 32-bit ARM libraries are built in CI but have never been run.
- Shared storage is shared with other apps and can be removed or cleaned by the system; a memory card that is taken out takes the store with it.
- `fsync` is the flush on Linux/Android (`F_FULLFSYNC` is macOS-only); phone storage hardware is trusted to honour it.
