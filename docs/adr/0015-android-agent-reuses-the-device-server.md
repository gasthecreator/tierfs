---
status: accepted
date: 2026-10-16
decision-makers: Gideon Sanni
---

# 0015. The Android agent is the existing device server, compiled for Android

## Context and Problem Statement
The project started from "use my phone as the device". Everything so far ran a plain server on a Mac. A phone agent needs the store, the wire protocol, the secure channel and the
pairing rules, all of which are security- and durability-critical and already tested (crash points, mutants, known-answer vectors).

## Decision Drivers
- Do not duplicate security-critical code; one implementation, one set of tests
- Android's background limits: a service that stays up only while the person has it on
- Work offline from the build: the SDK/NDK are on the machine; no Gradle downloads
- The phone must never serve an unauthenticated store on the network

## Considered Options
- Rewrite the server in Kotlin/Java
- Run the existing C++ server through the NDK, behind a thin Java app
- A Termux-style standalone binary

## Decision Outcome
Chosen option: **the existing C++ server through the NDK.** `android/native/jni_shim.cpp` includes `backend/device_server.cpp` with `main` renamed, so the phone runs the
tested code; JNI exposes only `serve`, `pairing` and `keyId`. Java (no AndroidX) provides one screen and a foreground service in its own process (the server never returns;
stopping ends the process, which the store survives by design). The app refuses to start an unpaired store. Discovery uses `NsdManager` with the TXT record of ADR-0013.

Portability fixes that came with it, all with Mac behaviour unchanged: the durable-sync call is `F_FULLFSYNC` on macOS and `fsync` elsewhere (`fsutil::strict_full_sync`), and a
store directory whose filesystem cannot lock is reported as that (not as "in use by another process"), because Android's shared storage cannot lock and the first run said the wrong thing.

### Consequences
- Good: one implementation; the same device-protocol tests cover the phone; the build needs no network; the by-product is that the device server builds for Linux (a Raspberry Pi) too.
- Bad / trade-offs: OpenSSL and SQLite have to be built into the APK (13 MB); the debug-signed APK is for sideloading only; Android can still stop the service; a native crash takes
  the server process down (the app's UI process is separate); only arm64-v8a is built.

### Later additions
The app saves what the person chose (`State`: on, start at boot, shared storage, port) in a file read by both processes, so the service can be restarted by the system (`START_STICKY`) and by a boot receiver exactly as it was and
stays off if it was switched off. Shared storage cannot lock files, so `DeviceStore::open` takes a separate lock directory (`--lock-dir`) kept in internal storage; the rest of the store (SQLite in WAL mode, durable file writes) works on it.
SQLite and OpenSSL are fetched by `android/fetch-deps.sh` against hashes pinned in the script, and CI builds arm64, x86_64 and 32-bit ARM.

### Confirmation
`make test` (the shared code); a manual run on an arm64 API 34 emulator with `tests/android_smoke.cpp` (offload to the phone and a local device, read back from the phone alone), plus
switch off/on, force-stop and restart with the store's state intact. Not run on hardware.
