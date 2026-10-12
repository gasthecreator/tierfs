---
status: accepted (implemented and wired in)
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0009. Authenticate and encrypt the device protocol with a pairing secret and a Noise-style channel

## Context and Problem Statement
The device protocol (v3) has no authentication and no transport encryption, so a device may only listen on loopback. A real device (another Mac, a NAS,
a phone) is reached over a network. The stored data is already encrypted and authenticated end to end, but anyone who can reach the port can read metadata,
fill the disk, delete nothing (append-only) but upload junk, and impersonate the device to the Mac.

## Decision Drivers
- A phone and a small server must be able to run it: no certificate authority, no OS-specific TLS stack
- Pairing must be a one-time act a person can do with a code on a screen
- Compromise of the pairing secret later must not expose recorded traffic
- The cryptography must be small enough to verify independently, and must reuse primitives already in the tree (OpenSSL libcrypto)

## Considered Options
- TLS 1.3 with pinned self-signed certificates (mutual)
- A pre-shared key used directly to MAC and encrypt each frame
- A pairing secret plus an ephemeral X25519 exchange (Noise "NNpsk"-style), then AEAD frames with counters

## Decision Outcome
Chosen option: **pairing secret plus ephemeral X25519, AES-256-GCM frames with strictly increasing counters** (protocol version 4, `core/securechannel.*`).
The secret is 32 random bytes, shown once as a 16-group code (the same checksummed format as the recovery phrase) and stored on the Mac in the key store;
a public 8-byte key id (an HMAC of the secret) says which secret a connection claims. Both sides prove knowledge of it; keys are fresh per connection.
The frame's type and id are inside the seal. A server holding a pairing secret refuses plaintext clients; a server without one keeps the old loopback-only behaviour.

### Consequences
- Good: mutual authentication, confidentiality, integrity, replay/reorder/drop detection, forward secrecy for recorded traffic; about 300 lines of code; no certificates; the whole thing is covered by known-answer tests from an independent implementation.
- Bad / trade-offs: no certificate-style revocation (to revoke, re-pair with a new secret); connection existence, timing and sizes are visible; a leaked secret lets an attacker impersonate the device or the Mac to the other from then on; rate limiting of failed handshakes is basic.

### Confirmation
`tests/securechannel_test.cpp` (known answers computed by `scripts/gen_channel_kat.py`, which implements X25519 from RFC 7748 and checks itself against the RFC's vectors; bit-flip, replay, reorder, drop, reflection, truncation, wrong-secret, low-order-point and socket-abuse tests) and mutation testing of `core/securechannel.cpp` (80 mutants).

## More Information
Specification: proto/PROTOCOL.md (version 4). Not specified: secret rotation beyond replacing the secret, per-device authorization of operations.

### Pairing as built
- The device owns the secret: `tierfs-device <store> --show-pairing-code` creates `<store>/pairing.key` on first use (random, mode 0600) and prints it in the same
  word-group form as the recovery phrase plus its 8-byte key id; `--new-pairing-code` replaces it (every Mac must pair again).
- The Mac stores it in a key store (Keychain item `pair-<keyid>` under the service `tierfs-master-key`, or `dir:PATH`) with `tierctl pair <host:port> --store ...`,
  which authenticates against the device first and stores only what worked. Devices are then named `host:port@keyid` in the daemon and in `tierctl restore`.
- Disaster recovery on a new Mac needs the recovery phrase and the device codes (written down with the phrase): `tierctl restore --pairing-file FILE` takes lines of `host:port code`.
- A paired device may listen on any address; an unpaired one still refuses anything but loopback unless `--insecure-allow-network`.
