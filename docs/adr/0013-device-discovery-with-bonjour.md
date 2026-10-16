---
status: accepted
date: 2026-10-15
decision-makers: Gideon Sanni
---

# 0013. Devices are found with Bonjour, and an announcement is only ever a locator

## Context and Problem Statement
A device was named by its address (`host:port@keyid`). A phone, a laptop or a Raspberry Pi on a home network changes address whenever it reconnects, so the daemon lost
the device until a person edited a configuration. The original plan called for discovery on the local network (mDNS/Bonjour). But anything on the network can publish
any announcement, so a discovery feature that decides *who to trust* would hand the data to whoever answers first.

## Decision Drivers
- A device that moves must be found again without a person
- A forged announcement must never read data, receive data, or make the daemon trust anything new
- No new dependency: macOS ships the Bonjour client library (`dns_sd.h`), and avahi provides the same API on Linux
- The rules (what an announcement may say, which device a configuration means) must be testable without a network

## Considered Options
- Trust the first announcement for a name ("kitchen-pi")
- Announce unauthenticated devices too, and let the person pick from a list
- Announce only paired devices; the announcement names the pairing key id; the daemon follows only an announcement that names a key id it already holds a secret for

## Decision Outcome
Chosen option: **announce only paired devices, match on the key id, and authenticate as always.**

- **Service** `_tierfs._tcp`, with a TXT record `v=1`, `auth=1|0`, `kid=<16 hex>` (`core/discovery.*`). The key id is the public identifier of the pairing secret (ADR-0009), already
  visible in every handshake; the secret is never announced. The parser is strict (one version, no repeated keys, a paired device must say its key id).
- **A device that is not paired refuses to advertise** (`tierfs-device <store> <port> <addr> --advertise[=NAME]`). An unauthenticated device is never invited onto the network.
- **The daemon follows `mdns:NAME@KEYID`** entries (`devices=mdns:kitchen-pi@0123456789abcdef`). The key id is required and must have a pairing secret in the key store, otherwise
  the daemon refuses to start. Each maintenance pass looks the key ids up; an announcement is followed only if it says it is paired and carries exactly that key id
  (`discovery::pick`; among several the smallest instance name, so the choice is stable). The NAME is only a label for people.
- **The connection still authenticates**: the secure channel needs the pairing secret on both ends, and the ledger still identifies the device by its own device id. A forged
  announcement can at worst make a connection fail (the daemon then shows the device as "not attached"). New addresses take effect at the next new connection
  (`DeviceClient::set_endpoint`); a working connection is never interrupted.
- **`tierctl discover [--seconds N] [--store S]`** lists what is announced, says whether this Mac is paired with each device, and prints the device entry to use. It also says
  plainly that an announcement is not evidence of anything. `tierctl restore --device mdns:NAME@KEYID --store S` finds a device the same way during disaster recovery.

### Consequences
- Good: devices that move are found by themselves; discovery adds no trust; no new dependency; the whole decision logic is pure and mutation-tested.
- Bad / trade-offs: anyone on the network can see that a tierfs device with a given key id exists (the id is derived from the secret but does not reveal it) and can flood the
  network with announcements (they cost the daemon one failed connection per maintenance pass). An attacker can make a device appear missing by announcing the same key id
  at a dead address and winning the name tie-break (a denial of service the network always allowed). mDNS is link-local: devices on another network need an address.

### Confirmation
`tests/discovery_test.cpp` (format, strict parsing, specs, choice, and a real announcement published and found through the system's service), `tests/daemon_test.cpp` ("devices found on the network": followed, not found, impostor, unpaired announcement, moved device), mutants in `scripts/discovery_mutants.py`.

## More Information
Specification: `proto/PROTOCOL.md` (Discovery). Threat T17 in `docs/THREAT_MODEL.md`.
