---
status: accepted
date: 2026-10-16
decision-makers: Gideon Sanni
---

# 0016. A pairing for each Mac, revocable, with its own right to delete

## Context and Problem Statement
A device had one pairing secret, shared by every Mac that used it. Losing one Mac meant replacing the secret and re-pairing every other Mac (`--new-pairing-code`), there was no way to
take one Mac away, and every paired Mac could ask the device to delete (garbage collection, ADR-0010) whether it should or not.

## Decision Drivers
- Revoke one Mac without disturbing the others, effective at once, including connections that are already open
- A Mac that only stores and reads data should not be able to delete
- Existing devices must behave exactly as before (the single `pairing.key`, with the right to delete)
- A typo in a file must never silently weaken or disable security: no fallback to "open"

## Decision Outcome
A store can hold several pairings (`core/pairings.*`):
- `<store>/pairing.key` is the original single secret, now called "primary"; it may delete, as it always could.
- `<store>/pairings/<keyid>.key` holds one per Mac: the secret (64 hex), `label=`, `delete=0|1`, `created=`. Mode 0600; the file name must be the key id of the secret inside, so a
  file cannot be swapped for another. Parsing is strict: unknown, repeated or missing lines, a loose mode, a link, or a mismatched name make the file unacceptable.
- **Unacceptable files stop the device** (`tierfs-device ... --list-pairings` says why). A pairing file that cannot be read must never turn a paired device into an open one, and a
  typo in `delete=` must never change what a Mac may do.
- **Management**: `--add-pairing=LABEL [--pairing-allow-delete]` (prints that Mac's code), `--list-pairings`, `--revoke-pairing=KEYID`; `--show-pairing-code` / `--new-pairing-code`
  still work on the primary.
- **Lookup per handshake and per request**: the server finds the pairing by the key id the client names (reading only that file), so a revoked Mac is refused at once; a
  connection remembers its pairing and checks it (a stat; the file is read again only if it changed) before every request: revoked ends the connection, a changed right to delete
  applies immediately.
- **Deleting is per pairing**: `DELETE_MANIFESTS` and `SWEEP` from a pairing without the right answer EPERM ("this pairing may not delete"); `GC_STATUS` tells each Mac the truth about
  itself. An open device still follows `--allow-delete`.
- **Discovery** announces one record per pairing (each with its own key id and an instance name suffixed with the label), so each Mac finds the device by the key id it holds.
  The Android app lists the pairings, adds one per Mac and revokes them.

### Consequences
- Good: losing a Mac costs one `--revoke-pairing`; Macs that only store need no delete right; nothing changes for devices that already exist.
- Bad / trade-offs: a pairing added while the server runs works at once but is announced on the network only after a restart; the number of pairings is limited to 64; the mode
  (paired or open) is decided at start; a device that was started with no pairing stays open until restarted; revocation is on the device, so a device that is off keeps its old files
  until it is next started (a Mac revoked in absentia still holds its own secret, now useless).

### Confirmation
`tests/pairings_test.cpp` (the store: parsing, limits, revoke, refresh, permissions), `tests/deviceauth_test.cpp` ("several Macs, one device": each secret connects, delete rights, revocation
cutting an open connection, a changed right applying at once, unacceptable files stopping the device), `scripts/pairings_mutants.py`.
