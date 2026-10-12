# Threat model

tierfs holds the only copy of files while they are offloaded, so the threats that matter are mostly **loss and corruption**, then **disclosure**.
This is a living document; each row names the control and where it is tested.

## Assets
1. The user's files (content, names, sizes, attributes).
2. The master key and its recovery phrase.
3. The ledger (what exists where) and the quarantine (the last local copies).

## Trust boundaries
- **The Mac** (trusted while running; compromise of the Mac is out of scope).
- **Storage devices** (untrusted for confidentiality, integrity and honesty: they may rot, lie, lose data, be restored from old backups, or be stolen).
- **The network between them** (untrusted; the protocol has no encryption or login, so it is loopback-only by default).
- **The kernel / FUSE-T / macOS NFS client** (trusted to behave; known to have bugs: ADR-0006).

## Threats and controls
| # | Threat | Control | Evidence |
|---|---|---|---|
| T1 | A bug or crash destroys the only copy during offload | Move-to-quarantine, gated purge, intents journaled before the filesystem is touched, recovery at start | `tests/dropengine_test.cpp` (every crash point), ADR-0003, ADR-0004 |
| T2 | A device returns corrupted or wrong data | Chunks are AEAD-sealed with their id as associated data; ids are keyed HMACs of the plaintext; whole-file HMAC on recovery | `tests/crypto_test`, overlay and recovery tests (rot, swapped chunks, lying device) |
| T3 | A device silently lost or never had a copy | Challenge audits with one-time precomputed responses before any destructive step; replica weight needed (K=2.0) | `tests/replicator_test.cpp`, `tests/dropengine_test.cpp` |
| T4 | A device is restored from an old backup or re-initialised | Epoch and sequence tracking mark it suspect; its replicas stop counting until re-audited | `tests/replicator_test.cpp` |
| T5 | Two copies of the same data are confused (replay, swap) | AAD binds volume id, chunk id, file id and version | `tests/crypto_test.cpp` |
| T6 | A file is modified while being moved | Write gate (`FileGate`): a file with writers cannot be frozen; generation counters invalidate stale replication | `tests/overlay_write_test.cpp` (stress with drops) |
| T7 | The key is lost with the Mac | Recovery phrase (16 checksummed groups) proven by retyping three groups at setup; `tierctl check-phrase` | `tests/init_test.py` |
| T8 | An attacker with the phrase reads everything | Out of scope: the phrase is the root secret; keep it on paper, off the Mac | docs/RUNBOOK.md |
| T9 | A manifest or path from a device escapes the restore directory | Path sanitising (`..`, NUL, control chars, symlink components); setuid bits never applied; exclusive rename | `tests/recovery_test.cpp` (hostile manifests) |
| T10 | A malicious local process talks to the control socket | Socket is mode 0600 in the user's state directory; commands are the user's own | `tests/daemon_test.cpp` |
| T11 | The folder is unmounted and the scanner "forgets" every file | Refuses when more than half (and more than 10) tracked files are missing or the folder cannot be read | `tests/scanner_test.cpp` |
| T12 | Names that differ only in case or Unicode form collide | Folded unique key (ADR-0005) | `tests/ledger_test.cpp` |
| T13 | Traffic on the device network is read or altered, or someone impersonates the device or the Mac | Content is encrypted and authenticated end to end. Protocol v4 adds mutual authentication with a pairing secret, a fresh ephemeral key per connection and sealed, counted frames. A paired device refuses plaintext clients and any peer without the secret, drops peers that stall in the handshake, and may listen on the network; an unpaired device stays plaintext and loopback-only | `proto/PROTOCOL.md`, ADR-0009, `tests/securechannel_test.cpp`, `tests/deviceauth_test.cpp`, `tests/pairing_test.py`, `tests/recovery_test.cpp` (drill 15) |
| T14 | A kernel or NFS-client bug panics the machine | Never mount-test on the development Mac; CI never mounts | ADR-0006 |
| T15 | A file leaves the Mac although no backup holds it (new or edited since the last backup, or the backup is stale) | The backup statement is dated; the ledger refuses to drop or purge a file created or changed at or after it, or when it is older than 30 days; the policy does not plan such files | ADR-0007, `tests/ledger_test.cpp`, `tests/policy_test.cpp`, `tests/daemon_test.cpp` |

## Known gaps (tracked, not hidden)
- A leaked pairing secret lets its holder impersonate the device or the Mac to the other until the device is given a new one (`--new-pairing-code`, then every Mac pairs again); there is no revocation list and no per-Mac secret. On the device the secret is a 0600 file in the store directory, readable by anything running as that user; there is no rate limiting beyond the handshake deadline and the 64-connection cap. Devices that stay unpaired speak plaintext and must stay on loopback.
- The key lives in the login Keychain (this device only) when set up with `--store keychain`; the older key-file and `dir:` forms are development-only and leave the key readable by anything running as you. Any process running as you can ask the Keychain for the item once macOS allows it.
- Chunk ids and sizes leak the file-size distribution and which files share content (deduplication is visible to a device).
- Deleted files and old versions remain on the devices (append-only) until a tombstone and garbage-collection design exists.
- The backup gate trusts the owner's dated statement: `tierctl check-backup` shows what macOS reports, but nothing proves a given file is inside the backup. Offloaded files drop out of later backups of the folder (older backups and the devices keep them).
