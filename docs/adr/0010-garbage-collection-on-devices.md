---
status: accepted
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0010. Devices forget only what the ledger has decided to forget (version pruning and chunk sweeping)

## Context and Problem Statement
Devices were append-only (invariant I4): every version of every file, every deleted file and every chunk ever uploaded stays forever. Editing a large file
many times, or deleting files, never frees space on a device. Deleting is the most dangerous thing a device can be asked to do, so it needs its own design.

## Decision Drivers
- A wrong delete on a device can destroy the only copy of data (the Mac's local bytes may already be gone)
- Chunks are shared (identical content has one chunk id), so a chunk is garbage only when NO retained manifest lists it
- The device cannot read manifests (they are encrypted), and the Mac can be offline, lose its ledger, or be restored from a backup
- A device that was offline during a deletion must not bring deleted versions back to life
- Open (unpaired) devices have no authentication, so they must not accept deletions without an explicit choice

## Considered Options
- Tombstone records written to the devices, honoured by `restore`
- The device decides on its own (age-based expiry)
- The Mac's ledger decides; the device only executes two narrow, idempotent, self-checking operations

## Decision Outcome
Chosen option: **the ledger decides, the device executes**, in two separate steps.

1. **Prune versions (Mac decides).** A version is pruned only when the ledger records the decision first (write-ahead, `versions.pruned_at`), under hard rules:
   a live file's *current* version is never pruned and at least one NEWER version must be committed with the full replica weight from fresh audits (so history
   is only dropped when something better is safely held); a deleted file is pruned only after its undelete window (default 30 days) and while no quarantined local
   bytes still depend on its replicas. A pruned version stays recorded forever (ledger rows are never deleted), so a device that comes back with an old manifest is
   never trusted to "adopt" it again: the ledger re-issues the deletion. This replaces tombstones: the ledger is the memory of what was deleted, and the devices
   need nothing extra (restore from a device that missed a deletion shows the older state, which is the user's own data, and the next GC pass removes it).
2. **Delete manifests (device obeys).** `DELETE_MANIFESTS` removes exactly the named (file, version) manifests, idempotently, and bumps the device's commit
   sequence so a device restored from an older copy is detected as before. Replicas are marked PRUNED in the ledger only after the device confirms.
3. **Sweep chunks (device checks).** `SWEEP` deletes chunks that no stored manifest lists. The device keeps the chunk list of every manifest it holds
   (`manifest_refs`, written in the same transaction as the manifest) and a database trigger refuses to delete a chunk that is still listed, whatever the code does.
   Chunks touched recently (uploaded, or reported present to the Mac) are left alone for a grace period so an upload in progress is never swept; the device
   operator sets a floor for that period (default 1 hour). A device whose store predates reference lists refuses to sweep until the Mac has re-sent every
   manifest's chunk list (a garbage-collection run does that automatically: the Mac reads each manifest, which it can decrypt, and sends its chunk list back), because it cannot otherwise know what is referenced.
4. **Authorization.** A device accepts deletions only if it is paired (authenticated channel) or was started with `--allow-delete`. Otherwise it answers EPERM.
5. **Off by default.** The daemon never prunes unless GC is switched on (`gc=on` / `tierctl gc run`), and `tierctl gc plan` shows exactly what would go.

### Consequences
- Good: space comes back; the safety property that matters (a retained manifest's chunks are never swept) is enforced inside the device's database, not only in code; every decision is in the hash-chained ledger; interrupted runs are harmless and repeatable (every step is idempotent).
- Bad / trade-offs: the device trusts the chunk list the Mac sends with a manifest (an authenticated Mac that lied could cause a premature sweep; an open device trusts any local process, as before); a stale device that missed deletions keeps old versions until the next pass reaches it; restore from such a device can show a file that was deleted.

### Confirmation
`tests/devicestore_test.cpp`, `tests/devicenet_test.cpp`, `tests/deviceauth_test.cpp` (device side), `tests/ledger_test.cpp` (the prune gates), `tests/gc_test.cpp` (engine end to end, crash points), and mutation tests of each.

## More Information
Supersedes the "append-only forever" part of invariant I4 (docs/DURABLE_STORE.md section 2); the ledger itself stays append-only. Specification: proto/PROTOCOL.md.
