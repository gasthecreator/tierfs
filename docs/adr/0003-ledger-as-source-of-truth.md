---
status: accepted
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0003. A hash-chained SQLite ledger is the source of truth for what exists where

## Context and Problem Statement
The filesystem must never delete the only copy of a file because of a crash, a bug, or a lying device. Where is the truth about what is replicated, offloaded, or quarantined kept?

## Decision Drivers
- Crash safety: any step may be cut off at any instruction
- Evidence must be tamper-evident and auditable
- One writer process, many threads

## Considered Options
- State in extended attributes or marker files next to the data
- A key-value store
- SQLite with full-fsync, a state machine enforced by triggers and transactions, and an append-only hash-chained event log

## Decision Outcome
Chosen option: **SQLite ledger.** Every dangerous step (drop, purge, restore) is a transaction that re-checks all its gates, recorded as an intent before the filesystem is touched and completed after, so recovery can finish or undo it. Rows are never deleted (triggers refuse); the event log is hash-chained and verified by `fsck`.

### Consequences
- Good: crash-injection tests at every crash point; recovery is deterministic; history cannot be silently rewritten.
- Bad: a single-process ledger (flock) and one lock around every method; a schema change needs a migration (done once so far, ADR-0005).

### Confirmation
`tests/ledger_test.cpp` (including crash points via `TIERFS_CRASH_AT`), `Ledger::fsck`, and mutation testing of `core/ledger.cpp`.

## More Information
Design details: docs/DURABLE_STORE.md sections 5 to 8.
