---
status: accepted
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0007. The backup gate is a dated statement checked per file

## Context and Problem Statement
Moving a file off the Mac must not rely on tierfs alone: a backup should exist. The gate was a yes/no flag, so one old "I have a backup" covered files
created or edited long after that backup, and offloaded files drop out of later backups of the folder.

## Decision Drivers
- Must be testable without Time Machine (none is configured on the development Mac; `tmutil` needs Full Disk Access to list backups)
- A wrong "yes" can cost the only copy of a file
- Must not trust a clock or a file timestamp the user can set

## Considered Options
- Keep the boolean
- Verify through `tmutil` (destination, latest backup)
- A dated statement, enforced per file against the append-only event history, plus an advisory `tierctl check-backup`

## Decision Outcome
Chosen option: **dated statement**. `ack-backup` records the time. A file may be dropped or purged only if its last `file.tracked` or `file.modified`
event is strictly before that time, and the statement is at most `backup_max_age_days` (default 30) old. The policy skips files that fail the gate.
`check-backup` reports what macOS says but never changes the ledger.

### Consequences
- Good: a new or edited file cannot ride on an old statement; the rule uses the ledger's own history, not file mtimes (which `touch` can set); fully tested.
- Bad / trade-offs: still a statement, not proof the backup contains the file; the owner must re-run `ack-backup` after each backup that should cover new work.

### Confirmation
`tests/ledger_test.cpp` (every branch, expiry boundary, same-second change, purge gate), `tests/policy_test.cpp`, `tests/daemon_test.cpp`, `tests/init_test.py`; mutation tests of `backup_check`.

## More Information
Threat T15 in docs/THREAT_MODEL.md. Revisit if a reliable programmatic check of Time Machine coverage becomes available without special permissions.
