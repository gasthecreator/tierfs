---
status: accepted
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0004. Offloading moves local bytes into a quarantine; deleting them is a separate, gated step

## Context and Problem Statement
After a file is copied to devices, when may its local bytes be deleted?

## Decision Drivers
- A bug in offload must not destroy the only copy
- The user must be able to undo
- Evidence of the remote copies must be fresh when the point of no return is crossed

## Considered Options
- Delete after the copy is verified
- Move to a quarantine folder for N days, purge later with fresh evidence

## Decision Outcome
Chosen option: **move to quarantine (default 7 days), purge only with fresh audit evidence** of enough replicas. A drop re-audits before moving; a purge re-audits again, and cannot be skipped even in an emergency.

### Consequences
- Good: every step is reversible until the purge; recovery paths restore the quarantine copy.
- Bad: offloaded files keep occupying local space for the quarantine period (policy can purge early under space pressure, still with fresh evidence).

### Confirmation
docs/DURABLE_STORE.md section 7; `tests/dropengine_test.cpp` (all crash points, rotted replicas, racing writers).

## More Information
Related gates: recovery phrase acknowledged, a backup recorded, a reserve file present, a scoped expiring consent.
