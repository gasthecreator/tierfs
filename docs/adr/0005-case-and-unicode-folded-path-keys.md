---
status: accepted
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0005. Make file names unique by a case- and Unicode-folded key

## Context and Problem Statement
APFS is case-insensitive and normalisation-insensitive by default, but the ledger compared paths exactly, so `A.txt` and `a.txt` could become two ledger files for one real file.

## Decision Drivers
- Must match what the volume treats as one name
- Must work on case-sensitive volumes too
- Must not change the displayed spelling

## Considered Options
- Compare exactly and rely on the user
- Normalise paths on the way in
- Keep the spelling, add a unique folded key column; fold = lowercase + NFD on Apple platforms (identity on case-sensitive volumes)

## Decision Outcome
Chosen option: **a unique `pkey` column holding the folded path** (schema version 2, with a migration that refuses and changes nothing if existing paths collide). All lookups, uniqueness checks, renames and prefix queries use it; the stored spelling is kept for display. The daemon sets the rule from `pathconf(_PC_CASE_SENSITIVE)`.

### Consequences
- Good: one name, one file, whatever spelling the user types; case-only renames work.
- Bad: folding approximates APFS's tables (simple lower-casing, no full case folding); a volume that changes sensitivity needs a new ledger.

### Confirmation
`tests/ledger_test.cpp` (folding, migration, tampering), overlay, scanner and daemon tests; `Ledger::fsck` checks every key.

## More Information
APFS uses its own Unicode tables; revisit if a discrepancy is found.
