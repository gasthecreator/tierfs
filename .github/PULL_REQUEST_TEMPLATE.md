## What
<!-- One paragraph: what changes. -->

## Why
<!-- The problem or requirement. Link the issue, ADR, or design section. -->
Closes #

## How
<!-- Approach, alternatives considered, known limitations. -->

## Testing
<!-- What you ran and what it proves. tierfs is a data-safety project: say how a failure (crash, bad device, race) is covered. -->
- [ ] `make test` passes locally
- [ ] New behavior has tests, including failure paths
- [ ] For changes to `core/`: a mutation run (`scripts/mutate_par.py`) of the touched files, or a note on why not
- [ ] **Not tested by mounting a real filesystem** (see docs/RUNBOOK.md: mounting can panic the kernel)

## Risk
- [ ] Cannot lose, corrupt, or expose user data on any failure path, or the risk is stated here
- [ ] Safe to roll back (schema changes include a migration and a refusal path)
- [ ] Docs updated (`docs/`, README, CHANGELOG under "Unreleased")

## Checklist
- [ ] Single-purpose change (refactors separate from behavior changes)
- [ ] No secrets, keys, or build artifacts committed
- [ ] I can explain every line of this change
