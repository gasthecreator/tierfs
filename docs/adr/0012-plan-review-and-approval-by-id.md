---
status: accepted
date: 2026-10-15
decision-makers: Gideon Sanni
---

# 0012. A space plan is read in plain words and approved by its id

## Context and Problem Statement
The policy layer could build a plan (which cold files to move off the Mac), turn a person's approval into scoped, expiring consents, and execute exactly that plan. But nothing
connected it to a person: the low-space notification said "Review and approve to continue" and there was no way to review or approve. The plan text was a digest and a list of paths.

## Decision Drivers
- Moving a file off the Mac is the one step that can lose data if everything else is wrong, so "yes" must mean "yes to exactly this, understood"
- What a person needs to see is not what the code needs to know: sizes in words, folders rather than hundreds of paths, what happens to each file, what is left alone, what blocks it
- A plan must not be approvable after the world changed, or twice, or when a gate would refuse it anyway
- It must be testable without a mount or a screen

## Considered Options
- A GUI (menu bar app)
- A text review and approval through the daemon's control socket (`tierctl plan` / `tierctl approve`), with the same text in the notification's instructions
- Auto-approval above some confidence

## Decision Outcome
Chosen option: **text review and approval by plan id, through the control socket** (which is already the user's own, mode 0600).
- `plan [free-now] [GiB]` builds a plan, remembers it as THE pending plan, and prints a review: space, what moves (folders, the largest files, counts), what happens to each file, what is left alone and why,
  warnings, anything that blocks it (recovery phrase not acknowledged, no or old backup statement, fewer than two devices), and the exact approval command with the plan's id. It moves nothing.
- `approve <id>` runs the pending plan if the id matches (a prefix of at least 8 characters is enough), it is younger than `plan_ttl_seconds` (one hour), and nothing blocks it. A plan is approved once. A blocked
  approval is refused without consuming the plan, so it can be approved after the problem is fixed. Execution is the policy engine's, which re-checks every file at the moment it moves, and the ledger enforces the gates again.
- "Free the space NOW" (no undo period) is only ever what the person typed (`free-now`); a critical disk does not turn it on by itself.
- Auto-approval stays out: nothing moves unless a person ran `approve`.

### Consequences
- Good: a person can read what will happen and agree to precisely that; the notification points at the command; every rule is tested through the daemon without a mount.
- Bad / trade-offs: a terminal command rather than a button; one pending plan at a time (a new `plan` replaces it).

### Confirmation
`tests/policy_test.cpp` (the text, every number and singular/plural), `tests/daemon_test.cpp` (plan and approve end to end: wrong id, stale, once only, blockers, one device, free-now); mutation tests of the text functions.

## More Information
Builds on the policy design in docs/DURABLE_STORE.md section 22; the gates are ADR-0007 (backup) and the recovery-phrase rule (I9).
