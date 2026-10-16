---
status: accepted
date: 2026-10-15
decision-makers: Gideon Sanni
---

# 0014. Free space is watched on its own clock, and the notification says what to do and what stands in the way

## Context and Problem Statement
The low-space warning was a by-product of the maintenance tick: scan the folder, reconcile the devices, copy cold files (up to 4 GiB), purge, and only then measure free space.
On a slow device or a large folder the person could wait minutes (or, with background copying off, forever) to hear that the disk was filling. When a notification could not be
shown (no logged-in user session, notifications blocked) it was recorded as said and not repeated for six hours. The thresholds could not be set from the mount options. The
notification offered to move files even when a gate (recovery phrase, backup statement, two devices) would refuse.

## Decision Drivers
- Hearing about a filling disk must not depend on how long copying takes
- The check must be cheap enough to run every few seconds and must touch no device and move nothing
- "Said" must mean "shown"
- A notification that promises something the gates will refuse is worse than none
- It must stay a prompt, never an action: nothing moves without the approval of ADR-0012

## Decision Outcome
- **`PolicyEngine::check_space()`**: measure (macOS's "available for important usage", as the system's own warning does), and when short and a notification is due, make the plan
  and tell the person. The plan, which reads every file, is made only when it is going to be shown. `tick()` uses it, so behaviour there is unchanged.
- **A thread of its own** in the daemon runs `check_space` every `spacecheck` seconds (default 30; 0 turns it off), starting at once. It does not take the engine lock, so a long
  copy never delays a warning. Calls are serialised, so one shortage is announced once.
- **Said means shown.** `Notifier::low_space` returns whether the system could show it (`osascript` exit status). A failure is not recorded as said: it is retried after
  `prompt_retry` (10 minutes), at once if the shortage got worse, and the daemon reports "the low-space notification could not be shown" in `status` and `space`.
- **The notification names what stands in the way**: the hint is worked out when it is shown, and starts with the first blocker ("Not ready to run yet: no backup is recorded...")
  before the review command `tierctl plan '<ledger>'`, and always says nothing moves until approved.
- **Thresholds are options**: `lowgb`, `criticalgb`, `lowpct`, `criticalpct` (the larger of the size and the percentage applies, as before), validated at start
  (`validate_thresholds`: critical not above low, percentages 0 to 90, a low level that can appear).
- **`tierctl space <ledger>`** reports the level, the thresholds, how much would have to move, whether macOS counts reclaimable space or snapshots hold deleted space, when the
  person was last told, and any problem showing notifications.

### Consequences
- Good: the warning arrives within one check period, independent of copying; a lost notification is retried and visible; the text is honest about what can happen next.
- Bad / trade-offs: macOS has no hook for its own low-disk warning, so this polls (one `statfs` and a ledger read per check); the notification is text only (no buttons): approving
  stays a terminal command; a user session is needed to show anything.

### Confirmation
`tests/policy_test.cpp` (check_space, retry, serialisation, thresholds, report), `tests/daemon_test.cpp` ("free space is watched on its own clock": the thread, rate limit, worse-at-once,
a held engine lock, failed delivery and recovery, off), mutants in `scripts/policy_mutants.py`.
