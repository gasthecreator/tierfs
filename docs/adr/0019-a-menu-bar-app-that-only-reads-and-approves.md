---
status: accepted
date: 2026-10-17
decision-makers: Gideon Sanni
---

# 0019. A menu-bar app that shows the state and approves exactly the plan you read

## Context and Problem Statement
When the disk filled, the Mac showed a text notification and the person had to open a terminal, run `tierctl plan`, read it, and run `tierctl approve <id>`. That is the right safety design (ADR-0012) but a poor
experience: the notification cannot carry a button, and "where do I look?" is the first problem.

## Decision Drivers
- Approval must still mean "yes to exactly this plan, understood": nothing may be approvable without the plan being on screen
- The app must not widen what can be done: every rule is enforced by the daemon, not by the app
- It must be testable without a display
- No entitlements, no paid Apple account

## Decision Outcome
`macos/TierfsMenu` is a menu-bar app (no Dock icon) that talks only to tierfsd's control socket (mode 0600, the user's own):
- **A status item** shows `tierfs`, `tierfs · LOW`, `· CRITICAL` or `· off` (tierfsd not running), and a menu with the space report (`space`), any problem the daemon reports (a notification that could not be shown), and the devices (`status`).
- **Review what could move…** opens the plan exactly as `tierctl plan` prints it (the daemon's own text). **Approve this plan** is enabled only when the plan names an id, moves files and has nothing in the way (`CANNOT RUN YET`); it asks once more
  ("Move these files off this Mac?"), then sends `approve <id>` where the id is the one in the text on screen and is checked to be 16 hex characters. The daemon still refuses a plan that is stale, not the last one shown, already approved, or blocked, and re-checks every file before it moves.
- The control client (`TierfsControl.swift`) has no user interface in it: it sends one line (a newline in a command cannot become a second command), reads the answer until the daemon closes the connection (with a deadline and a size limit), treats an answer that does not end in OK or ERR as not OK, and parses the reports.
  `make test-macos` tests it against a stand-in server (`macos/tests/main.swift`).
- Build: `macos/build.sh` -> `build/macos/TierfsMenu.app`, ad-hoc signed; `TierfsMenu --ledger DIR` (default `~/.tierfs/ledger`); add it to Login Items to have it at login.

### Consequences
- Good: one place to look, one button, and the button cannot do anything the terminal could not; the parts that decide (parsing, what may be approved, what is sent) are tested.
- Bad / trade-offs: the windows and menu were not exercised by a person or an automated UI test (the status item was started against a stand-in daemon and polled it as expected, and was not looked at); notifications still come from the daemon (`osascript`) and have no button; the app polls every 15 seconds; it needs the control socket, so it shows `· off` while tierfsd is not running.

### Confirmation
`macos/tests/main.swift` (replies, the client against a stand-in daemon including injection, silence, huge and cut-off answers, and the parsing of the daemon's real texts, and which plans may be approved); a manual start against a stand-in daemon.
