---
status: accepted
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0006. Do not mount-test on the development Mac

## Context and Problem Statement
A real mount test through FUSE-T reset the author's Mac several times. A kernel panic report shows `nfs_vinvalbuf2: ubc_msync failed! error 22` in Apple's NFS client while `cp` wrote into the mount.

## Decision Drivers
- A kernel panic can lose unsaved work in any application
- The filesystem logic must still be tested thoroughly

## Considered Options
- Keep running mount tests locally
- Test the logic without a mount (library level) and mount only in a disposable macOS VM
- Replace FUSE-T

## Decision Outcome
Chosen option: **test everything without a mount** (`make test`), keep the one mount script behind an explicit opt-in (`TIERFS_I_ACCEPT_A_REBOOT=1`), and use a throwaway VM if real mount tests are wanted.

### Consequences
- Good: the data-safety logic is tested without risking the machine.
- Bad: the FUSE-T driver is unproven on real hardware; whether tierfs's access patterns provoke the Apple bug is unknown.

### Confirmation
CI never mounts. `scripts/phase3h-test.sh` refuses to run without the opt-in. docs/RUNBOOK.md carries the warning.

## More Information
Panic string and analysis: docs/DURABLE_STORE.md (3h-4 status).
