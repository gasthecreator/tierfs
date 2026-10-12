# tierfs

A tiered-storage filesystem for macOS: cold files move off your Mac to other devices and come back on demand, at the same path, as if they never left.
Written in C/C++17 on FUSE-T (no kernel extension).

> **Status: work in progress. Do not point it at real data.**
> The engines are heavily tested, but the FUSE mount layer is unproven: mounting through FUSE-T triggered a kernel panic in macOS's NFS client
> during testing (`nfs_vinvalbuf2: ubc_msync failed`). See [docs/RUNBOOK.md](docs/RUNBOOK.md) before running anything that mounts.

## What it does
- **Offloads** files you rarely touch to storage devices, keeping their names, sizes, and attributes in place. Reads fetch only the chunks they need.
- **Never trusts a copy it hasn't verified.** Data is split into 1 MiB chunks, encrypted and authenticated (keys derived from a recovery phrase), and
  a file is moved off the Mac only after enough copies pass a fresh audit and a backup is on record.
- **Survives crashes.** Every step of an offload, restore and recall is journaled in a ledger and finished or undone at the next start.
- **Recovers from the phrase alone.** `tierctl restore` rebuilds your files from the devices if the Mac is lost, without overwriting anything.

## Layout
| Path | What |
|---|---|
| `core/` | ledger, crypto, device store and client, replicator, drop (offload) engine, policy, overlay (filesystem semantics), scanner, recovery, daemon |
| `mount/` | the FUSE-T drivers (`tierfsd.c` is the real one; the others are earlier phases) |
| `tools/tierctl.cpp` | the command-line tool: `init`, `restore`, `control`, `ledger-status`, `check-phrase`, ... |
| `tests/` | unit, crash-injection, concurrency and disaster-drill tests |
| `scripts/` | mutation-testing runners (`mutate_par.py`) and old mount scripts |
| `docs/` | `DURABLE_STORE.md` (the design, in detail), `RUNBOOK.md` (operating it), phase notes |

## Build and test
Requires macOS on Apple silicon, Xcode command-line tools, and `brew install openssl@3`. FUSE-T is needed only to build the mount drivers.
```bash
make test-unit test-client test-device test-replicator test-dropengine test-policy \
     test-recovery test-overlay test-overlay-write test-overlay-ns test-scanner test-daemon test-init
```
None of these mount anything. The tests build with AddressSanitizer; `make test-ledger-tsan test-overlay-tsan test-ns-tsan` run ThreadSanitizer builds.
Mutation testing: `python3 scripts/mutate_par.py <ledger|recovery|overlay|scanner> -j 4`.

## Design in one paragraph
A ledger (SQLite, hash-chained history, full-fsync) is the source of truth for what exists where. The overlay joins an *origin folder* (local bytes), the
ledger, and the devices into one namespace. Offloading is a two-step, journaled move into a quarantine folder that can be undone for days; deleting the
last local copy is a separate, gated step. See `docs/DURABLE_STORE.md`.
