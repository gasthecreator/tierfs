# tierfs

[![ci](https://github.com/gasthecreator/tierfs/actions/workflows/ci.yml/badge.svg)](https://github.com/gasthecreator/tierfs/actions/workflows/ci.yml)
[![codeql](https://github.com/gasthecreator/tierfs/actions/workflows/codeql.yml/badge.svg)](https://github.com/gasthecreator/tierfs/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/gasthecreator/tierfs/badge)](https://scorecard.dev/viewer/?uri=github.com/gasthecreator/tierfs)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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
- **Tells you when the disk is filling** (checked every 30 seconds) and shows, in plain words, what it would move; nothing moves until you approve that exact plan.
- **Has a menu-bar app** that shows the state and approves exactly the plan you have read (`macos/`).
- **Finds its devices on the network** (Bonjour) when their addresses change; an announcement is only a locator, every device still has to prove it holds the pairing secret.
- **Runs on an Android phone** as one of the devices (the same server, built with the NDK; see [android/](android/)); so far tried only on an emulator.
- **Recovers from the phrase alone.** `tierctl restore` rebuilds your files from the devices if the Mac is lost, without overwriting anything.

## Layout
| Path | What |
|---|---|
| `core/` | ledger, crypto, device store and client, replicator, drop (offload) engine, policy, overlay (filesystem semantics), scanner, recovery, daemon |
| `mount/` | the FUSE-T drivers (`tierfsd.c` is the real one; the others are earlier phases) |
| `tools/tierctl.cpp` | the command-line tool: `init`, `restore`, `control`, `ledger-status`, `check-phrase`, ... |
| `android/` | the Android agent: the device server built with the NDK, a small app, and a Gradle-free build script |
| `tests/` | unit, crash-injection, concurrency and disaster-drill tests |
| `scripts/` | mutation-testing runners (`mutate_par.py`) and old mount scripts |
| `docs/` | start at [docs/README.md](docs/README.md): design, runbook, ADRs (`docs/adr/`), threat model |

## Build and test
Requires macOS on Apple silicon, Xcode command-line tools, and `brew install openssl@3`. FUSE-T is needed only to build the mount drivers.
```bash
make test        # everything that does not mount a filesystem (this is exactly what CI runs)
```
The tests build with AddressSanitizer and UBSan. `make test-ledger-tsan test-overlay-tsan test-ns-tsan` run ThreadSanitizer builds.
Mutation testing of the safety-critical files: `python3 scripts/mutate_par.py <ledger|recovery|overlay|scanner> -j 4`.

## Documentation
[docs/README.md](docs/README.md) is the index. Highlights: the [runbook](docs/RUNBOOK.md) (setup, recovery, what is unsafe), the
[design](docs/DURABLE_STORE.md), the [decision records](docs/adr/), and the [threat model](docs/THREAT_MODEL.md).

## Contributing and security
See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately: [SECURITY.md](SECURITY.md). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License
[MIT](LICENSE).

## Design in one paragraph
A ledger (SQLite, hash-chained history, full-fsync) is the source of truth for what exists where. The overlay joins an *origin folder* (local bytes), the
ledger, and the devices into one namespace. Offloading is a two-step, journaled move into a quarantine folder that can be undone for days; deleting the
last local copy is a separate, gated step. See `docs/DURABLE_STORE.md`.
