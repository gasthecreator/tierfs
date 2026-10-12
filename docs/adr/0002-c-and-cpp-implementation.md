---
status: accepted
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0002. Implement in C (driver) and C++17 (core), built with Make

## Context and Problem Statement
Which languages and build system for a data-safety critical filesystem?

## Decision Drivers
- The author wants C/C++ practice
- The FUSE-T API is C
- No CMake installed; keep the toolchain small

## Considered Options
- C driver adapter plus C++17 core, plain Makefile
- Go, Rust or Swift for the core

## Decision Outcome
Chosen option: **C driver adapter plus C++17 core with a Makefile.** The language was an explicit goal of the project, so it is not swapped for convenience.

### Consequences
- Good: direct FUSE-T access; ASan/UBSan/TSan available out of the box; no new toolchain.
- Bad: memory-safety risk is higher than in Rust; mitigated by sanitizers in every test build, TSan on concurrent code, and mutation testing of safety-critical files.

### Confirmation
Every test target builds with `-fsanitize=address,undefined`; concurrency tests also run under TSan (`make test-ledger-tsan test-overlay-tsan test-ns-tsan`).

## More Information
Revisit only for the daemon's network-facing parts if they grow.
