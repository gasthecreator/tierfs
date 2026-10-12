---
status: accepted
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0001. Use FUSE-T (not FSKit or a kernel extension) to present the filesystem

## Context and Problem Statement
tierfs needs a userspace filesystem on macOS 26 for an author with a free Apple developer identity only. Which mount mechanism can run without a paid developer program or a kernel extension?

## Decision Drivers
- No paid Apple Developer Program (FSKit modules need the `fskit.fsmodule` entitlement)
- No kernel extensions on Apple silicon
- Must work on macOS 26.6.2

## Considered Options
- FSKit (Apple's userspace filesystem framework)
- macFUSE (kernel extension)
- FUSE-T (userspace NFS server that macOS mounts)

## Decision Outcome
Chosen option: **FUSE-T**, because it mounts with no entitlement and no kext, and a spike (docs/PHASE0.md) mounted it successfully, including over a non-empty folder.

### Consequences
- Good: works today with a free account; the FUSE API is well known.
- Bad: FUSE-T serves the mount through macOS's own NFS client, so NFS caching semantics apply (attribute caches, no change notification) and the client has kernel bugs: see ADR-0006.

### Confirmation
docs/PHASE0.md records the spike; `mount/tierfsd.c` is the driver.

## More Information
FSKit was also reported broken for third-party modules on macOS 26.1/26.2. Revisit if a paid team identity becomes available or FSKit stabilises: the driver is a thin layer (`core/tfs_c.h`), so replacing it does not touch the engines.
