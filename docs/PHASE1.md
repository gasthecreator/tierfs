> **Historical record.** Written during the early feasibility work and kept because ADRs and code comments cite it. It does not describe the current system: see [README.md](README.md).

# Phase 1 status: read-only mount over the network

Built: protocol v1 (proto/PROTOCOL.md), C++17 backend (backend/server.cpp),
C++ client with C API (core/), FUSE-T driver in C (mount/tierfs.c).

Run: `make && ./scripts/phase1-test.sh && ./scripts/attack.sh`

## Verified (macOS 26.6.2, M2, FUSE-T 1.2.9)
- Byte-exact reads, sha256 of a 3 MB file, partial read across a 1 MiB boundary.
- Writes refused; owner = current user; real mtimes.
- Path traversal (`..`, escaping symlink, relative, NUL) refused; oversized
  length, truncated payload, missing HELLO, unknown type all handled; ASan/UBSan clean.
- Backend killed: read fails immediately. Backend frozen (SIGSTOP): read fails in
  ~3 s (1.5 s timeout x 2: stale-connection retry). Driver reconnects by itself.

## Findings / open items
1. **FUSE-T rewrites our errnos.** Driver returns -EHOSTUNREACH or -ETIMEDOUT
   but apps saw "Permission denied" / "No such file or directory" (the NFS
   layer maps them). "No such file" for an unreachable device is dangerous:
   git/Xcode may treat the file as deleted. Phase 2 must find which errno
   survives the NFS translation (try EIO, EAGAIN, ESTALE) and test with git.
2. Metadata still hits the network on every getattr (Phase 2: local SQLite).
3. No TLS/auth: backend binds loopback only. Required before any LAN use.
4. errno numbers differ between macOS and Linux; need a portable table before
   pairing a Linux backend with the Mac.
5. Finder behaviour and protected folders (~/Documents) still untested.
6. (FIXED in Phase 2 step 4: whole-request deadline) Timeout was applied per socket op, so a slow-but-alive link that trickles
   bytes could exceed the intended deadline (use an overall deadline later).
