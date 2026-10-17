> **Historical record.** Written during the early feasibility work and kept because ADRs and code comments cite it. It does not describe the current system: see [README.md](README.md).

# Phase 0: feasibility spike

Goal: prove a userspace filesystem can mount on this Mac (macOS 26.6.2, M2)
without a paid Apple Developer account, and answer two open questions.

## Decisions so far
- Driver: FUSE-T (no kext, no paid entitlement). FSKit dropped: its
  `com.apple.developer.fskit.fsmodule` entitlement needs a paid team, and
  third-party FSKit was reported broken on macOS 26.1/26.2.
- Languages: C driver adapter, C++17 core and backend.
- "Original path" strategy: overlay mount (test in step 4).

## Steps (only ever touch ~/tierfs/scratch-mnt and ~/tierfs/testdata)
1. Install FUSE-T (needs your admin password): `brew install --cask fuse-t`
2. `make`
3. `mkdir -p scratch-mnt && ./build/hellofs -f scratch-mnt`  (-f = foreground,
   so you see logs; Ctrl-C then `umount scratch-mnt` to stop)
4. In another terminal: `ls scratch-mnt`, `cat scratch-mnt/hello.txt`,
   `stat scratch-mnt/hello.txt`, `dd if=scratch-mnt/hello.txt bs=4 count=2`
5. Overlay test: create `~/tierfs/scratch-over/` containing a dummy file,
   mount hellofs ON it, confirm the dummy file is hidden, unmount, confirm
   it returns. Record whether macOS allows it.
6. Open scratch-mnt in Finder and note any hangs or `._` / `.DS_Store` noise.

## Record results here
- FUSE-T mounts: YES on macOS 26.6.2 / M2, free account, no kext. Mounted as
  NFS (`fuse-t:/x on ... (nfs)`). ls/cat/stat/partial dd all correct.
  Needed `-Wl,-rpath,/usr/local/lib` because the dylib uses @rpath.
- Overlay over non-empty directory: YES (user-owned dir under ~/tierfs).
  Underlying files hidden while mounted, intact after umount.
  NOT yet tested: protected folders (~/Documents, ~/Desktop) under TCC.
- Finder behaviour: not yet tested (needs GUI session).
- Known driver bugs to fix: owner shows root, mtime shows 1969 (set uid/gid/
  times in getattr).
