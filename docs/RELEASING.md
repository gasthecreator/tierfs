# Releasing

tierfs is pre-1.0, so every release is marked a pre-release. A release is cut by pushing a tag; the `release` workflow does the rest.

## Cut a release
1. Move the "Unreleased" entries in `CHANGELOG.md` under a new `## [0.x.y] - YYYY-MM-DD` heading, in a pull request, and merge it.
2. Make sure `main` is green, then tag it: `git switch main && git pull && git tag -a v0.x.y -m "v0.x.y" && git push origin v0.x.y`.
3. The workflow (`.github/workflows/release.yml`) runs the device-side tests on Linux, then publishes the device server binary, a source archive, an
   SPDX software bill of materials (from GitHub's dependency graph), and `SHA256SUMS`, with signed build provenance for every file.

The Mac side (the daemon, the drivers, the menu-bar app) is built from source: it has no Apple developer account behind it, so there is no signed or
notarized Mac download. The Android agent is built from source too (`android/build.sh`); a published APK would need a release key that must never be
in CI without a deliberate decision (ADR needed first).

## Verify a download
```bash
gh attestation verify tierfs-device-v0.x.y-linux-x86_64 --repo gasthecreator/tierfs     # built by this repository's workflow, from that tag
sha256sum -c SHA256SUMS
```

## Roll back
A bad release is withdrawn with `gh release delete v0.x.y --yes` plus `git push --delete origin v0.x.y`, and a fixed one is cut with the next number
(never re-use a tag: provenance and checksums must stay unique).

## Refreshing pinned dependencies
Dependabot cannot update these, so it is done by hand. `android/fetch-deps.sh` pins SQLite (SHA3-256, as published on sqlite.org) and OpenSSL (SHA-256,
as published next to the tarball). To move to a newer version: read the new hashes at the sources (not from the download), change the four lines at the
top of the script, and run `android/build.sh` (CI's Android job does the same on every pull request). GitHub Actions are pinned by commit SHA and
are updated by Dependabot (`.github/dependabot.yml`).
