# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/)
once 1.0 is reached. Until then, anything may change.

## [Unreleased]

### Added
- `tierctl service plist|install|uninstall|status`: tierfsd as a LaunchAgent. The plist is rendered and checked by `core/service.*` (absolute paths; the mountpoint may not be, contain or lie inside the origin; the key only from the Keychain or a key store; no comma or control character in option values) and does not restart a crashed mount or start at login unless asked. `install` writes the plist and starts nothing; `--load` additionally needs `TIERFS_I_ACCEPT_A_REBOOT=1` while mounting is unproven (ADR-0006).
- Read-ahead for offloaded files: after three sequential reads the overlay fetches the next chunks in the background (window 1, 2, 4 ... up to `readahead=N`, default 4, never more than a quarter of the cache), verified and cached like any other fetch; a chunk wanted by the reader and the read-ahead at once is fetched once. `-o readahead=0` (negative in the C options) turns it off.
- Garbage collection on the devices (ADR-0010): the ledger decides which old versions and deleted files to forget (permanent, hash-chained, never a live file's current version, only with a newer version held by fresh audits, deleted files after 30 days), devices delete exactly the named manifests and sweep chunks no manifest lists (a database trigger protects listed chunks), only if paired or started with `--allow-delete`; `tierctl control <ledger> gc-plan|gc-run`, daemon option `gc=1`. Device store schema 2 and ledger schema 3 migrate on open.
- Secure channel for the device protocol (v4): pairing secret, ephemeral X25519, AES-256-GCM frames with counters (ADR-0009); known-answer vectors from an independent reference.
- Device authentication, wired in: `tierfs-device <store> --show-pairing-code` / `--new-pairing-code`; a paired device speaks only the authenticated channel and may listen on any address, an unpaired one stays plaintext and loopback-only; `tierctl pair <host:port> --store keychain|dir:PATH` keeps the secret in the Keychain; devices are named `host:port@keyid` in the daemon and in `tierctl restore --store SPEC`, and `restore --pairing-file FILE` lets a disaster recovery start from the recovery phrase plus the codes written on paper.
- The master key can live in the login Keychain: `tierctl init <ledger> --store keychain`, `tierctl check-phrase --store keychain <ledger>`, daemon option `keyfile=keychain` (key sources: `keychain`, `dir:PATH`, or a key file). The real-Keychain tests are opt-in (`TIERFS_TEST_KEYCHAIN=1`).
- Dated backup statements: a file may leave the Mac only if it was created or changed before the recorded backup, and the statement expires after 30 days; `tierctl check-backup` (read-only Time Machine report); the policy skips files the backup does not cover.
- Case- and Unicode-insensitive name handling (unique folded key, schema version 2 with migration), matching APFS.
- Repository standards: LICENSE (MIT), SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, CODEOWNERS, issue and PR templates, ADRs, threat model,
  CodeQL, Scorecard and Dependabot, pinned CI actions, `make test`.
- `tierctl init`, `check-phrase`, `ack-backup`, `control`, `restore`, `ledger-status`.
- `tierfsd`: daemon with start-up recovery, scanner, maintenance thread and a private control socket; FUSE-T driver.
- Overlay filesystem semantics: reads from local or remote bytes, writes with a write gate, hydration, namespace operations, extended attributes.
- Disaster recovery from the recovery phrase and any one device.
- Policy layer: space levels, cold-file planning, scoped expiring consent, background replication.
- Drop engine with quarantine, purge and restore; replicate engine with audits; device store and protocol v3; deterministic encryption; ledger.

### Changed
- `tierctl ack-backup` now records the time; ledgers with an undated statement refuse to move files until it is run again.

### Known issues
- The FUSE-T mount layer is unproven on real hardware: mounting reset the development machine (macOS NFS-client panic, ADR-0006).
- The device server has no authentication; see the threat model.
