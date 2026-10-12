# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/)
once 1.0 is reached. Until then, anything may change.

## [Unreleased]

### Added
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
