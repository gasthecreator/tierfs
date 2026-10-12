# Contributing

Thanks for helping. tierfs is a data-safety project: a bug can destroy the only copy of someone's file, so changes are held to a high bar. This
page is the shortest path from clone to merged change.

## Setup
Requires macOS on Apple silicon, Xcode command-line tools, and Homebrew.
```bash
git clone https://github.com/gasthecreator/tierfs.git && cd tierfs
brew install openssl@3
make test        # builds with sanitizers and runs every test that does not mount a filesystem; must pass on a fresh clone
```
FUSE-T is needed only to build the mount drivers (`brew install --cask fuse-t`).

> **Never run a mount test on a machine you care about.** FUSE-T mounts triggered a kernel panic in macOS's NFS client during development
> (ADR-0006). `scripts/phase3h-test.sh` refuses to run unless you set an explicit opt-in. CI never mounts.

## Workflow
1. Open or claim an issue. For anything that changes how data is moved, stored or deleted, write down the design first: an ADR in
   [`docs/adr/`](docs/adr/) (copy `0000-template.md`) or a section in `docs/DURABLE_STORE.md`.
2. Branch from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`. Keep branches short-lived.
3. Keep changes small and single-purpose; refactors in separate commits from behavior changes; include tests in the same change.
4. Run `make test`. CI runs the same.
5. Open a pull request using the template and explain *why*, not just what.

## Standards
- **Tests:** new behavior needs tests, including failure paths (a crash at each step, a bad or lying device, a racing writer). A bug fix starts
  with a failing test. Tests must look things up by id, not list position, and must not use fixed ports or paths: use the environment overrides
  (`TIERFS_TEST_PORT`, `TIERFS_TEST_TMP`).
- **Mutation testing:** for changes under `core/` that guard data (`ledger`, `crypto`, `dropengine`, `recovery`, `overlay`, `scanner`), run
  `python3 scripts/mutate_par.py <target> -j 4` and either kill the survivors with tests or tag them in the mutant list with the reason they are
  equivalent (`[reason] name`). A change that leaves unexplained survivors is not done.
- **Concurrency:** anything with threads also runs under ThreadSanitizer (`make test-ledger-tsan test-overlay-tsan test-ns-tsan`).
- **System calls:** inside a class that has methods named `mkdir`, `unlink`, `rename`... always call the libc function as `::unlink(...)`.
- **Format:** `.clang-format` applies to the lines you change (CI checks the diff); do not reformat code you are not otherwise touching.
- **Docs:** update `docs/`, the README, and `CHANGELOG.md` (under "Unreleased") in the same change. Do not edit an accepted ADR's decision:
  write a new ADR that supersedes it.
- No secrets, keys, recovery phrases, or build artifacts in commits.

## Commit messages (Conventional Commits)
`type(scope): imperative summary`, where type is `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, or `chore`. Use `!` or a
`BREAKING CHANGE:` footer for incompatible changes (including ledger schema changes). The body explains why.
(Earlier history uses `Phase N:` messages; it is not rewritten.)

## Reporting bugs and security issues
Bugs: use the issue template. Vulnerabilities: see [SECURITY.md](SECURITY.md) (private report).
