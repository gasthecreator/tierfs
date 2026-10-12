# Security Policy

tierfs handles the only copy of people's files, so correctness and security reports are taken seriously.

## Supported versions
The project is pre-1.0. Only the latest commit on `main` is supported.

## Reporting a vulnerability
**Please do not open a public issue.** Use GitHub's private reporting: the **Security** tab of this repository, then **Report a vulnerability**.

Include the commit you tested, the impact, and steps to reproduce (a failing test is ideal).

## What to expect
- Acknowledgement within **7 days** (this is a one-person project, so please be patient).
- A first assessment of severity within **14 days**, and updates as the fix progresses.
- Coordinated disclosure: a fix and an advisory crediting you (if you wish) within **90 days** of the report.

## Scope
In scope: this repository's code, in particular the ledger, the encryption and key handling, the device protocol and server, the offload/restore
engines (anything that could lose, corrupt, or leak a file), and recovery. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what is
protected and what is explicitly not.

Out of scope: third-party software (FUSE-T, macOS), and attacks that require an attacker who already controls the Mac.

Known limitation, not a vulnerability: the device server has no authentication and is loopback-only unless explicitly overridden.

## Safe harbor
Good-faith research that follows this policy will not be pursued legally.
