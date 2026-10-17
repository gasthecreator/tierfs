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

Also in scope: the device protocol's secure channel and pairings (`core/securechannel.*`, `core/pairings.*`, ADR-0016), the device trash
(ADR-0017), and the Android agent (`android/`).

Known limitations, not vulnerabilities (all stated in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)):
- An *unpaired* device server speaks plaintext without a login and is loopback-only unless `--insecure-allow-network` is given. A *paired*
  device authenticates and encrypts every connection (protocol v4); use pairing for any device reached over a network.
- Anyone holding a pairing secret can act as that Mac until the pairing is revoked (`--revoke-pairing`).
- Service announcements (Bonjour) are only locators and prove nothing.
- The FUSE mount layer is unproven and the project says so: do not use it on data you cannot lose.

## Safe harbor
Good-faith research that follows this policy will not be pursued legally.
