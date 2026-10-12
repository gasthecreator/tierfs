---
status: accepted
date: 2026-10-12
decision-makers: Gideon Sanni
---

# 0008. Keep the master key in the login Keychain, selected by a key source

## Context and Problem Statement
The master key was a 0600 file the user named. A file is readable by anything running as the user and is easy to copy into a backup or a sync folder by accident.

## Decision Drivers
- The key must not leave the device or land in a backup or iCloud
- The recovery phrase, not the Keychain, is the backup of the key
- Tests must not need the user's real Keychain

## Considered Options
- Keep the key file
- Login Keychain, "this device only", selected by a key source string
- Secure Enclave key wrapping

## Decision Outcome
Chosen option: **login Keychain with a key source string** (`keychain`, `dir:PATH` for development and tests, or a key file for compatibility). The item is a generic password with service `tierfs-master-key` and the volume id as the account, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, not synchronizable. It is never overwritten silently. `tierctl init --store keychain` stores the key only after the recovery phrase is proven, and undoes the ledger it created if the Keychain refuses.

### Consequences
- Good: the key is not in a file; each volume has its own item; the daemon looks it up by the ledger's volume id; the normal test suite never touches the Keychain.
- Bad / trade-offs: any process running as the user may be allowed to read the item after macOS access approval; the Keychain is lost with the Mac (the phrase covers that); Secure Enclave wrapping is not done.

### Confirmation
`tests/keysource_test.cpp`, `tests/daemon_test.cpp`, `tests/init_test.py` (plain suite uses `dir:`; `TIERFS_TEST_KEYCHAIN=1` exercises the real Keychain with one throwaway item that is deleted again); mutation tests of `core/keysource.cpp`.

## More Information
Revisit for Secure Enclave wrapping or a separate keychain with its own access control.
