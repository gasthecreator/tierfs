# scripts

| Script | Status | Purpose |
|---|---|---|
| `mutate_par.py` + `*_mutants.py` | **current** | Parallel mutation testing: `python3 scripts/mutate_par.py <ledger\|recovery\|overlay\|scanner> -j 4 [--tests N] [--from N] [name filters]`. A mutant whose name starts with `[reason]` is a documented equivalent mutant. |
| `gen_crypto_kat.py` | current | Regenerates `tests/crypto_kat.hpp`: known-answer vectors for `core/crypto.cpp` from an independent pure-Python AES-GCM, HMAC and HKDF. |
| `phase3h-test.sh` | **dangerous** | Mounts a real filesystem. Refuses to run without `TIERFS_I_ACCEPT_A_REBOOT=1`; see ADR-0006. |
| `mutate-*.py`, `ledger_mutants_3e.py`, `dropengine_mutants.py`, `policy_mutants.py` | legacy | The serial per-component mutation runners (crypto, device, dropengine, ledger, policy, replicator) that preceded `mutate_par.py`. Still work; `mutate-crypto.py` is the only way to mutation-test `core/crypto.cpp`. |
| `phase1-test.sh`, `phase2-test.sh`, `phase2b-test.sh`, `errno-probe.sh` | legacy, mounts | Early read-only-driver tests. They mount FUSE-T: do not run on a machine you care about. |
| `attack.py`, `attack.sh` | legacy | Raw-protocol abuse tests against the Phase 1 backend (symlink escapes, malformed frames), loopback only. |
| `tsan-device.sh` | legacy | ThreadSanitizer run of the device store, server and client. |
