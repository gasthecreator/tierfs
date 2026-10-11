# Durable store and safe offload (Phase 3 design)

Status: design accepted. **3a (ledger), 3b (crypto), 3c (device store + protocol v3) and 3d (replicate engine + reconciliation) and 3e (drop-local engine) are implemented and tested** (sections 17-21);
nothing else in Phase 3 exists yet and nothing deletes data. Written before any code because this is the
one place where a bug destroys the only copy of someone's file. The caches
(meta.db, chunks.db) are disposable; everything in this document is not.

## 0. The problem in one paragraph
Offloading deletes local bytes and leaves the device holding the only copy. Five
things can go wrong: we crash half way, the device lies or forgets, the bytes
rot, we lose our own records of where things went, or the user loses the Mac
(or the key). The design answers each with a rule (section 2) that the code must
never break, and a test that tries to break it (section 14).

## 1. Failure model
Defended against:
- Mac crash, `kill -9`, or power loss at ANY instruction of an offload.
- Device offline, asleep, restarted mid-write, or on another network.
- Device acks a write that is not yet on disk (phones, cheap flash) [see 10].
- Bit rot, truncated or swapped blobs on the device.
- Device rolled back (restored from an old backup, factory reset, reinstall).
- Our own ledger corrupt, deleted, or restored from an old Time Machine copy.
- Mac disk full while we need to write a record.
- User error: confirming without understanding, wrong device, lost phone.
- Total loss of the Mac (stolen, dead SSD) while the device survives.

NOT defended against (say so to the user, in the UI):
- Mac AND every replica lost together. That is what replica count is for.
- A device that deletes data on purpose (availability). It cannot forge or alter
  data undetected (authenticated encryption), but it can delete.
- An attacker with root on the Mac. APFS or drive firmware bugs beyond F_FULLFSYNC.
- Losing the recovery phrase AND the Keychain: encrypted data is then unreadable.

## 2. Invariants (rules the code must never break)
- **I1  Local bytes are deleted only if** K verified replicas hold exactly this
  file version (K from policy, section 10) and each was audited < T_audit ago.
- **I2  Write-ahead.** Intent is durably logged before any irreversible step;
  completion is logged after it. After a crash we can always tell which step ran.
- **I3  Fail closed.** Any error, timeout, mismatch, or unwritable ledger means
  "keep the local bytes". There is no code path where uncertainty deletes.
- **I4  Remote data is append-only in Phase 3.** No remote delete or overwrite of
  a committed chunk or manifest. (Garbage collection is a later, separate design.)
- **I5  Versions are immutable.** A change creates version N+1; version N stays.
- **I6  The device alone can rebuild the tree** (self-describing encrypted
  manifests) given the recovery phrase. The Mac's ledger is an index, not the
  only record.
- **I7  "Verified" means read back from the device's storage by challenge**, never
  "the upload call returned OK".
- **I8  No offload without consent** recorded for that batch; consent expires.
- **I9  No offload until the recovery phrase is acknowledged** (section 11).
- **I10 Ordering uses F_FULLFSYNC**, not fsync (measured: macOS fsync does not
  flush the drive cache, `man 2 fsync`).

## 3. Where state lives
| What | Where | If lost |
|---|---|---|
| Ledger (authoritative) | `~/Library/Application Support/tierfs/<volume>/ledger.db` | rebuild from device snapshot + manifests (S3) |
| Local bytes of files | origin store `~/.tierfs-store/<volume>/objects/` | local-only files: gone unless backed up |
| Master key | Keychain (not synced) + recovery phrase on paper | without BOTH: encrypted data unreadable |
| Disposable caches | `~/Library/Caches/tierfs/...` (meta.db, chunks) | nothing; refetched |
| Chunks, manifests, ledger snapshots | on each device | that replica is gone |

The ledger is NOT in Caches (macOS may purge it, Time Machine skips it), is
included in Time Machine, and is excluded from tiering itself.
Finding on this Mac: no Time Machine destination is configured, so today nothing
backs up the origin store. The setup flow must say so before first offload.

## 4. Identity and data model
IDs (random 128-bit): `volume_id`, `device_id`, `file_id` (stable across rename,
so renaming never re-uploads). Per file: `version` (monotonic) and `generation`
(bumped by ANY local modification of the current version; used for compare-and-swap).

Chunks: plaintext cut into 1 MiB chunks (same size as the read cache).
- `chunk_id  = HMAC-SHA256(K_id, plaintext)`: dedupes within a volume, and the
  device learns nothing about content hashes.
- blob on device = `nonce(12) || AES-256-GCM(K_data, plaintext, aad = chunk_id || "tfs1") || tag`.
  Binding chunk_id into the AAD stops a device from swapping blobs.
- `blob_sha256` (of the ciphertext) is kept in the ledger to verify a full re-download.
  It cannot verify a challenge (see "Audits" below and the correction in section 17).

Manifest, one per (file_id, version), encrypted with K_manifest, stored on the
device as `manifests/<file_id>/<version>.mf`:
`{path, mode, mtime, size, xattrs, chunk_ids[], file_hmac, prev_version}`.
A plaintext list of chunk_ids travels beside it so the device can check that every
referenced chunk exists before accepting the manifest.

Ledger tables (SQLite, WAL, `synchronous=FULL`, `fullfsync=ON`, `checkpoint_fullfsync=ON`):
```sql
meta(key, value)                        -- schema_version, volume_id, recovery_acked, policy
devices(device_id PK, name, class, state, last_seen, device_epoch, last_device_seq)
files(file_id PK, path UNIQUE, current_version, generation, state, size, mtime,
      mode, local_present, last_access)
versions(file_id, version, size, mtime, chunk_count, manifest_sha256, PRIMARY KEY(file_id,version))
version_chunks(file_id, version, idx, chunk_id, len, blob_sha256)
replicas(file_id, version, device_id, state, committed_at, last_audit_at, device_seq)
intents(intent_id PK, kind, file_id, version, generation, payload, state, created_at, done_at)
consents(consent_id PK, created_at, expires_at, scope, policy, ack_text)
events(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts, kind, file_id, version, device_id,
       detail, prev_hash, hash)         -- append-only, hash-chained
```
`events` is protected by triggers that abort UPDATE and DELETE, and each row's
`hash = SHA256(prev_hash || row)`. A broken chain is detected by `tierctl fsck`.

## 5. State machine (per file; replicas have their own states)
```
LOCAL ──replicate──▶ REPLICATING ──all chunks + manifest committed──▶ REPLICATED
                                                                   │  (bytes local AND remote)
        audit ok, >=K replicas, consent, CAS(generation) ──────────┤
                                                                   ▼
                     OFFLOADED ◀──bytes gone── DROPPING (intent logged)
                         │
        read / recall ───┴──▶ HYDRATING ──▶ REPLICATED
 any state ──audit fails / device inventory disagrees──▶ AT_RISK (alert; repair from another replica)
```
Key design choice: **replicate and drop are separate steps.** Replication is safe,
reversible, and can run in the background whenever the device is reachable.
Dropping only needs a fresh audit. So when the disk is nearly full we never
upload under pressure; we verify and delete already-replicated cold files.

Replica states: PENDING, UPLOADED, COMMITTED, AUDIT_FAILED, MISSING.

## 6. Replicate (device-side commit)
1. `HAS_CHUNKS(chunk_ids)` -> which are missing.
2. `PUT_CHUNK(chunk_id, blob)` for each: idempotent. Device writes temp, F_FULLFSYNC/
   fsync, rename, fsync the directory.
3. `PUT_MANIFEST(file_id, version, manifest, chunk_id_list)`: device rejects unless
   every chunk is present, then durably stores it and increments `device_seq` in a
   persisted commit log. Ack = `{device_epoch, device_seq, manifest_sha256}`.
4. Ledger transaction (full fsync): replica COMMITTED, file REPLICATED, event.
A crash anywhere leaves either nothing, orphan chunks (harmless, never deleted in
Phase 3), or a device manifest the ledger has not recorded yet (adopted by
reconciliation, section 8).

## 7. Drop local bytes (the dangerous step), with crash points
0. **Pre-flight (read-only):** file REPLICATED at current version; >=K COMMITTED
   replicas; valid consent; ledger reserve present (section 13); file not open for write.
1. **Freeze:** FS refuses new writers on this file (EBUSY) until step 7.
2. **AUDIT now** (corrected in 3b): per replica, send the next unused one-time nonce for
   each chunk; the device returns `SHA256(nonce || blob)` computed from its disk. The Mac
   compares with a response it precomputed and stored when it uploaded the chunk (the Mac
   does not keep blobs, and `SHA256(nonce || blob)` cannot be derived from `SHA256(blob)`).
   Nonces are `HMAC(K_audit, chunk_id || n)`, so the device cannot know one before it is
   asked, hence cannot answer without reading the blob now. A used nonce is never reused.
   When a chunk's pool (4 nonces) is spent, the next audit of it is a full fetch: download,
   authenticate, re-derive a fresh pool. Also audits the manifest.
   **CP1**
3. **Ledger txn A (full fsync):** compare-and-swap `files` where `generation == g`
   and `current_version == v` -> state DROPPING; insert intent DROP_LOCAL; event.
   If the CAS fails the file changed: abort, keep everything. **CP2**
4. **Move bytes to quarantine:** rename `objects/<file>` to `trash/<intent_id>`
   (atomic, same volume), then F_FULLFSYNC the directory. **CP3**
5. **Ledger txn B (full fsync):** state OFFLOADED, `local_present=0`, intent done,
   event. **CP4**
6. **Unfreeze.** Reads now hydrate from the device.
7. **Later:** after the quarantine period (or on disk pressure) unlink the trash
   entry; event. **CP5**

| Crash at | After restart | Action |
|---|---|---|
| before CP2 | file still REPLICATED | nothing lost; unfreeze |
| CP2..CP3 | intent open, bytes in place | re-audit; resume, or set REPLICATED again |
| CP3..CP4 | intent open, bytes in trash | re-audit; if ok complete txn B, if NOT ok restore from trash |
| after CP4 | normal | continue step 7 |
| step 7 half done | trash entry may exist | unlink is idempotent |

Because bytes are renamed before they are unlinked, a bad audit discovered late is
survivable. The price is that space is not freed until the quarantine ends; policy
can shorten it to zero under real disk pressure (section 13).

## 8. Reconciliation (on every connect, and daily)
Ask the device for `LIST_MANIFESTS(since = last_device_seq)` plus presence of every
chunk each of our replicas needs.
- Ledger says COMMITTED, device agrees: fine.
- Ledger says COMMITTED/OFFLOADED, device lacks the manifest or chunks: mark
  MISSING / AT_RISK, alert loudly. If local bytes exist: re-replicate. If another
  replica exists: repair. Otherwise the file is LOST and only the user can
  acknowledge it. Never silent.
- Device has a manifest the ledger lacks (crash between 6.3 and 6.4, or ledger
  restored from backup): decrypt and verify it, check `volume_id`, then adopt and
  log "adopted".
- Device has chunks with no manifest: leave alone (aborted upload).
- `device_epoch` changed or `device_seq` went BACKWARDS: the device was restored
  or reset. Treat all its replicas as unverified and re-audit everything.
- `volume_id` mismatch: refuse to write; it belongs to another volume.

## 9. Recall (hydration)
Reads of an OFFLOADED file fetch chunks from a replica. Each blob is checked
(AEAD tag, then `HMAC(plaintext) == chunk_id`); a failure tries the next replica,
else returns EIO and logs AT_RISK. After a full hydrate, `file_hmac` is checked.
Hydrated bytes go to the origin store; the file becomes REPLICATED again and
is a cheap candidate for dropping later.

## 10. Devices and replica policy
Devices declare a durability class; unknown means the worst class.
- **A  server:** always on, fsync honoured, redundant storage. Weight 1.0.
- **B  single disk:** a Pi, a spare Mac, an external drive. Weight 1.0 but not
  counted if not audited within T_audit.
- **C  mobile/removable:** phones, laptops, USB sticks; app uninstall, "clear
  data", factory reset, or loss destroys the data. Weight 0.5, and never the sole
  replica unless the user typed the override.
Policy: sum of weights of COMMITTED, recently audited replicas >= K.
Proposed default K = 2.0. Single-copy mode exists only as an explicit per-volume
override that shows exactly what is at risk and asks for typed confirmation, with
a long quarantine.
Devices cannot prove they honour fsync, so class is user-declared with
conservative defaults (any phone is C).

## 11. Keys and recovery
- Master key MK (32 random bytes). HKDF derives K_id, K_data, K_manifest,
  K_snapshot, K_file, K_audit, K_nonce (separate labels). Stored in Keychain, not synced.
- **Recovery phrase:** MK plus an 8-byte checksum as 16 groups of `XXXXC` (Crockford base32: 4 data
  characters and 1 check character per group; I/L read as 1, O as 0); shown once. The user must re-enter
  3 randomly chosen groups before `recovery_acked` flips to true. Until then no offload (I9).
  Losing the Mac loses the Keychain; the phrase is what saves the data.
- Phones and other agents never see MK; they store ciphertext only.
- Nonces are synthetic: `HMAC(K_nonce, aad || plaintext)[:12]` (section 20). Identical input gives identical
  output; different inputs collide only if a 96-bit HMAC prefix does (about 2^-97 per pair), so there is no
  per-key message budget to track. Key rotation is still not designed.
- Not designed yet: key rotation, multi-user.

## 12. Disasters and what the user does
- **S1 Mac dead or stolen:** new Mac, `tierctl recover --device D --phrase ...` lists
  and decrypts manifests and rebuilds the tree as stubs; files hydrate on demand.
  Files that were never replicated are gone unless Time Machine has them. We can
  say "everything offloaded or replicated is recoverable", nothing more.
- **S2 Device dead:** REPLICATED files are still local, so re-replicate. OFFLOADED
  with >=2 replicas: repair from the survivor. OFFLOADED with 1 replica: LOST (the
  accepted risk of single-copy mode).
- **S3 Ledger corrupt:** restore the newest encrypted ledger snapshot from a device,
  then reconcile (adopts anything newer). Snapshots are pushed after every batch
  and hourly via SQLite's backup API.
- **S4 Old Time Machine ledger restored:** reconcile sees `device_seq` ahead of
  `last_device_seq` and adopts; it never trusts the stale ledger over the device.
- **S5 Phone app removed:** same as S2.

## 13. Disk-full safety
- At setup, preallocate `ledger.reserve` (64 MiB) beside the ledger. In an
  emergency it is released to give SQLite and the WAL room, then recreated.
- Before any offload step that needs a write: if the ledger cannot be written,
  stop (I3). The free-space poller never blocks and never writes to the ledger.
- Quarantine uses real space. Policy: normal free space -> full quarantine (7
  days proposed); free space below a critical threshold -> shortened or zero,
  only after a fresh audit. (APFS local snapshots can also keep deleted blocks
  alive; none exist on this Mac now, but `tmutil listlocalsnapshots /` belongs in
  the pre-flight check, and the UI must not promise freed space it cannot confirm.)

## 14. Testing plan (nothing deletes real data until this passes)
1. **Crash injection.** `TIERFS_CRASH_AT=CPn` calls `_exit(137)` at each named
   point; also before and after each fsync. A harness runs every scenario at every
   crash point, restarts, runs recovery, then checks the invariant checker.
2. **Invariant checker (`tierctl fsck`).** For every OFFLOADED file: >=K replicas
   whose blobs, fetched and decrypted, reproduce the recorded `file_hmac`. Ledger
   hash chain intact. LOCAL/REPLICATED files have their bytes locally. No
   intent left open.
3. **Device fault modes in the reference backend:** drop acks; ack before persisting
   (a lying device); corrupt, truncate or swap a blob; delete a manifest; roll the
   device back to an older directory copy; wrong `volume_id`; slow responses.
4. **Mutation tests** like the cache tests: delete the audit, skip the CAS, unlink
   before the ledger commit, ignore a MISSING replica. Each must make a test fail.
5. **Real power loss cannot be automated.** Residual risk is covered by F_FULLFSYNC
   and ordering, and stated plainly in the README.
6. Only the throwaway `testdata/` tree until the user explicitly says otherwise.

## 15. Build order (Phase 3)
- 3a Ledger library: schema, hash-chained events, CAS transactions, full-fsync
  commits, reserve file, `fsck`. Unit tests.
- 3b Crypto layer: chunk ids, AEAD, manifests; known-answer tests.
- 3c Device store in the reference backend (protocol v3: HAS_CHUNKS, PUT_CHUNK,
  PUT_MANIFEST, AUDIT, LIST_MANIFESTS, GET_CHUNK, DEVICE_INFO) plus fault modes.
- 3d Replicate engine and reconciliation (including adoption). **Still deletes
  nothing.**
- 3e Drop-local with crash points, then the full fault-injection suite.
  Deletion is switched on only when 3e passes.
- 3f Tiering policy: cold detection from `last_access`, thresholds, consent prompt.
- 3g `tierctl recover` and the disaster drills S1 to S4.
Also needed first: the origin store (the overlay that holds local bytes) must exist
before anything can be dropped; today the mount only serves a remote tree.

## 16. Decisions (accepted 2026-10-11: "go with the recommendations")
1. **K = 2.0** replica weight required before any local deletion. Single-device mode
   exists only as a per-volume override: typed confirmation, shows what is at risk,
   forces the full quarantine period.
2. **Quarantine 7 days** by default, shortened (never skipped without a fresh audit)
   only when free space is below the critical threshold.
3. **Background replication of cold candidates** is on: the emergency path is
   "audit, then drop". Bandwidth/battery limits come with the tiering policy (3f).
4. **Encrypted at rest with a recovery phrase**, acknowledged before the first
   offload (I9).
5. **Backup before first real offload.** OWNER ACTION: configure Time Machine (or any
   backup) for this Mac. Until the owner records `backup_acked` in the ledger, offload
   of anything outside `testdata/` is refused. (None is configured today.)

## Open technical questions
- AES-GCM via OpenSSL (installed) or CryptoKit; 1 MiB vs 4 MiB upload chunks.
- Android: can `FileDescriptor.sync()` be trusted on all flash? Probably not; class C.
- Partial offload (keep the first N MiB local for previews and mmap)? Later.
- Garbage collection of remote data (mark and sweep from manifests with a grace
  period) is deliberately excluded from Phase 3.

## 17. Phase 3a status: the ledger library (implemented)
Code: `core/ledger.{hpp,cpp}`, `core/crashpoint.hpp`. Tests: `tests/ledger_test.cpp`
(about 200 checks), `tests/ledger_helper.cpp`, `scripts/mutate-ledger.py`.
Run: `make test-unit`, `python3 -I scripts/mutate-ledger.py`.

What exists
- Schema of section 4 plus: `versions.generation` (snapshot for compare-and-swap),
  `files.prior_state`, a unique index allowing one open DROP_LOCAL intent per file,
  and triggers that abort every UPDATE/DELETE on `events` and every DELETE on the
  other tables (the engine can have bugs; it cannot erase history).
- Opens with WAL, `synchronous=FULL`, `fullfsync=ON`, `checkpoint_fullfsync=ON` and
  reads each setting back; refuses to run if any did not take.
- Never wipes or repairs: garbage file, failed `integrity_check`, unknown schema
  version, or a database with tables but no version all make `open()` fail with the
  file left byte-for-byte untouched. One process per ledger (flock).
- Hash-chained, length-prefixed events appended inside the same transaction as the
  change they describe. `fsck()` checks SQLite integrity, foreign keys, the chain,
  contiguous sequence numbers, and the state invariants of section 5.
- Every transition is a compare-and-swap (`UPDATE ... WHERE state=? AND generation=?`
  checked with `sqlite3_changes`). Replica transitions follow an allowed-transition
  table; a replica cannot be COMMITTED without the device's sequence number.
- **`begin_drop` enforces I1, I3, I8, I9 itself, in one IMMEDIATE transaction:**
  recovery phrase acknowledged; backup acknowledged OR path under `test_prefix`;
  ledger reserve present; positive policy; consent exists, unexpired, covers the
  path; file REPLICATED at that exact version and generation with bytes local; replica
  weight (A=1, B=1, C=0.5; retired devices excluded; audits must be younger than
  `max_audit_age` and non-zero) >= `min_weight`. Any failure rolls back untouched.
- `complete_drop` re-checks the replica evidence (a late failed audit, or a recovery
  that took hours, cannot slip through). `abort_drop` restores REPLICATED.
- Losing the last committed replica of an OFFLOADED file moves it to AT_RISK
  automatically; `clear_at_risk` refuses unless a committed replica or local bytes exist.
- Named crash points (`TIERFS_CRASH_AT`) at both commits of the drop protocol.
- `snapshot_to()` (VACUUM INTO) for the encrypted snapshots pushed to devices.

How it was verified
- Crash injection: a freshly spawned helper process dies (`_exit(137)`) at each point;
  the restarted ledger is checked for state, intents and `fsck`, then recovery runs.
- Tamper tests: forged but self-consistent event rows, dropped triggers, deleted
  events, rows edited behind the ledger's back (generation, replica states, states
  the API cannot reach). `fsck` or the next operation catches each.
- **Mutation testing: 31 mutants, each removing one safety rule (consent expiry, weight
  check, generation compare, triggers, chain check, ...). All 31 killed.**

What testing taught us (so we do not repeat it)
- A flaky failure turned out to be macOS: `fork()` without `exec` in a process that
  has used sqlite/os_log crashes intermittently (`_os_log_preferences_refresh`).
  Crash tests now spawn a fresh helper process, which is also closer to a real crash.
- My first mutation script counted a *crashed* test run as "mutant survived" because
  a segfault prints no FAIL line. A crash now counts as a kill, and a flaky test is
  treated as a bug in its own right (stress-run 100x, plain and sanitized).
- Six mutants first survived: three were genuine gaps (redundant guards that only
  matter on tampered data, the chain-link check, unasserted event kinds). Writing
  tests for them is what finally made the suite deterministic.
- The refusal-test macro initially dereferenced an empty `optional` (undefined
  behaviour that ASan did not flag). Test code is code.

Not done yet (next): 3b crypto layer, 3c device store + protocol v3 with fault modes,
3d replicate engine + reconciliation, 3e the drop-local engine (quarantine, audit by
challenge, crash points around the filesystem steps), 3f policy, 3g recovery tool.

## 18. Phase 3b status: the crypto layer (implemented)
Code: `core/crypto.{hpp,cpp}`, `core/keychain_mac.cpp`. Tests: `tests/crypto_test.cpp` (106
checks), vectors generated by `scripts/gen_crypto_kat.py` into `tests/crypto_kat.hpp`,
mutation script `scripts/mutate-crypto.py`. Run: `make test-unit`.

What exists
- OpenSSL 3 (static `libcrypto.a`, so only macOS system libraries are needed at run time):
  AES-256-GCM, HMAC-SHA256, HKDF-SHA256 (hand-written per RFC 5869 over HMAC), RAND.
- Master key -> HKDF -> six independent keys (id, data, manifest, snapshot, file, audit).
- Chunks: `chunk_id = HMAC(K_id, plaintext)`; blob `0x01 || nonce(12) || ct || tag(16)`,
  AAD binds `volume_id` and `chunk_id`. `open_chunk` authenticates, then re-derives the id
  from the plaintext, so a blob is accepted only if it IS the chunk that was asked for.
- Manifests: same AEAD under K_manifest; AAD binds volume, file id and version; the body
  is also checked against the requested slot; trailing bytes, oversized fields and xattr
  caps (1 MiB each, 4 MiB total) are rejected.
- Nonces (changed in 3d): a synthetic IV, `HMAC(K_nonce, aad || plaintext)[:12]`, so sealing is
  deterministic. See section 20 for why. (3b originally used random nonces with a per-key budget.)
- `FileHmac` (streaming whole-file check), audit nonces/responses (see section 7).
- Recovery phrase encode/decode with per-group typo pinpointing, a global checksum,
  forgiving input, and a confirm-3-random-groups helper.
- `SecretKey` is move-only and wiped on destruction; `KeyStore` interface with a
  development file store (0600, refuses group-readable files, never overwrites, rejects
  hostile volume ids) and a login-Keychain store ("this device only", never overwrites).

How it was verified
- Published vectors: SHA-256, RFC 4231 (HMAC), RFC 5869 cases 1 and 3 (HKDF), NIST GCM
  test case 16.
- **An independent implementation**: `gen_crypto_kat.py` contains a from-scratch pure-Python
  AES-GCM, first checked against NIST cases 13 and 16, which then produced 8 more vectors
  (sizes 0, 1, 15, 16, 17, 255, 1000, 4096) that the C++ code must reproduce byte for byte.
  This guards against misusing OpenSSL (AAD order, tag position, nonce handling), not just
  against broken math.
- Attack tests: every bit-flip class (header, nonce, ciphertext, tag), truncation,
  extension, wrong key/volume/chunk id/file/version, an authentic blob whose content is
  not its claimed chunk, chunk-for-manifest confusion, nonce uniqueness over 20,000 seals,
  concurrent sealing, key wiping (inspecting the storage after the destructor).
- Mutation testing: 36 mutants, each removing one protection (AAD parts, tag check,
  nonce randomness, label separation, id check, slot check, phrase checks, wipe,
  keystore guards, ...). All killed. One mutant (trailing bytes in a manifest) first
  survived; the missing test was written.
- ThreadSanitizer clean; 40 stress runs clean.

Design corrections found while building (so the doc matches the code)
1. **Audits.** The earlier text compared the device's `SHA256(nonce || blob)` with a stored
   blob hash. That is impossible: SHA-256 of nonce plus blob cannot be computed from the
   blob's hash. Fixed in section 7: one-time nonces derived from K_audit with responses
   precomputed at upload (4 per chunk), then a full verified fetch to refresh the pool.
   The ledger needs a `chunk_challenges` table for this (added in 3e; no real ledgers
   exist yet, so no migration).
2. **Recovery phrase** is 16 groups of base32, not 24 words: I would not trust a
   word list typed from memory, and per-group check characters give better error
   messages than a word list does.

Not done / decisions left for later
- The Keychain store compiles but its test is opt-in (`TIERFS_TEST_KEYCHAIN=1`): it writes
  and deletes one item in the login Keychain and could raise a macOS permission prompt, so
  it should only run with the owner's say-so. It has NOT been run.
- Key rotation, multi-user, and wrapping the master key with a user passphrase are not designed.
- OpenSSL's EVP_MAC API is not in BoringSSL (Android); the primitives are isolated in
  `crypto.cpp` so only that file changes for a port.

## 19. Phase 3c status: the device side (implemented)
Code: `core/devicestore.{hpp,cpp}` (the storage logic), `backend/device_server.cpp` (`tierfs-device`),
`core/deviceclient.{hpp,cpp}` (what the Mac uses), `core/net.hpp` (shared connect helper). Protocol:
`proto/PROTOCOL.md`, "Device protocol (version 3)". Tests: `tests/devicestore_test.cpp` (store),
`tests/devicenet_test.cpp` (real server process, real client, real encryption), `tests/device_helper.cpp`
(crash injection), `scripts/mutate-device.py`, `scripts/tsan-device.sh`. Run: `make test-unit`, `make test-device`.

What exists
- A device that stores chunks and manifests durably (temp, full fsync, rename, directory fsync, then
  the index row), append-only (triggers), with an exclusive lock, a free-space reserve, upload hash
  checks, download self-checks, a commit-sequence log, volume binding, and challenge audits that
  read the disk at the moment of the request.
- "Existed" semantics: the device keeps the first copy of anything it already has and reports the hash
  of what it actually holds. With deterministic sealing (section 20) a retry is byte-identical, so
  "existed with the same hash" means the same bytes; a different hash means a conflict, which the
  replicate engine reports instead of assuming.
- A server that validates every id (never a path), bounds every count, drops idle connections,
  caps connections, refuses to listen beyond loopback without an explicit flag, and rejects unknown
  fault names.
- A client with whole-request deadlines (a device that trickles its reply is cut off), one safe retry
  on a stale connection (all operations are idempotent), and paged `has_chunks`.
- Fault modes for the tests: lie about storing, rot a byte, truncate, serve the wrong chunk, lose a
  manifest, disk full, slow, drop the connection after executing (a lost ack).

How it was verified
- Crash injection (spawned helper process dies at each durability step): a renamed file with no index
  row stays invisible and is replaced on retry; a transaction killed before commit rolls back the
  manifest AND its sequence bump together, so the sequence has no gaps; after commit everything is
  retrievable and a repeat returns "existed".
- Every fault is shown to be detectable by the Mac: lies and rot via audits, wrong-chunk answers via the
  AEAD binding, lost acks via "existed" on retry, rollback via epoch + seq, full disk via ENOSPC with
  nothing half-recorded.
- Hostile clients: requests before HELLO, wrong protocol version, unknown types, absurd counts, lying
  lengths, a four-billion-id request, truncated payloads, a 4 GB frame length, path-like ids, 80 idle
  connections. The server stays up and serves normally afterwards.
- Mutation testing: 46 mutants over store, server and client. All killed except 3 that remove an fsync
  (a missing fsync is only observable by cutting power) and 1 proven equivalent (the stored-size check
  duplicates the hash check). Several test bugs were found and fixed along the way (see below).
- ThreadSanitizer clean on the store, the client and the server process (141 + 107 checks);
  38 stress runs without a failure.

Findings along the way
1. **Hostile files on disk.** A multi-gigabyte file at a chunk path would have been read entirely into
   memory before being judged. Reads are now capped (15 MiB) before allocation; tested with a 2 GiB sparse file.
2. **Test code, again.** After a failed check a test indexed an empty vector and crashed instead of
   reporting. All assertion indexing now goes through bounds-safe helpers. A crash that prints no FAIL
   line must never be mistaken for a pass, so the mutation script treats crashes as kills.
3. **A check that was not a check.** My first ThreadSanitizer command silently built nothing (shell word
   splitting) yet printed "0 warnings". It is now a script that verifies each binary exists and counts the
   passes, and it reads the server process's log too.
4. **Untestable by design:** the three power-loss mutants. Durability here rests on the documented
   fsync ordering and F_FULLFSYNC, not on a test. An honest remaining risk, listed in the README.

Not done / next
- 3d: replicate engine (seal, upload, verify "existed", commit manifests, finish replication in the
  ledger) and reconciliation (adopt, rollback detection, MISSING/AT_RISK).
- 3e: drop-local engine using audits; the ledger's `chunk_challenges` table (precomputed audit responses).
- No authentication or TLS: loopback only, by enforcement, not by convention.
- Files above ~225 GiB need manifest splitting.

## 20. Phase 3d status: the replicate engine and reconciliation (implemented)
Code: `core/replicator.{hpp,cpp}`; ledger additions in `core/ledger.*`; sealing change in `core/crypto.*`.
Tests: `tests/replicator_test.cpp` (real files, device process, ledger and crypto; 316 checks),
`tests/repl_helper.cpp` (crash injection), `scripts/mutate-replicator.py`. Run: `make test-replicator`.
It deletes nothing: local bytes stay, remote data is append-only. What it produces is the evidence the
dangerous drop step (3e) depends on.

Design change made first: **deterministic sealing.** The nonce is now `HMAC(K_nonce, aad || plaintext)[:12]`
(a synthetic IV). The same chunk or manifest always seals to the same bytes. That makes a crashed
upload resume byte-for-byte, lets "the device already has it" be checked by comparing hashes, removes the
random-nonce budget, and means the engine never has to stage blobs on disk. Cost: equal plaintexts give
equal blobs, which the content-derived chunk id already reveals by design. Verified against the
independent pure-Python AES-GCM build of the complete blob; 40/40 crypto mutants killed.

How a file is replicated
1. **pass 1 (plan):** read the file, cut 1 MiB chunks, compute each chunk id and sealed-blob hash; confirm
   the file did not change; ledger `begin_replication` records the plan BEFORE anything is sent.
2. **pass 2 (upload):** re-read, re-seal, check each chunk still equals the plan (else the file changed:
   `note_local_modified` and nothing is committed); upload what the device lacks; every chunk the device
   claims to have already is AUDITED with a fresh secret nonce, never trusted; a random sample of newly
   uploaded chunks is audited too. A final snapshot of the file catches modification of an already-read chunk.
3. **commit:** seal the manifest, record its hash in the ledger first, upload it, audit it, then ledger replica
   COMMITTED and REPLICATING -> REPLICATED. Whenever the engine holds a blob it tops up that chunk's pool of
   one-time audit challenges (4 per chunk and for the manifest).
Failure handling: a timeout leaves the replica PENDING/UPLOADED (retryable); evidence of lying or conflict
(failed audit, different bytes under the same id, different manifest for a version) marks the replica MISSING.

Reconciliation (`reconcile`): list the device's whole commit log and compare with the ledger.
- A manifest on the device whose hash equals the one the ledger recorded is **adopted** (this is the crash
  between "device committed" and "ledger recorded"); a different hash is a **conflict**; a version the ledger
  does not know is **reported, never adopted**.
- A committed replica whose manifest the device no longer lists becomes MISSING (and, if it was the last
  one, the file falls back or goes AT_RISK).
- A device found rolled back (same epoch, lower sequence) or re-initialised (new epoch) becomes **suspect**: its
  replicas stop counting, dependent files fall back to REPLICATING / AT_RISK, and the engine refuses to use it.
  It earns standing back only when EVERY replica it still claims passes a challenge audit; one failure keeps
  it suspect. Catching up in sequence number alone does not clear it.
- `audit_replica` spends one-time challenges; when a chunk's pool is used up it downloads and verifies the real
  bytes (AEAD, id, hash) and mints a fresh pool.

Ledger changes this needed: device epoch/sequence/suspect state; `chunk_challenges` (each usable once, a used row
cannot be revived, enforced by trigger); manifest hash recorded once per version; and a rule that a REPLICATED
file whose last committed replica is lost goes back to REPLICATING (an OFFLOADED one to AT_RISK) so the
invariants stay true. 51 ledger mutants killed.

Crash injection: the process dies at `after_begin`, `mid_upload`, `before_manifest`, `after_manifest_put`
(recovered both by a plain re-run and by reconcile-then-run) and `before_finish`; every time the ledger passes
fsck, the file ends REPLICATED, the device holds exactly the 5 chunks and one manifest (nothing duplicated or
lost), the data downloads and verifies byte-for-byte, and a full audit passes.

What testing taught us
- Each mutation batch found real gaps, now tests: growth of a file between plan and upload (only the size check
  sees it), rewriting an already-uploaded chunk (only the final snapshot sees it), a manifest the device
  acknowledges but does not keep, a device that rolled back between two calls, a suspect device that caught up
  in sequence number, refetch verification (needs a device whose bytes are intact but wrong), recall of a manifest
  that decrypts but does not add up, a corrupted plan.
- A harness lesson: a mutant killed only by a crash may be a flaky crash hiding a survivor. The script now
  reruns crash-only kills and trusts the second result.
- Challenge pools were not topped up after a repair until a test showed the audit path running dry.

Limits / not done
- Files over ~225 GiB need manifest splitting; the engine refuses them up front.
- `verify_chunks` (16) samples newly uploaded chunks before commit. That is a smoke test, not proof: a device that
  lies about chunk 17 of 100 can slip through until the full pre-drop audit in 3e.
- A device that once lied (its index claims chunks its disk lacks) stays unusable for those chunks: append-only
  means we cannot overwrite them. Replicating elsewhere is the remedy.
- Authentication and TLS are still absent: loopback only.
- Next: 3e (drop-local engine: quarantine, fresh full audit under freeze, the ledger's two-transaction protocol
  with crash points around the filesystem steps) and only then policy (3f) and recovery (3g).

## 21. Phase 3e status: the drop-local engine (implemented)
Code: `core/dropengine.{hpp,cpp}`, `core/fsutil.hpp` (durable filesystem operations), quarantine bookkeeping in
`core/ledger.*`. Tests: `tests/dropengine_test.cpp` (219 checks; real files, two real device processes, a real
ledger, real encryption, a real second volume), `tests/drop_helper.cpp` (crash injection),
`scripts/mutate-dropengine.py` + `scripts/dropengine_mutants.py`. Run: `make test-dropengine`.
This is the only code that makes local bytes go away, and it never deletes in the same step as it decides.

The protocol, as built
- **drop** (moves, never deletes): freeze writers -> verify that the LOCAL file still equals the replicated
  version chunk by chunk (chunk id, length, sealed-blob hash, total size) -> fresh audit of every reachable replica ->
  ledger `begin_drop` (consent, replica weight, audit freshness, gates, generation: one transaction) -> prepare the
  quarantine (same volume, durable directory, a plain-text note beside the bytes) -> re-check the file's identity
  (size, mtime to the nanosecond, inode) -> ONE atomic rename into quarantine + sync of both directories -> ledger
  `complete_drop` (which re-checks the evidence) -> unfreeze. If `complete_drop` refuses, the bytes are moved back.
- **purge** (the deletion): fresh audits -> ledger `begin_purge` (retention elapsed unless emergency; replica weight from
  audits younger than `max_audit_age`, ALWAYS, including in an emergency; the file must not be AT_RISK; all gates) ->
  unlink -> `complete_purge`. The ledger records the intent BEFORE the unlink.
- **restore**: ledger `begin_restore` -> verify the quarantined bytes against the plan -> rename back (never over an
  occupied path) -> `complete_restore`. Bytes that no longer match come back as LOCAL data with a new generation, never
  as "REPLICATED".
- **recover()** after any crash: a DROPPING intent whose bytes never left is abandoned (and the file re-checked for
  modifications meanwhile); one whose bytes moved is completed after re-auditing, or put back if the replicas no longer
  suffice; bytes in both places, or in neither with unverifiable replicas, are reported and left alone. Interrupted
  purges are finished, interrupted restores are finished or reported.

Invariant, tested at every crash point (7 for drop, 4 for purge, 3 for restore): the original bytes exist somewhere
recoverable (original path, quarantine, or verified replicas), the ledger passes fsck, and recovery converges.

What the tests showed (so the code and the doc agree)
- **A real bug found by the race test:** on detecting a modification just before the move, the engine told the ledger
  "file modified" BEFORE withdrawing the drop; the ledger rightly refuses that while a drop is open, so the file ended up
  marked REPLICATED with local bytes that no longer matched. Order reversed (withdraw, then mark modified).
- A drop must not trust only remote evidence: the local bytes are re-read and compared with the plan, because a
  modification the filesystem layer failed to report would otherwise be destroyed.
- Recovery after a crash must re-audit, not reuse the evidence seen before the crash: a test rots a replica during
  the crash window and requires the bytes to be restored instead of the drop completed.
- Testing the "same volume" rule needed a real second volume: the test creates a RAM disk (no privileges needed) and
  removes it, also on a fail-fast exit.
- Two flaky tests were really bugs in the tests (assuming a position in an id-sorted list; two worlds on one port).
- Mutation testing: 39 mutants, 35 killed. Expected survivors: removing the directory syncs (power-loss only), a
  chunk-hash check that the chunk-id check also covers, and `move_back`'s overwrite guard that `restore` checks first.

What is NOT done
- **Nothing in the mounted filesystem calls this yet.** The mount today is the read-only remote view (Phases 1-2); the
  overlay with an origin store, the freeze gate (refuse writers), and what appears at a dropped file's path are the
  filesystem layer's job (policy 3f / the write phase). `FileGate` is the contract that layer must satisfy.
- Quarantined bytes still occupy disk until purge; freeing space needs the retention period or an emergency purge.
- Power-loss durability rests on the fsync ordering, not on a test.
- Next: 3f (policy: cold detection, thresholds, background replication, the consent prompt) and 3g (recovery tool
  and the disaster drills). Real-file use stays off until the owner has set up backups.

## 22. Phase 3f status: the policy layer (implemented)

`core/spaceprobe.*` (how much room is there), `core/policy.*` (when to move files and which), `Ledger::committed_weight`.
The policy decides; it never deletes. Every byte that goes away still goes through the drop engine and its ledger gates.

Measuring space
- The figure is macOS's "available for important usage" (what Finder and the OS's own low-disk warning use), because it
  counts purgeable space the system will reclaim itself; offloading files to cover space the OS would free anyway is
  pointless. When the OS gives no answer the raw `statvfs` figure is used. APFS local snapshots (`tmutil`) are counted
  and reported: they keep deleted blocks alive, so freed space may not show up until they are thinned.
- Levels: LOW when free < max(20 GiB, 15% of the volume); CRITICAL when free < max(8 GiB, 5%). The target is the LOW
  threshold x 1.25 (headroom), so one run does not leave the machine one download away from LOW again.
  (On the author's machine, 5 GiB free of 228 GiB, that is CRITICAL.)

Which files
- Only inside **managed roots** the user opted in (empty list: nothing is eligible). Roots match as whole path prefixes
  ending in `/`, so `/Projects/` never covers `/Projects2/`. Excluded substrings (default `.git`) and tierfs's own
  bookkeeping are never touched.
- Eligible: LOCAL / REPLICATING / REPLICATED, bytes present locally, at least 1 MiB, and idle (no access AND no
  modification) for 30 days. Idle time is `now - max(last_access, mtime)`.
- Files with too few trusted devices to ever reach weight 2.0 are not candidates at all (the plan says so).
- Ranking: size x days idle, biggest-and-coldest first, until the need is met or 500 files. Everything left out is
  counted with the reason, and a plan that cannot reach the target says so.

Plan, approval, execution
- A plan is immutable and stamped with a SHA-256 digest over its content (files, generations, sizes, roots, mode, time).
- `approve(plan)` verifies the digest and creates ONE expiring consent per root (1 hour), whose text records the digest,
  the counts, the root and the mode. Consents are scoped: a file under another root cannot use them.
- `execute(plan, approval)` refuses a plan whose digest does not match its approval, or whose mode differs. For each
  file it re-checks at that moment: still tracked, same generation and size, still cold, still in a managed root, state
  still allowed, a consent exists for its root. Then it copies to the required weight if needed and calls the drop
  engine. A changed file is skipped, never moved.
- LOW keeps the 7-day quarantine; the space is freed when `purge_due` runs after it. CRITICAL plans carry `free_now`:
  the executor purges right after the drop, but through the same fresh audits (emergency purge). A rotten replica blocks
  even that: the bytes stay in quarantine.

Background work (`tick`)
- Reconcile with the devices hourly; copy cold files (7 days idle) to devices within a byte budget (coldest first, never
  touching the local files); purge quarantine whose period is over (switchable); and, when space is short, build a plan
  and prompt the user (macOS notification via `osascript`, text only).
- Prompts are rate-limited by state kept in the ledger, so a restart does not re-nag: the same level at most every 6 h,
  but a worse level at once; back to OK resets it. `tick` never moves a file on its own.

- Execution also looks at the file itself (`stat` size against the plan) and re-reads the ledger record after copying,
  because the ledger only knows what the filesystem layer reported; the replicator copies whatever is on disk.
  A file edited behind the ledger's back is skipped, never dropped under an approval for the old content.

What the tests showed
- Mutation testing: 103 mutants of `policy.cpp`; the first run left 43 survivors, i.e. 43 test gaps (floors on small
  volumes, root prefix matching, idle boundary, ranking, per-field digest coverage, consent scoping, retired devices,
  states such as DROPPING, purge failing after a successful move, prompt boundaries, the no-notifier path). All were
  closed with tests. 8 survive by design: a pair of guards that cover each other (generation vs post-copy re-check;
  policy retention vs engine retention), a state that fsck forbids, a redundant size check, one equivalent mutant, an
  idempotent re-copy, and a write racing an upload. One test also found a real behaviour question (prompting after the
  level improved) which changed the code: the rate limit is now "at most once per interval at the same or a better level".
- Mutants killed by fail-fast `_exit` skip the test's destructors and each left a ~27 MB temp directory: ~100 of them
  filled the disk and made even the shell tool fail. The mutation script now cleans `/tmp` after every mutant.
- A second `World` in one scope reused the first one's device ports and silently produced an empty plan; scoping each
  world fixed it. (The failure looked like a policy bug: the check "approve() refuses an empty plan" caught it.)
- Several cases assumed the ranking could use a last-access time older than the mtime; activity is the later of the two.

What is NOT done
- The mounted filesystem does not call any of this yet (overlay/origin store, write-freeze gate, what appears at a
  dropped path). There is no daemon or approval UI; `format_plan` is the text such a UI would show.
- The Keychain test and real-file use still wait for the owner (backups first).
- Next: 3g (recovery tool and disaster drills).

## 23. Phase 3g status: disaster recovery (implemented)

`core/recovery.*` (library), `tierctl restore` and `tierctl ledger-status`, `tests/recovery_test.cpp` (the disaster drills).

The scenario: the Mac is gone. No ledger, no keys, no cache, no files. What survives is the recovery phrase (paper) and
the devices. Everything needed is on the devices, sealed under keys derived from the phrase: each manifest carries the
file's path, size, mode, mtime, extended attributes and chunk list, and the device itself remembers which volume it
belongs to (the volume id is needed to open anything, and it is not secret).

`tierctl restore --out DIR --device host:port [--device ...] [--phrase-file F | phrase on stdin] [--dry-run] [--only /prefix/]`
- Read-only towards the devices (INFO, LIST_MANIFESTS, GET_MANIFEST, GET_CHUNK): no BIND, nothing written or deleted there.
  Never overwrites anything on the Mac: an existing identical file is "already present", a different one is a conflict and
  is left alone, so the command can be re-run (and resumed) safely.
- The phrase is never an argument (process lists, shell history): a file, a hidden prompt on a terminal, or a pipe. Case,
  spaces and dashes are forgiven; a typo is pinpointed to its group; a valid phrase for another volume is detected because
  no manifest opens (nothing is written).
- Chunks are taken from whichever device has a good copy, chunk by chunk, so rot on A and loss on B in different chunks of
  the same file still restores it. A device that lies (answers with the wrong chunk) is skipped because every chunk is
  authenticated against its id and re-checked against the file's whole-file HMAC.
- If the newest version of a file cannot be rebuilt from anything, the newest older version that can is restored, and the
  report says so (exit code 3). Files that cannot be rebuilt at all are listed as FAILED; nothing half-written remains.
- Paths in manifests are treated as hostile: `..`, NUL/control characters, the recovery temp-file namespace and any path
  component that is a symlink are refused and reported; setuid/setgid bits from a manifest are never applied; a file with
  a lying whole-file HMAC or size is refused.
- Each file is written to a temp file, fsynced (F_FULLFSYNC), moved into place with an exclusive rename, and the directory
  is synced. A kill at any point leaves either nothing or a whole file; a rerun clears its own leftovers.
- Space is checked before the first byte is written (needed + a 256 MiB reserve vs free); refused with nothing written.
- Exit codes: 0 everything recovered, 3 incomplete (failures, conflicts, refused paths, older versions), 1 nothing done.

`tierctl ledger-status <ledger-dir>`: files by state, devices, whether the phrase and a backup were acknowledged, open steps
(an interrupted drop/purge/restore: finished or undone at the next start), quarantine counts, `fsck`. Exit 3 if anything
needs attention. It refuses (exit 1) while another process holds the ledger and creates nothing for a missing ledger.

What is NOT recovered by this
- The ledger itself (replication state, audits): after total loss the files come back, but a fresh ledger would be a new
  volume. Re-adopting the old volume id so the same devices keep serving the new Mac is a later feature.
- Deleted files stay on the devices (append-only) and are restored too; a tombstone mechanism does not exist yet.

What the drills showed
- The drills are in `tests/recovery_test.cpp`: total loss (with some files already offloaded), a replaced device,
  bridged damage, a chunk lost everywhere, an unrecoverable newest version, every kind of wrong phrase, hostile manifests
  (including a symlink planted in the output), kills mid-restore, an undersized target (a real RAM disk), a lying device,
  mixed volumes, a catalogue larger than one listing page, damaged manifests, and `ledger-status` on a healthy ledger, a
  busy one, a missing one and one with a crashed drop.
- Mutation testing of `recovery.cpp`: 92 mutants; the first pass left 26 test gaps (an unreachable device counted as alive,
  duplicate paths overwriting each other, damaged manifests ending the search early, an exact space fit refused, a symlink at
  the destination, bridging a chunk from a device that never held the manifest, the reason reported for a failed file...),
  all closed. 8 survivors are expected: two power-loss syncs, three races (a destination appearing during the restore, a
  stale temp file), an optimisation (size check before the hash), a regular-file partial write, and a check that
  `open_chunk` makes redundant.
- A same-port pitfall again (two labs in one scope); and the mutation harness was too slow run serially, so it now runs
  mutants in parallel (own ports and temp dir per worker via TIERFS_TEST_PORT / TIERFS_TEST_TMP).

## 24. Phase 3h design: connecting the engines to the filesystem (the overlay)

Until now the mount is a read-only view of a remote tree (Phases 1-2) and the ledger/engines (3a-3g) are libraries
nothing calls. 3h joins them. It is built as a library first (`core/overlay.*`, no FUSE in it, fully testable with real
devices) and only then wrapped by the FUSE driver. Slices: 3h-1 read side, 3h-2 write side + write gate + hydration,
3h-3 namespace operations + scanner, 3h-4 the FUSE wrapper, the daemon and end-to-end mount tests.

Layout
- **Origin**: the real folder that holds the local bytes. The overlay is mounted over the same path (verified in Phase 1),
  so the driver reaches the origin through a directory file descriptor opened BEFORE mounting (the library takes a path;
  the driver will pass `/dev/fd/N`-style access). Nothing is moved or renamed to set this up.
- **Bookkeeping** lives inside the origin in `.tierfs/` (quarantine, hydration temp files): same volume, so the drop is one
  atomic rename. The overlay hides `.tierfs` completely (not listed, not openable, not creatable).
- **Logical path** = a configured prefix + the path relative to the origin (`/Users/me/Projects/` + `a/b.txt`). It is what the
  ledger and the manifests store.

What a path is
- A directory is always a real directory in the origin (directories are never offloaded).
- A file that is present in the origin is a **local file**; its attributes come from the origin.
- A file that is absent from the origin but tracked in the ledger in a state whose bytes are elsewhere (DROPPING after the
  rename, OFFLOADED, HYDRATING, AT_RISK) is a **remote file**: it is listed, `stat`s with the ledger's size/mtime/mode, and
  its contents are read from the devices. Anything else is ENOENT.

Reading a remote file
- Partial reads: the ledger holds the chunk list of the version (id, length), so offset -> chunk is arithmetic. Only the chunks a
  read touches are fetched, from a device holding a committed replica first, then any other device. Every chunk is
  authenticated (AEAD bound to its id), its length and its id (HMAC of the plaintext) are re-checked, so a lying or rotted
  device is simply skipped and another is tried; if none has a good copy the read fails with EIO (never wrong bytes).
- Verified chunks are kept in an in-memory LRU keyed by chunk id (content-addressed, so nothing ever needs invalidating).

Writing, and the write gate (3h-2)
- Opening for write registers the writer first, THEN records the modification in the ledger (generation + 1, state LOCAL), THEN
  opens the file. The drop engine's `FileGate::freeze` refuses while any writer is registered and, once frozen, makes new
  write-opens wait (bounded) until the drop finishes. Closing a writer records the final size/mtime again (so a replication
  that raced the last writes can never be treated as current).
- Writing to a remote file hydrates it first: from the quarantine copy when one is still HELD for that version (local rename +
  re-verification, no network), else by streaming and verifying the version from the devices into a temp file and renaming
  it into place. A crash mid-hydration is resolved at start (temp removed; a completed rename is re-verified chunk by chunk
  against the ledger before it is trusted).

Namespace operations (3h-3)
- The ledger mirrors the origin; the origin is the authority for what exists locally and the ledger is the authority for what
  exists remotely. unlink/rename/mkdir/rmdir/chmod/utimens act on the origin and then update the ledger; a scanner at start
  (and periodically) reconciles anything done behind our back (new files tracked, changed files marked modified, vanished
  files flagged, never silently forgotten).
- Deleting or renaming a file does not erase what the devices hold (they are append-only): a deleted file stays recoverable by
  `tierctl restore` until a tombstone mechanism exists. This is stated, not hidden.
- Operations on a remote file that would need its bytes (chmod/utimens/xattrs/rename-over) are handled by hydrating, or refused
  with a clear errno in the first slices; unlink of a remote file is refused until deletion semantics are settled.

Failure semantics
- Network failures surface as EIO (FUSE-T maps other errnos to misleading ones; Phase 2 finding).
- A remote read never blocks the metadata path: getattr/readdir use the ledger and the origin only.

Status of 3h-1 (the read side, implemented): `core/overlay.*` and `tests/overlay_test.cpp` (122 checks).
- `getattr`, `readdir`, `read`, `readlink` over the origin and the ledger; local files are served from the origin, remote
  files (DROPPING after the rename, OFFLOADED, HYDRATING, AT_RISK) from the devices, chunk by chunk, verified, with failover
  and an LRU of verified plaintext chunks (least recently USED is evicted). The bookkeeping directory is invisible; paths with
  `..`, NUL or a relative form are refused; names with SQL wildcard characters work (the ledger query is a byte range).
- Tests show: dropped files keep their listing, attributes and bytes (whole-file reads in awkward piece sizes, ranges across
  chunk boundaries, at EOF); a read inside one chunk fetches exactly that chunk and a read ending on a boundary does not
  touch the next; a rotted or missing chunk fails only the reads that need it, with EIO, never short or wrong; one dead
  device is bridged by the other; a device that lies is skipped; a retired device is never asked; with every device down
  getattr/readdir still work and only reads fail; a power cut in the middle of a drop leaves the file readable from the
  devices; eight threads reading at once all get exact bytes.
- Mutation testing: 85 mutants, 17 expected survivors (equivalent or paired guards, a self-contradicting ledger, a race).
  The first pass found 8 gaps (stable ordering, readlink errno, a vanished file must not be guessed at, retired/null/uncommitted
  device handling, LRU recency, the chunk-boundary fetch count).
- Found on the way: `open_chunk` already checks the plaintext against the chunk id, so the extra HMAC check I had added in both
  the overlay and recovery is redundant (kept as defence in depth, tagged as such in the mutant lists).
Next: 3h-2, the write side (write gate, hydration on write), then 3h-3 namespace operations and the scanner, then 3h-4 the
FUSE wrapper.
