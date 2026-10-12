# tierfs wire protocol, version 2 (DRAFT)

Status: version 3 is **plaintext TCP with no authentication**, so an unpaired device binds to 127.0.0.1 only. A paired device speaks version 4
(authenticated, encrypted; below) and may bind to a network address.

All integers are big-endian ("network byte order"). Strings are `u16 length`
followed by that many UTF-8 bytes (no NUL).

## Framing

Every message, in both directions, is one frame:

| field     | size | meaning                                          |
|-----------|------|--------------------------------------------------|
| length    | u32  | bytes that follow (type + id + payload), >= 5    |
| type      | u8   | request type, or request type OR 0x80 for a reply|
| id        | u32  | chosen by the client, echoed in the reply        |
| payload   | ...  | depends on type                                  |

`length` must not exceed 16 MiB (MAX_FRAME). A receiver that sees an invalid
length closes the connection. Reads are capped at 1 MiB (MAX_READ) per request;
the server may return fewer bytes than asked (short read), never more.

## Messages

Paths are absolute within the exported root, start with `/`, use `/`
separators, and are resolved by the server. The server rejects any path that
resolves (after symlink resolution) outside the root with EACCES.

| type | name    | request payload              | reply payload (type|0x80)              |
|------|---------|------------------------------|----------------------------------------|
| 0x01 | HELLO   | u16 version                  | u16 version, str server_name           |
| 0x02 | STAT    | str path                     | ATTR                                   |
| 0x03 | READDIR | str path                     | u32 count, count x (str name, ATTR)    |
| 0x04 | READ    | str path, u64 off, u32 len   | u64 size, i64 mtime, raw bytes (0..len, none at/after EOF) |
| 0xFF | ERROR   | (reply only, any request)    | i32 errno, str message                 |

READ's `size` and `mtime` describe the file version the bytes were read from.
The server stats the file before and after reading and retries if it changed, so
the label always matches the data. Clients key their chunk cache on it and must
discard cached chunks of any other version.

`ATTR` = `u8 is_dir` (0/1), `u64 size`, `i64 mtime` (unix seconds), `u32 mode`
(permission bits only).

Errors use POSIX errno numbers as the server's OS defines them. (Both ends are
currently macOS or Linux; the numbers differ between them for some codes, so a
portable errno table is an open item before a Linux backend is paired with a
Mac.)

## Connection behaviour
- Client sends HELLO first (client and server must speak the same version). Version mismatch: server replies ERROR (EPROTO)
  and closes.
- Requests are processed in order per connection (no pipelining yet; the id
  field exists so pipelining can be added without a format change).
- Clients apply a socket timeout (default 3 s) and surface it as a filesystem
  error rather than hanging the application.

## Device protocol (version 3)

A second protocol on the same framing, spoken by `tierfs-device` (the storage side of a replica).
HELLO carries version **3**; a version-2 client is refused and vice versa. The device stores
**ciphertext only** (see docs/DURABLE_STORE.md sections 4 and 11) and never sees keys.

Identifiers: a *chunk id* is 64 lowercase hex characters, a *file id* 32. The device rejects
anything else, so an id can never be a path. `sha256` fields are 32 raw bytes.

| type | name           | request payload                                                        | reply payload (type\|0x80)                |
|------|----------------|------------------------------------------------------------------------|-------------------------------------------|
| 0x10 | INFO           | (empty)                                                                | str device_id, u64 epoch, u64 seq, str volume_id, u64 free_bytes |
| 0x11 | BIND           | str volume_id                                                          | (empty)                                   |
| 0x12 | HAS_CHUNKS     | u32 n (<= 1024), n x str chunk_id                                      | u32 n, n x u8 (0/1)                       |
| 0x13 | PUT_CHUNK      | str chunk_id, sha256 of blob, u32-length blob                          | u8 existed, sha256 of the blob the device holds |
| 0x14 | GET_CHUNK      | str chunk_id                                                           | u32-length blob                           |
| 0x15 | PUT_MANIFEST   | str file_id, i64 version, sha256 of blob, u32-length blob, u32 n, n x str chunk_id | u8 existed, u64 seq, sha256 of the manifest the device holds |
| 0x16 | GET_MANIFEST   | str file_id, i64 version                                               | u32-length blob                           |
| 0x17 | LIST_MANIFESTS | u64 since_seq, u32 max (<= 1000)                                       | u64 epoch, u64 seq, u32 n, n x (u64 seq, str file_id, i64 version, sha256) |
| 0x18 | AUDIT          | u32 n (<= 64), n x (u8 kind 0=chunk 1=manifest, str id, i64 version, 32-byte nonce) | u32 n, n x (u8 status 0=answered 1=missing 2=unreadable, 32-byte response) |

Semantics the Mac relies on
- **An ack means durable.** The device writes a temp file, full-fsyncs it, renames it, full-fsyncs the
  directory, and only then records it in its index (also full-fsync). A crash at any point leaves
  either nothing or an invisible orphan file; never an index row without data.
- **Append-only.** There is no delete message. Re-sending an existing chunk or an existing
  (file, version) manifest is not an error: the device keeps the original and answers `existed = 1`
  with the hash of the bytes it actually holds (re-sealed data differs from the original because
  of random nonces). The caller fetches and verifies what is stored before trusting it.
- **Integrity.** Every upload carries the sha256 the sender computed; the device refuses a mismatch
  (EBADMSG). GET re-reads the file and re-checks it against the recorded hash and refuses to serve
  damaged data (EIO).
- **Manifests only over chunks the device has.** PUT_MANIFEST fails with ENOENT naming the first missing
  chunk. Each accepted manifest gets the next `seq`; `seq` never decreases (database trigger).
- **Rollback detection.** `epoch` is random and fixed when the store is created; `seq` counts
  committed manifests. The same epoch with a lower seq than the Mac last saw means the device
  was restored from an older copy.
- **Binding.** The first BIND fixes the device to one volume; another volume gets EPERM.
- **AUDIT** hashes `nonce || stored bytes`, reading the disk at that moment. The Mac checks the answer
  against a response it precomputed from the blob it sealed (docs/DURABLE_STORE.md section 7).

Errors reuse `ERROR (0xFF)` with POSIX errno values: EINVAL (bad id/size), EBADMSG (hash mismatch),
ENOENT, EIO (damaged data), ENOSPC (device full or its free-space reserve of 16 MiB), EMSGSIZE (limits),
EPERM (other volume), EPROTO (malformed request, which also closes the connection).

Limits: a frame is at most 16 MiB, so a manifest listing more than about 230,000 chunks (roughly a 225 GiB
file at 1 MiB per chunk) does not fit in one request; larger files need manifest splitting (not designed).
The server drops idle connections after 120 s and refuses connections beyond 64.

**Security status:** version 3 has no authentication and no encryption of the transport, so `tierfs-device` listens only on
127.0.0.1 unless started with `--insecure-allow-network`. Version 4 (below) adds the authenticated, encrypted channel and is in use: a device whose store holds `pairing.key` (64 hex characters, mode 0600; created
by `tierfs-device <store> --show-pairing-code`) speaks only the channel and answers a plaintext HELLO with a plain ERROR (EPERM, "this device is paired")
before hanging up; it drops a peer that has not finished the handshake within 10 s. Inside the channel the version 3 messages (HELLO first) are unchanged.
A client holding the secret (`DeviceClient`'s fourth argument) runs the handshake on every new connection; authentication failures surface as EACCES.

## Secure channel (version 4)
Specified in docs/adr/0009; implemented in `core/securechannel.*`. All integers big-endian.

Handshake, using the ordinary frame format (u32 length, u8 type, u32 id, payload), unsealed:

| type | name | payload |
|------|------|---------|
| 0x20 | AUTH_INIT (client to device) | u16 version = 4, 8-byte key id, 32-byte client ephemeral X25519 public key, 32-byte client nonce |
| 0xA0 | AUTH_REPLY (device to client) | 32-byte device ephemeral public key, 32-byte device nonce, 32-byte device confirmation |
| 0x21 | AUTH_FINISH (client to device) | 32-byte client confirmation |
| 0xA1 | AUTH_OK (device to client) | empty, **sealed** |

The key id is `HMAC-SHA256(secret, "tierfs-key-id")[0..8]`. Let `T = SHA-256("tierfs-chan-v4" || 0x00 || u16 version || key id || client pub ||
client nonce || device pub || device nonce)` and `okm = HKDF-SHA256(ikm = secret || X25519 shared secret, salt = T, info = "tierfs-chan-v4 keys", 128 bytes)`.
`okm[0..32]` seals client to device frames, `okm[32..64]` device to client, `okm[64..96]` and `okm[96..128]` key the two confirmations:
`device confirmation = HMAC(okm[96..128], T || 'S')`, `client confirmation = HMAC(okm[64..96], T || 'C')`. A low-order X25519 point (all-zero shared
secret) is refused. On a wrong client confirmation the device sends a plain ERROR (EACCES, "authentication failed") and closes; an unknown key id or a
malformed handshake is closed without an answer.

Frames after the handshake: `u32 length` then `AES-256-GCM(type u8 || id u32 || payload)` sealed with the direction's key, a 96-bit nonce made of four
zero bytes and a 64-bit big-endian counter that starts at 0 for each direction and increases by one per frame, and the 4 length bytes as additional
authenticated data; the 16-byte tag follows the ciphertext, and `length` counts both. A receiver derives the expected counter itself: a replayed, reordered,
dropped, modified or reflected frame fails authentication, after which the connection is closed. `length` is at most `MAX_FRAME + 16`.
The device protocol messages of version 3 (above) then run unchanged inside the sealed frames.

Known answers for the whole handshake and the first frames are in `tests/channel_kat.hpp`, generated independently by `scripts/gen_channel_kat.py`.

## Version history
- v4: secure channel (above).
- v3: device storage protocol (above).
- v2: READ reply gained `size` and `mtime` (needed for a correct chunk cache).
- v1: initial read-only protocol.

## Planned (not yet specified)
PutChunk / Commit / Delete (writes), content-hash chunk addressing, Subscribe
(change notifications), Heartbeat, TLS 1.3 + pairing, agent-initiated
connections for phones.
