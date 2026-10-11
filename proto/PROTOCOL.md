# tierfs wire protocol, version 1 (DRAFT, Phase 1)

Status: **plaintext TCP, read-only, no authentication.** The backend binds to
127.0.0.1 by default for that reason. TLS with pinned keys (mutual auth) and
pairing are the next protocol step and must land before binding to a LAN
address.

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
| 0x04 | READ    | str path, u64 off, u32 len   | raw bytes (0..len, empty at/after EOF) |
| 0xFF | ERROR   | (reply only, any request)    | i32 errno, str message                 |

`ATTR` = `u8 is_dir` (0/1), `u64 size`, `i64 mtime` (unix seconds), `u32 mode`
(permission bits only).

Errors use POSIX errno numbers as the server's OS defines them. (Both ends are
currently macOS or Linux; the numbers differ between them for some codes, so a
portable errno table is an open item before a Linux backend is paired with a
Mac.)

## Connection behaviour
- Client sends HELLO first. Version mismatch: server replies ERROR (EPROTO)
  and closes.
- Requests are processed in order per connection (no pipelining yet; the id
  field exists so pipelining can be added without a format change).
- Clients apply a socket timeout (default 3 s) and surface it as a filesystem
  error rather than hanging the application.

## Planned (not in v1)
PutChunk / Commit / Delete (writes), content-hash chunk addressing, Subscribe
(change notifications), Heartbeat, TLS 1.3 + pairing, agent-initiated
connections for phones.
