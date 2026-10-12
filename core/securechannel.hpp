// The secure channel for the device protocol (protocol version 4). See docs/adr/0009 and proto/PROTOCOL.md.
//
// What it gives: both ends prove they know a 32-byte pairing secret (a pre-shared key), a fresh key is agreed for every connection
// from an ephemeral X25519 exchange mixed with that secret (so recorded traffic stays unreadable even if the secret leaks later),
// and every frame afterwards is AES-256-GCM sealed with a strictly increasing counter (so tampering, replay, reordering, dropping
// and reflection are all detected). Nothing in the channel is addressed by file paths or chunk ids: type and id are inside the seal.
//
// What it does not give: protection of the pairing secret itself, or hiding that a connection exists, its timing and its sizes.
//
// Handshake (plain frames, then sealed):
//   C -> S  AUTH_INIT    u16 version(4), 8-byte key id, 32-byte client ephemeral public key, 32-byte client nonce
//   S -> C  AUTH_REPLY   32-byte server ephemeral public key, 32-byte server nonce, 32-byte server confirmation
//   C -> S  AUTH_FINISH  32-byte client confirmation
//   S -> C  AUTH_OK      (sealed, empty): the server verified the client
// Keys are HKDF-SHA256(ikm = psk || X25519 shared secret, salt = SHA-256(transcript)); confirmations are HMAC over the transcript with
// a role label, so a message from one side cannot be replayed as the other's.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "crypto.hpp"
#include "wire.hpp"

namespace tierfs {
namespace chan {

using crypto::Bytes;

constexpr uint16_t VERSION = 4;
constexpr size_t PSK_LEN = 32, KEY_ID_LEN = 8, PUB_LEN = 32, NONCE_LEN = 32, CONFIRM_LEN = 32, TAG_LEN = 16;

constexpr uint8_t T_AUTH_INIT = 0x20, T_AUTH_FINISH = 0x21;  // replies are type | 0x80

// The public identifier of a pairing secret: lets a server holding several secrets pick the right one. Not secret.
Bytes key_id(const Bytes& psk);
std::string key_id_hex(const Bytes& psk);

// One direction's sealing state. Counters start at 0 and must match exactly on both ends.
class Session {
public:
    Session(crypto::SecretKey send_key, crypto::SecretKey recv_key);
    // The sealed wire form of a frame: u32 length of what follows, then AES-GCM(type u8, id u32, payload) with the length as AAD.
    // Empty on failure (payload too large).
    Bytes seal(uint8_t type, uint32_t id, const Bytes& payload);
    // `body` is what follows the u32 length. False on any authentication failure, wrong counter, or malformed input; the session is then dead.
    bool open(const uint8_t* len_prefix, const uint8_t* body, size_t body_len, Frame& out);
    bool dead() const { return dead_; }
    uint64_t sent() const { return send_ctr_; }
    uint64_t received() const { return recv_ctr_; }

private:
    crypto::SecretKey send_key_, recv_key_;
    uint64_t send_ctr_ = 0, recv_ctr_ = 0;
    bool dead_ = false;
};

// Randomness source, replaceable in tests (known-answer vectors).
using Rng = std::function<Bytes(size_t)>;

class ClientHandshake {
public:
    explicit ClientHandshake(Bytes psk, Rng rng = nullptr);
    // The AUTH_INIT payload.
    Bytes init();
    // Processes the AUTH_REPLY payload. Returns the AUTH_FINISH payload, or nullopt if the server did not prove it knows the secret.
    std::optional<Bytes> on_reply(const Bytes& reply);
    // After on_reply succeeded: the session. The first frame the server sends (AUTH_OK) must open with it.
    std::optional<Session> session();

private:
    Bytes psk_, key_id_, cpub_, cnonce_;
    Rng rng_;
    struct Impl;
    std::shared_ptr<Impl> impl_;
    std::optional<Session> session_;
    bool replied_ = false;
};

class ServerHandshake {
public:
    // `lookup` maps a key id to the pairing secret (nullopt: unknown).
    using Lookup = std::function<std::optional<Bytes>(const Bytes& key_id)>;
    explicit ServerHandshake(Lookup lookup, Rng rng = nullptr);
    // Processes AUTH_INIT; returns the AUTH_REPLY payload, or nullopt (unknown key id, wrong version, malformed).
    std::optional<Bytes> on_init(const Bytes& init);
    // Processes AUTH_FINISH; returns the session if the client proved it knows the secret.
    std::optional<Session> on_finish(const Bytes& finish);

private:
    Lookup lookup_;
    Rng rng_;
    struct Impl;
    std::shared_ptr<Impl> impl_;
    bool inited_ = false;
};

// ---- over a socket ----
// A connected, authenticated channel: send and receive whole frames.
class Channel {
public:
    Channel(int fd, Session s) : fd_(fd), s_(std::move(s)) {}
    bool send(uint8_t type, uint32_t id, const Bytes& payload, int64_t deadline_ms = 0);
    // 1 = frame, 0 = peer closed cleanly, -1 = error (errno set; EBADMSG for an authentication failure).
    int recv(Frame& f, int64_t deadline_ms = 0);
    int fd() const { return fd_; }

private:
    int fd_;
    Session s_;
};

// Runs the client side on a connected socket. Null with *why on failure (the caller closes the socket).
std::unique_ptr<Channel> connect_secure(int fd, const Bytes& psk, int64_t deadline_ms, std::string* why, Rng rng = nullptr);
// Runs the server side. Null with *why on failure (the caller closes the socket). *client_hello_type is set when the first frame was
// not an AUTH_INIT, so the caller can tell a legacy plaintext client from garbage.
std::unique_ptr<Channel> accept_secure(int fd, ServerHandshake::Lookup lookup, int64_t deadline_ms, std::string* why, int* first_type = nullptr,
                                       Rng rng = nullptr);

}  // namespace chan
}  // namespace tierfs
