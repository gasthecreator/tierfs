#include "securechannel.hpp"

#include <openssl/evp.h>

#include <cerrno>
#include <cstring>

namespace tierfs {
namespace chan {
namespace {

struct PkeyDel {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;

const char LABEL[] = "tierfs-chan-v4";

Bytes cat(std::initializer_list<const Bytes*> parts) {
    Bytes out;
    for (auto* p : parts) out.insert(out.end(), p->begin(), p->end());
    return out;
}

Pkey make_private(const Bytes& raw32) { return Pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, raw32.data(), raw32.size())); }

Bytes public_of(const Pkey& k) {
    size_t n = PUB_LEN;
    Bytes pub(n);
    if (!k || EVP_PKEY_get_raw_public_key(k.get(), pub.data(), &n) != 1 || n != PUB_LEN) return {};
    return pub;
}

// X25519. Empty on any failure, including a low-order peer point (an all-zero result).
Bytes dh(const Pkey& mine, const Bytes& peer_pub) {
    if (!mine || peer_pub.size() != PUB_LEN) return {};
    Pkey peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size()));
    if (!peer) return {};
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> ctx(EVP_PKEY_CTX_new(mine.get(), nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1) return {};
    size_t n = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &n) != 1 || n != 32) return {};
    Bytes out(n);
    if (EVP_PKEY_derive(ctx.get(), out.data(), &n) != 1 || n != 32) return {};
    uint8_t zero[32] = {0};
    if (crypto::ct_equal(out.data(), zero, 32)) return {};
    return out;
}

struct Keys4 {
    crypto::SecretKey c2s, s2c;
    Bytes confirm_c, confirm_s;
    Bytes transcript;
};

// Everything both sides derive from the same inputs.
std::optional<Keys4> derive(const Bytes& psk, const Bytes& kid, const Bytes& cpub, const Bytes& cnonce, const Bytes& spub, const Bytes& snonce,
                            const Bytes& shared) {
    if (psk.size() != PSK_LEN || shared.size() != 32) return std::nullopt;
    Bytes ver = {static_cast<uint8_t>(VERSION >> 8), static_cast<uint8_t>(VERSION & 0xff)};
    Bytes label(reinterpret_cast<const uint8_t*>(LABEL), reinterpret_cast<const uint8_t*>(LABEL) + sizeof(LABEL));  // includes the NUL
    Bytes transcript_input = cat({&label, &ver, &kid, &cpub, &cnonce, &spub, &snonce});
    Bytes T = crypto::sha256(transcript_input.data(), transcript_input.size());
    Bytes ikm = cat({&psk, &shared});
    const char info[] = "tierfs-chan-v4 keys";
    Bytes okm = crypto::hkdf_sha256(ikm.data(), ikm.size(), T.data(), T.size(), reinterpret_cast<const uint8_t*>(info), sizeof(info) - 1, 128);
    if (okm.size() != 128) return std::nullopt;
    Keys4 k{crypto::SecretKey(okm.data()), crypto::SecretKey(okm.data() + 32), Bytes(okm.begin() + 64, okm.begin() + 96),
            Bytes(okm.begin() + 96, okm.end()), T};
    OPENSSL_cleanse(okm.data(), okm.size());
    OPENSSL_cleanse(ikm.data(), ikm.size());
    return k;
}

Bytes confirmation(const Bytes& key, const Bytes& T, char role) {
    Bytes msg = T;
    msg.push_back(static_cast<uint8_t>(role));
    return crypto::hmac_sha256(key.data(), key.size(), msg.data(), msg.size());
}

Bytes nonce_for(uint64_t ctr) {
    Bytes n(12, 0);
    for (int i = 0; i < 8; i++) n[4 + i] = static_cast<uint8_t>(ctr >> (56 - 8 * i));
    return n;
}

}  // namespace

Bytes key_id(const Bytes& psk) {
    const char label[] = "tierfs-key-id";
    Bytes mac = crypto::hmac_sha256(psk.data(), psk.size(), reinterpret_cast<const uint8_t*>(label), sizeof(label) - 1);
    return Bytes(mac.begin(), mac.begin() + KEY_ID_LEN);
}

std::string key_id_hex(const Bytes& psk) {
    Bytes id = key_id(psk);
    return crypto::to_hex(id.data(), id.size());
}

// ---------------------------------------------------------------- session

Session::Session(crypto::SecretKey send_key, crypto::SecretKey recv_key) : send_key_(std::move(send_key)), recv_key_(std::move(recv_key)) {}

Bytes Session::seal(uint8_t type, uint32_t id, const Bytes& payload) {
    if (dead_ || payload.size() + 5 > MAX_FRAME) return {};
    Bytes plain;
    plain.reserve(5 + payload.size());
    plain.push_back(type);
    for (int i = 3; i >= 0; i--) plain.push_back(static_cast<uint8_t>(id >> (8 * i)));
    plain.insert(plain.end(), payload.begin(), payload.end());
    uint32_t len = static_cast<uint32_t>(plain.size() + TAG_LEN);
    uint8_t aad[4] = {static_cast<uint8_t>(len >> 24), static_cast<uint8_t>(len >> 16), static_cast<uint8_t>(len >> 8), static_cast<uint8_t>(len)};
    Bytes nonce = nonce_for(send_ctr_);
    Bytes out(4 + len);
    memcpy(out.data(), aad, 4);
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> c(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int n = 0, total = 0;
    if (!c || EVP_EncryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(c.get(), nullptr, nullptr, send_key_.data(), nonce.data()) != 1 || EVP_EncryptUpdate(c.get(), nullptr, &n, aad, 4) != 1 ||
        EVP_EncryptUpdate(c.get(), out.data() + 4, &n, plain.data(), static_cast<int>(plain.size())) != 1)
        return {};
    total = n;
    if (EVP_EncryptFinal_ex(c.get(), out.data() + 4 + total, &n) != 1) return {};
    total += n;
    if (static_cast<size_t>(total) != plain.size() || EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, out.data() + 4 + total) != 1)
        return {};
    send_ctr_++;
    return out;
}

bool Session::open(const uint8_t* len_prefix, const uint8_t* body, size_t body_len, Frame& out) {
    if (dead_) return false;
    auto die = [&]() {
        dead_ = true;
        return false;
    };
    if (body_len < 5 + TAG_LEN || body_len > static_cast<size_t>(MAX_FRAME) + TAG_LEN) return die();
    uint32_t declared = (uint32_t(len_prefix[0]) << 24) | (uint32_t(len_prefix[1]) << 16) | (uint32_t(len_prefix[2]) << 8) | uint32_t(len_prefix[3]);
    if (declared != body_len) return die();
    size_t plen = body_len - TAG_LEN;
    Bytes plain(plen);
    Bytes nonce = nonce_for(recv_ctr_);
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> c(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int n = 0;
    if (!c || EVP_DecryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(c.get(), nullptr, nullptr, recv_key_.data(), nonce.data()) != 1 ||
        EVP_DecryptUpdate(c.get(), nullptr, &n, len_prefix, 4) != 1 ||
        EVP_DecryptUpdate(c.get(), plain.data(), &n, body, static_cast<int>(plen)) != 1 || static_cast<size_t>(n) != plen)
        return die();
    uint8_t tag[TAG_LEN];
    memcpy(tag, body + plen, TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1 || EVP_DecryptFinal_ex(c.get(), plain.data() + n, &n) != 1)
        return die();
    recv_ctr_++;
    out.type = plain[0];
    out.id = (uint32_t(plain[1]) << 24) | (uint32_t(plain[2]) << 16) | (uint32_t(plain[3]) << 8) | uint32_t(plain[4]);
    out.payload.assign(plain.begin() + 5, plain.end());
    return true;
}

// ---------------------------------------------------------------- client handshake

struct ClientHandshake::Impl {
    Pkey priv;
};

ClientHandshake::ClientHandshake(Bytes psk, Rng rng)
    : psk_(std::move(psk)), rng_(rng ? rng : Rng([](size_t n) { return crypto::random_bytes(n); })), impl_(std::make_shared<Impl>()) {
    key_id_ = key_id(psk_);
}

Bytes ClientHandshake::init() {
    Bytes seed = rng_(32);
    cnonce_ = rng_(NONCE_LEN);
    if (psk_.size() != PSK_LEN || seed.size() != 32 || cnonce_.size() != NONCE_LEN) return {};
    impl_->priv = make_private(seed);
    OPENSSL_cleanse(seed.data(), seed.size());
    cpub_ = public_of(impl_->priv);
    if (cpub_.size() != PUB_LEN) return {};
    Bytes out = {static_cast<uint8_t>(VERSION >> 8), static_cast<uint8_t>(VERSION & 0xff)};
    out.insert(out.end(), key_id_.begin(), key_id_.end());
    out.insert(out.end(), cpub_.begin(), cpub_.end());
    out.insert(out.end(), cnonce_.begin(), cnonce_.end());
    return out;
}

std::optional<Bytes> ClientHandshake::on_reply(const Bytes& reply) {
    if (replied_ || !impl_->priv || reply.size() != PUB_LEN + NONCE_LEN + CONFIRM_LEN) return std::nullopt;
    replied_ = true;
    Bytes spub(reply.begin(), reply.begin() + PUB_LEN), snonce(reply.begin() + PUB_LEN, reply.begin() + PUB_LEN + NONCE_LEN),
        sconf(reply.begin() + PUB_LEN + NONCE_LEN, reply.end());
    Bytes shared = dh(impl_->priv, spub);
    impl_->priv.reset();  // the ephemeral private key is not kept past the exchange
    auto k = derive(psk_, key_id_, cpub_, cnonce_, spub, snonce, shared);
    OPENSSL_cleanse(shared.data(), shared.size());
    if (!k) return std::nullopt;
    Bytes want = confirmation(k->confirm_s, k->transcript, 'S');
    if (!crypto::ct_equal(want.data(), sconf.data(), CONFIRM_LEN)) return std::nullopt;
    session_.emplace(std::move(k->c2s), std::move(k->s2c));
    return confirmation(k->confirm_c, k->transcript, 'C');
}

std::optional<Session> ClientHandshake::session() {
    std::optional<Session> s = std::move(session_);
    session_.reset();
    return s;
}

// ---------------------------------------------------------------- server handshake

struct ServerHandshake::Impl {
    std::optional<Session> session;
    Bytes expect_client_confirm;
};

ServerHandshake::ServerHandshake(Lookup lookup, Rng rng)
    : lookup_(std::move(lookup)), rng_(rng ? rng : Rng([](size_t n) { return crypto::random_bytes(n); })), impl_(std::make_shared<Impl>()) {}

std::optional<Bytes> ServerHandshake::on_init(const Bytes& init) {
    if (inited_ || init.size() != 2 + KEY_ID_LEN + PUB_LEN + NONCE_LEN) return std::nullopt;
    inited_ = true;
    uint16_t ver = static_cast<uint16_t>((init[0] << 8) | init[1]);
    if (ver != VERSION) return std::nullopt;
    Bytes kid(init.begin() + 2, init.begin() + 2 + KEY_ID_LEN), cpub(init.begin() + 2 + KEY_ID_LEN, init.begin() + 2 + KEY_ID_LEN + PUB_LEN),
        cnonce(init.begin() + 2 + KEY_ID_LEN + PUB_LEN, init.end());
    auto psk = lookup_ ? lookup_(kid) : std::nullopt;
    if (!psk || psk->size() != PSK_LEN) return std::nullopt;
    Bytes seed = rng_(32), snonce = rng_(NONCE_LEN);
    if (seed.size() != 32 || snonce.size() != NONCE_LEN) return std::nullopt;
    Pkey priv = make_private(seed);
    OPENSSL_cleanse(seed.data(), seed.size());
    Bytes spub = public_of(priv), shared = dh(priv, cpub);
    priv.reset();
    auto k = derive(*psk, kid, cpub, cnonce, spub, snonce, shared);
    OPENSSL_cleanse(shared.data(), shared.size());
    if (!k || spub.size() != PUB_LEN) return std::nullopt;
    impl_->expect_client_confirm = confirmation(k->confirm_c, k->transcript, 'C');
    Bytes sconf = confirmation(k->confirm_s, k->transcript, 'S');
    impl_->session.emplace(std::move(k->s2c), std::move(k->c2s));  // this side sends with s2c and receives with c2s
    Bytes reply = cat({&spub, &snonce, &sconf});
    return reply;
}

std::optional<Session> ServerHandshake::on_finish(const Bytes& finish) {
    if (!inited_ || !impl_->session || finish.size() != CONFIRM_LEN) return std::nullopt;
    bool ok = crypto::ct_equal(finish.data(), impl_->expect_client_confirm.data(), CONFIRM_LEN);
    std::optional<Session> s = std::move(impl_->session);
    impl_->session.reset();
    impl_->expect_client_confirm.clear();
    if (!ok) return std::nullopt;
    return s;
}

// ---------------------------------------------------------------- over a socket

bool Channel::send(uint8_t type, uint32_t id, const Bytes& payload, int64_t deadline_ms) {
    Bytes wire = s_.seal(type, id, payload);
    if (wire.empty()) {
        errno = EMSGSIZE;
        return false;
    }
    return write_full(fd_, wire.data(), wire.size(), deadline_ms);
}

int Channel::recv(Frame& f, int64_t deadline_ms) {
    uint8_t hdr[4];
    int r = read_full(fd_, hdr, 4, deadline_ms);
    if (r <= 0) return r;
    uint32_t len = (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16) | (uint32_t(hdr[2]) << 8) | uint32_t(hdr[3]);
    if (len < 5 + TAG_LEN || len > MAX_FRAME + TAG_LEN) {
        errno = EPROTO;
        return -1;
    }
    Bytes body(len);
    r = read_full(fd_, body.data(), len, deadline_ms);
    if (r <= 0) {
        if (r == 0) errno = ECONNRESET;
        return -1;
    }
    if (!s_.open(hdr, body.data(), body.size(), f)) {
        errno = EBADMSG;
        return -1;
    }
    return 1;
}

namespace {
std::string error_text(const Frame& f) {
    if (f.payload.size() < 6) return "unreadable error";
    uint16_t n = static_cast<uint16_t>((f.payload[4] << 8) | f.payload[5]);
    if (6u + n > f.payload.size()) return "unreadable error";
    return std::string(reinterpret_cast<const char*>(f.payload.data() + 6), n);
}
void send_error(int fd, uint32_t id, int err, const std::string& msg, int64_t deadline_ms) {
    Writer w;
    w.u32(static_cast<uint32_t>(err));
    w.str(msg);
    send_frame(fd, 0xFF, id, w.b, deadline_ms);
}
}  // namespace

std::unique_ptr<Channel> connect_secure(int fd, const Bytes& psk, int64_t deadline_ms, std::string* why, Rng rng) {
    auto fail = [&](const std::string& m) -> std::unique_ptr<Channel> {
        if (why) *why = m;
        return nullptr;
    };
    ClientHandshake h(psk, rng);
    Bytes init = h.init();
    if (init.empty()) return fail("cannot start the handshake");
    if (!send_frame(fd, T_AUTH_INIT, 0, init, deadline_ms)) return fail(std::string("cannot reach the device: ") + strerror(errno));
    Frame f;
    int r = recv_frame(fd, f, deadline_ms);
    if (r <= 0)
        return fail(r == 0 ? "the device closed the connection (unknown pairing key?)"
                           : std::string("no answer from the device: ") + strerror(errno));
    if (f.type == 0xFF) return fail("the device refused: " + error_text(f));
    if (f.type != (T_AUTH_INIT | 0x80)) return fail("unexpected answer to the handshake");
    auto finish = h.on_reply(f.payload);
    if (!finish) return fail("the device did not prove it holds the pairing secret (wrong secret, or not the paired device)");
    if (!send_frame(fd, T_AUTH_FINISH, 0, *finish, deadline_ms)) return fail(std::string("cannot reach the device: ") + strerror(errno));
    auto sess = h.session();
    if (!sess) return fail("handshake state error");
    auto ch = std::make_unique<Channel>(fd, std::move(*sess));
    r = ch->recv(f, deadline_ms);
    if (r < 0 && errno == EBADMSG) return fail("the device's confirmation did not verify");
    if (r <= 0) return fail("the device closed the connection after the handshake (it rejected the secret)");
    if (f.type != (T_AUTH_FINISH | 0x80) || !f.payload.empty()) return fail("unexpected final handshake message");
    return ch;
}

std::unique_ptr<Channel> accept_secure(int fd, ServerHandshake::Lookup lookup, int64_t deadline_ms, std::string* why, int* first_type, Rng rng) {
    auto fail = [&](const std::string& m) -> std::unique_ptr<Channel> {
        if (why) *why = m;
        return nullptr;
    };
    Frame f;
    int r = recv_frame(fd, f, deadline_ms);
    if (r <= 0) return fail(r == 0 ? "closed before the handshake" : std::string("no handshake: ") + strerror(errno));
    if (first_type) *first_type = f.type;
    if (f.type != T_AUTH_INIT) return fail("not an authenticated client");
    ServerHandshake h(std::move(lookup), rng);
    auto reply = h.on_init(f.payload);
    if (!reply) return fail("unknown pairing key or malformed handshake");
    if (!send_frame(fd, T_AUTH_INIT | 0x80, f.id, *reply, deadline_ms)) return fail("cannot answer the handshake");
    r = recv_frame(fd, f, deadline_ms);
    if (r <= 0) return fail("the client went away during the handshake");
    if (f.type != T_AUTH_FINISH) return fail("unexpected handshake message");
    auto sess = h.on_finish(f.payload);
    if (!sess) {
        send_error(fd, f.id, EACCES, "authentication failed", deadline_ms);
        return fail("the client did not prove it holds the pairing secret");
    }
    auto ch = std::make_unique<Channel>(fd, std::move(*sess));
    if (!ch->send(T_AUTH_FINISH | 0x80, f.id, Bytes{}, deadline_ms)) return fail("cannot finish the handshake");
    return ch;
}

}  // namespace chan
}  // namespace tierfs
