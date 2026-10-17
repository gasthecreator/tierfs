// Tests of the secure channel (protocol v4): known answers from an independent reference, then everything an attacker on the wire can try.
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <signal.h>

#include <atomic>
#include <set>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "../core/securechannel.hpp"
#include "channel_kat.hpp"

using namespace tierfs;
using namespace tierfs::chan;

static int failures = 0;
static bool failfast() {
    static const bool f = getenv("TIERFS_TEST_FAILFAST") != nullptr;
    return f;
}
#define CHECK(cond)                                         \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("FAIL  line %d: %s\n", __LINE__, #cond); \
            failures++;                                     \
            if (failfast()) {                               \
                fflush(stdout);                             \
                _exit(1);                                   \
            }                                               \
        } else                                              \
            printf("PASS  %s\n", #cond);                    \
    } while (0)
#define CHECK_QUIET(cond)                                   \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("FAIL  line %d: %s\n", __LINE__, #cond); \
            failures++;                                     \
            if (failfast()) {                               \
                fflush(stdout);                             \
                _exit(1);                                   \
            }                                               \
        }                                                   \
    } while (0)

#define DL(ms) (now_ms() + (ms))  // the library takes ABSOLUTE steady-clock deadlines, like core/wire.hpp
static Bytes B(const unsigned char* p, size_t n) { return Bytes(p, p + n); }
static bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }

// A random generator that hands out fixed chunks in order (for known answers).
static Rng fixed(std::vector<Bytes> chunks) {
    auto q = std::make_shared<std::vector<Bytes>>(std::move(chunks));
    auto i = std::make_shared<size_t>(0);
    return [q, i](size_t n) {
        Bytes b = *i < q->size() ? (*q)[(*i)++] : Bytes();
        if (b.size() != n) return Bytes();
        return b;
    };
}

struct Pair {  // a completed handshake between a fresh client and server
    Session c, s;
    Bytes psk;
};
static std::optional<Pair> handshake(const Bytes& psk) {
    ClientHandshake ch(psk);
    ServerHandshake sh([&](const Bytes& id) -> std::optional<Bytes> { return id == key_id(psk) ? std::optional<Bytes>(psk) : std::nullopt; });
    Bytes init = ch.init();
    auto reply = sh.on_init(init);
    if (!reply) return std::nullopt;
    auto fin = ch.on_reply(*reply);
    if (!fin) return std::nullopt;
    auto ss = sh.on_finish(*fin);
    auto cs = ch.session();
    if (!ss || !cs) return std::nullopt;
    return Pair{std::move(*cs), std::move(*ss), psk};
}
static bool open_wire(Session& s, const Bytes& wire, Frame& f) {
    if (wire.size() < 4) return false;
    return s.open(wire.data(), wire.data() + 4, wire.size() - 4, f);
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    Bytes psk = crypto::random_bytes(32);

    printf("== known answers (an independent implementation of X25519, AES-GCM, HMAC and HKDF computed these)\n");
    {
        Bytes kpsk = B(kat_chan_psk, kat_chan_psk_len);
        CHECK(key_id(kpsk) == B(kat_chan_keyid, kat_chan_keyid_len));
        CHECK(key_id_hex(kpsk) == crypto::to_hex(kat_chan_keyid, kat_chan_keyid_len));
        ClientHandshake ch(kpsk, fixed({B(kat_chan_cseed, 32), B(kat_chan_cnonce, 32)}));
        ServerHandshake sh([&](const Bytes& id) -> std::optional<Bytes> { return id == key_id(kpsk) ? std::optional<Bytes>(kpsk) : std::nullopt; },
                           fixed({B(kat_chan_sseed, 32), B(kat_chan_snonce, 32)}));
        Bytes init = ch.init();
        CHECK(init == B(kat_chan_init, kat_chan_init_len));
        auto reply = sh.on_init(init);
        CHECK(reply && *reply == B(kat_chan_reply, kat_chan_reply_len));
        auto fin = ch.on_reply(*reply);
        CHECK(fin && *fin == B(kat_chan_finish, kat_chan_finish_len));
        auto ss = sh.on_finish(*fin);
        auto cs = ch.session();
        CHECK(ss && cs);
        if (ss && cs) {
            CHECK(cs->seal(0x02, 7, B(kat_chan_c2s_0_payload, kat_chan_c2s_0_payload_len)) == B(kat_chan_c2s_0_wire, kat_chan_c2s_0_wire_len));
            CHECK(cs->seal(kat_chan_c2s_1_type, static_cast<uint32_t>(kat_chan_c2s_1_id), B(kat_chan_c2s_1_payload, kat_chan_c2s_1_payload_len)) ==
                  B(kat_chan_c2s_1_wire, kat_chan_c2s_1_wire_len));
            CHECK(cs->seal(kat_chan_c2s_2_type, static_cast<uint32_t>(kat_chan_c2s_2_id), B(kat_chan_c2s_2_payload, kat_chan_c2s_2_payload_len)) ==
                  B(kat_chan_c2s_2_wire, kat_chan_c2s_2_wire_len));
            CHECK(ss->seal(kat_chan_s2c_0_type, static_cast<uint32_t>(kat_chan_s2c_0_id), B(kat_chan_s2c_0_payload, kat_chan_s2c_0_payload_len)) ==
                  B(kat_chan_s2c_0_wire, kat_chan_s2c_0_wire_len));
            CHECK(ss->seal(kat_chan_s2c_1_type, static_cast<uint32_t>(kat_chan_s2c_1_id), B(kat_chan_s2c_1_payload, kat_chan_s2c_1_payload_len)) ==
                  B(kat_chan_s2c_1_wire, kat_chan_s2c_1_wire_len));
            // and the other side opens exactly what the reference sealed
            Frame f;
            CHECK(open_wire(*ss, B(kat_chan_c2s_0_wire, kat_chan_c2s_0_wire_len), f) && f.type == 0x02 && f.id == 7 &&
                  f.payload == B(kat_chan_c2s_0_payload, kat_chan_c2s_0_payload_len));
            CHECK(open_wire(*ss, B(kat_chan_c2s_1_wire, kat_chan_c2s_1_wire_len), f) && f.type == 0x13 && f.id == 4294967295u && f.payload.empty());
            CHECK(open_wire(*ss, B(kat_chan_c2s_2_wire, kat_chan_c2s_2_wire_len), f) && f.payload.size() == 1280);
            CHECK(open_wire(*cs, B(kat_chan_s2c_0_wire, kat_chan_s2c_0_wire_len), f) && f.type == 0x81 && f.payload == Bytes({'O', 'K'}));
            CHECK(open_wire(*cs, B(kat_chan_s2c_1_wire, kat_chan_s2c_1_wire_len), f) && f.type == 0xFF);
            CHECK(ss->sent() == 2 && ss->received() == 3 && cs->sent() == 3 && cs->received() == 2);
        }
    }

    printf("== a normal session: every size, many frames, both directions\n");
    {
        auto p = handshake(psk);
        CHECK(p.has_value());
        Frame f;
        bool all = true;
        for (size_t n : {size_t(0), size_t(1), size_t(15), size_t(16), size_t(17), size_t(1000), size_t(65535), size_t(65536), size_t(1u << 20)}) {
            Bytes payload = crypto::random_bytes(n ? n : 1);
            payload.resize(n);
            Bytes wire = p->c.seal(0x15, static_cast<uint32_t>(n), payload);
            all = all && !wire.empty() && wire.size() == 4 + 5 + n + TAG_LEN && open_wire(p->s, wire, f) && f.type == 0x15 && f.id == n &&
                  f.payload == payload;
            Bytes back = p->s.seal(0x95, static_cast<uint32_t>(n + 1), payload);
            all = all && open_wire(p->c, back, f) && f.type == 0x95 && f.id == n + 1 && f.payload == payload;
        }
        CHECK(all);
        for (int i = 0; i < 2000; i++) {
            Bytes wire = p->c.seal(0x02, i, Bytes{uint8_t(i)});
            CHECK_QUIET(open_wire(p->s, wire, f) && f.id == static_cast<uint32_t>(i) && f.payload == Bytes{uint8_t(i)});
        }
        CHECK(p->c.sent() == 2009 && p->s.received() == 2009);
        // the largest frame the protocol allows, and one byte more
        Bytes big(MAX_FRAME - 5, 0x5a);
        Bytes wire = p->c.seal(0x02, 1, big);
        CHECK(!wire.empty() && open_wire(p->s, wire, f) && f.payload == big);
        Bytes too_big(MAX_FRAME - 4, 0x5a);
        CHECK(p->c.seal(0x02, 1, too_big).empty() && !p->c.dead());
    }

    printf("== nothing readable on the wire: type, id and payload are inside the seal\n");
    {
        auto p = handshake(psk);
        Bytes payload(200, 'A');
        Bytes wire = p->c.seal(0x13, 0x01020304, payload);
        CHECK(wire.size() == 4 + 5 + 200 + TAG_LEN);
        size_t as = 0;
        for (size_t i = 4; i + 1 < wire.size(); i++)
            if (wire[i] == 'A' && wire[i + 1] == 'A') as++;
        CHECK(as < 10);  // the plaintext does not show through
        Bytes wire2 = p->c.seal(0x13, 0x01020304, payload);
        CHECK(wire != wire2);  // the same message twice looks different
        auto q = handshake(psk);
        CHECK(q->c.seal(0x13, 0x01020304, payload) != wire);  // a new connection with the same secret has unrelated keys
    }

    printf("== tampering with ANY bit of a frame is detected, and the session is then dead\n");
    {
        Bytes payload = {'s', 'e', 'c', 'r', 'e', 't', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd'};
        size_t flips = 0, rejected = 0, dead_after = 0;
        for (size_t bit = 0; bit < 8 * (4 + 5 + payload.size() + TAG_LEN); bit++) {
            auto p = handshake(psk);
            Bytes wire = p->c.seal(0x02, 9, payload);
            wire[bit / 8] ^= static_cast<uint8_t>(1 << (bit % 8));
            Frame f;
            flips++;
            bool opened = open_wire(p->s, wire, f);
            if (!opened) rejected++;
            if (p->s.dead()) dead_after++;
        }
        CHECK(flips > 300 && rejected == flips && dead_after == flips);
    }

    printf("== replay, reordering, dropping, reflection\n");
    {
        auto p = handshake(psk);
        Frame f;
        Bytes w0 = p->c.seal(0x02, 1, Bytes{'a'}), w1 = p->c.seal(0x02, 2, Bytes{'b'}), w2 = p->c.seal(0x02, 3, Bytes{'c'});
        CHECK(open_wire(p->s, w0, f) && f.id == 1);
        CHECK(!open_wire(p->s, w0, f) && p->s.dead());  // replayed
        auto q = handshake(psk);
        Bytes v0 = q->c.seal(0x02, 1, Bytes{'a'}), v1 = q->c.seal(0x02, 2, Bytes{'b'});
        CHECK(!open_wire(q->s, v1, f) && q->s.dead());  // reordered (second first)
        (void)v0;
        auto r = handshake(psk);
        Bytes u0 = r->c.seal(0x02, 1, Bytes{'a'}), u1 = r->c.seal(0x02, 2, Bytes{'b'}), u2 = r->c.seal(0x02, 3, Bytes{'c'});
        CHECK(open_wire(r->s, u0, f) && !open_wire(r->s, u2, f) && r->s.dead());  // the middle one dropped
        (void)u1;
        (void)w1;
        (void)w2;
        // a frame the client sent cannot be fed back to the client (reflection), nor one from the server to the server
        auto t = handshake(psk);
        Bytes mine = t->c.seal(0x02, 1, Bytes{'x'});
        CHECK(!open_wire(t->c, mine, f));
        auto u = handshake(psk);
        Bytes theirs = u->s.seal(0x82, 1, Bytes{'x'});
        CHECK(!open_wire(u->s, theirs, f));
        // a dead session accepts nothing more, even a genuine frame, and seals nothing
        auto d = handshake(psk);
        Bytes good1 = d->c.seal(0x02, 1, Bytes{'g'});
        Bytes bad = good1;
        bad[6] ^= 1;
        CHECK(!open_wire(d->s, bad, f) && d->s.dead());
        CHECK(!open_wire(d->s, good1, f) && d->s.seal(0x82, 1, Bytes{}).empty());
        // frames from one connection mean nothing on another, even with the same secret
        auto e1 = handshake(psk), e2 = handshake(psk);
        Bytes cross = e1->c.seal(0x02, 1, Bytes{'z'});
        CHECK(!open_wire(e2->s, cross, f));
    }

    printf("== malformed frames\n");
    {
        auto p = handshake(psk);
        Frame f;
        Bytes wire = p->c.seal(0x02, 1, Bytes{'a', 'b', 'c'});
        Bytes truncated(wire.begin(), wire.end() - 1);
        CHECK(!open_wire(p->s, truncated, f));
        auto q = handshake(psk);
        Bytes w2 = q->c.seal(0x02, 1, Bytes{'a', 'b', 'c'});
        Bytes extended = w2;
        extended.push_back(0);
        CHECK(!open_wire(q->s, extended, f));
        auto r = handshake(psk);
        Bytes w3 = r->c.seal(0x02, 1, Bytes{});
        Bytes lying = w3;
        lying[3] = static_cast<uint8_t>(lying[3] + 1);  // the length prefix says one byte more than is there
        CHECK(!open_wire(r->s, lying, f));
        auto s = handshake(psk);
        uint8_t tiny_hdr[4] = {0, 0, 0, 10};
        uint8_t tiny_body[10] = {0};
        CHECK(!s->s.open(tiny_hdr, tiny_body, 10, f));  // shorter than a type, an id and a tag
        auto t = handshake(psk);
        std::vector<uint8_t> huge(MAX_FRAME + TAG_LEN + 1, 0);
        uint32_t hl = static_cast<uint32_t>(huge.size());
        uint8_t huge_hdr[4] = {uint8_t(hl >> 24), uint8_t(hl >> 16), uint8_t(hl >> 8), uint8_t(hl)};
        CHECK(!t->s.open(huge_hdr, huge.data(), huge.size(), f));
    }

    printf("== the handshake refuses everything that is not exactly right\n");
    {
        auto lookup_for = [](const Bytes& key) {
            return [key](const Bytes& id) -> std::optional<Bytes> { return id == key_id(key) ? std::optional<Bytes>(key) : std::nullopt; };
        };
        // wrong secret on the client: it cannot verify the server's proof
        {
            Bytes other = crypto::random_bytes(32);
            ClientHandshake ch(other);
            ServerHandshake sh([&](const Bytes&) -> std::optional<Bytes> { return psk; });  // a server that answers any key id with the real secret
            auto reply = sh.on_init(ch.init());
            CHECK(reply && !ch.on_reply(*reply) && !ch.session());
        }
        // wrong secret on the server: the client's proof does not verify there either
        {
            Bytes other = crypto::random_bytes(32);
            ClientHandshake ch(psk);
            ServerHandshake sh([&](const Bytes&) -> std::optional<Bytes> { return other; });
            auto reply = sh.on_init(ch.init());
            CHECK(reply && !ch.on_reply(*reply));
        }
        // unknown key id
        {
            ClientHandshake ch(crypto::random_bytes(32));
            ServerHandshake sh(lookup_for(psk));
            CHECK(!sh.on_init(ch.init()));
        }
        // the server's lookup returns nothing / a secret of the wrong length
        {
            ClientHandshake ch(psk);
            ServerHandshake sh([](const Bytes&) -> std::optional<Bytes> { return Bytes(31, 1); });
            CHECK(!sh.on_init(ch.init()));
            ServerHandshake sh2(nullptr);
            ClientHandshake ch2(psk);
            CHECK(!sh2.on_init(ch2.init()));
        }
        // wrong version, short, long, empty
        {
            ClientHandshake ch(psk);
            Bytes init = ch.init();
            for (int mutation = 0; mutation < 6; mutation++) {
                Bytes m = init;
                switch (mutation) {
                    case 0:
                        m[1] = 3;
                        break;  // version 3
                    case 1:
                        m[0] = 1;
                        break;  // version 260
                    case 2:
                        m.pop_back();
                        break;
                    case 3:
                        m.push_back(0);
                        break;
                    case 4:
                        m.clear();
                        break;
                    case 5:
                        m.resize(2);
                        break;
                }
                ServerHandshake sh(lookup_for(psk));
                CHECK_QUIET(!sh.on_init(m));
            }
            CHECK(true);
        }
        // a client with a secret of the wrong length cannot even start
        {
            ClientHandshake ch(Bytes(31, 7));
            CHECK(ch.init().empty());
            ClientHandshake ch2(Bytes{});
            CHECK(ch2.init().empty());
        }
        // a server handshake is single-use, and finish needs init
        {
            ClientHandshake ch(psk);
            ServerHandshake sh(lookup_for(psk));
            Bytes init = ch.init();
            CHECK(!sh.on_finish(Bytes(32, 0)));  // before init
            auto reply = sh.on_init(init);
            CHECK(reply && !sh.on_init(init));  // twice
            auto fin = ch.on_reply(*reply);
            CHECK(fin && !ch.on_reply(*reply));  // the client too
            CHECK(sh.on_finish(*fin).has_value());
            CHECK(!sh.on_finish(*fin).has_value());  // a finish cannot be replayed
        }
        // flipping any bit of the finish, or sending a short/long one, fails
        {
            ClientHandshake ch(psk);
            ServerHandshake base(lookup_for(psk));
            Bytes init = ch.init();
            auto reply = base.on_init(init);
            auto fin = ch.on_reply(*reply);
            size_t refused = 0;
            for (size_t bit = 0; bit < 8 * CONFIRM_LEN; bit++) {
                ClientHandshake c2(psk, fixed({Bytes(), Bytes()}));  // (unused: the server side below is re-run from a recorded init)
                ServerHandshake s2(lookup_for(psk));
                // a fresh server needs the same init but will answer with its own keys: so test bit flips with a fresh complete exchange
                ClientHandshake cc(psk);
                auto r2 = s2.on_init(cc.init());
                auto f2 = cc.on_reply(*r2);
                Bytes bad = *f2;
                bad[bit / 8] ^= static_cast<uint8_t>(1 << (bit % 8));
                if (!s2.on_finish(bad)) refused++;
            }
            CHECK(refused == 8 * CONFIRM_LEN);
            ServerHandshake s3(lookup_for(psk));
            ClientHandshake c3(psk);
            auto r3 = s3.on_init(c3.init());
            auto f3 = c3.on_reply(*r3);
            Bytes shorter(f3->begin(), f3->end() - 1), longer = *f3;
            longer.push_back(0);
            CHECK(!s3.on_finish(shorter));
        }
        // the roles are not interchangeable: the server's proof is not accepted as the client's
        {
            ClientHandshake ch(psk);
            ServerHandshake sh(lookup_for(psk));
            auto reply = sh.on_init(ch.init());
            Bytes server_proof(reply->begin() + PUB_LEN + NONCE_LEN, reply->end());
            CHECK(ch.on_reply(*reply).has_value());
            CHECK(!sh.on_finish(server_proof));
        }
        // a recorded reply from another connection does not work on a new one (the transcript includes the client's nonce and key)
        {
            ClientHandshake first(psk);
            ServerHandshake s1(lookup_for(psk));
            auto recorded = s1.on_init(first.init());
            ClientHandshake second(psk);
            second.init();
            CHECK(!second.on_reply(*recorded));
        }
        // replies of the wrong size, or with a corrupted proof, public key or nonce
        {
            for (int mutation = 0; mutation < 7; mutation++) {
                ClientHandshake ch(psk);
                ServerHandshake sh(lookup_for(psk));
                auto reply = sh.on_init(ch.init());
                Bytes m = *reply;
                switch (mutation) {
                    case 0:
                        m.pop_back();
                        break;
                    case 1:
                        m.push_back(0);
                        break;
                    case 2:
                        m[0] ^= 1;
                        break;  // public key
                    case 3:
                        m[PUB_LEN] ^= 1;
                        break;  // nonce
                    case 4:
                        m[PUB_LEN + NONCE_LEN] ^= 1;
                        break;  // proof
                    case 5:
                        m.back() ^= 0x80;
                        break;
                    case 6:
                        m.clear();
                        break;
                }
                CHECK_QUIET(!ch.on_reply(m));
            }
            ClientHandshake early(psk);
            CHECK(!early.on_reply(Bytes(96, 0)));  // a reply before an init
        }
        // low-order points (all-zero shared secret) are refused on both sides
        {
            ClientHandshake ch(psk);
            ServerHandshake sh(lookup_for(psk));
            Bytes init = ch.init();
            Bytes zero_pub = init;
            std::fill(zero_pub.begin() + 2 + KEY_ID_LEN, zero_pub.begin() + 2 + KEY_ID_LEN + PUB_LEN, 0);
            CHECK(!sh.on_init(zero_pub));
            ServerHandshake sh2(lookup_for(psk));
            auto reply = sh2.on_init(init);
            Bytes zero_reply = *reply;
            std::fill(zero_reply.begin(), zero_reply.begin() + PUB_LEN, 0);
            CHECK(!ch.on_reply(zero_reply));
        }
    }

    printf("== over a socket: the whole exchange, abuse of it, and deadlines\n");
    {
        auto lookup = [&](const Bytes& id) -> std::optional<Bytes> { return id == key_id(psk) ? std::optional<Bytes>(psk) : std::nullopt; };
        auto run_server = [&](int fd, std::unique_ptr<Channel>* out, std::string* why, int* first) {
            *out = accept_secure(fd, lookup, DL(3000), why, first);
        };
        // success, and an echo of many frames of many sizes in both directions at once
        {
            int sv[2];
            CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
            std::unique_ptr<Channel> srv;
            std::string swhy;
            int first = -1;
            std::thread t([&] { run_server(sv[1], &srv, &swhy, &first); });
            std::string cwhy;
            auto cli = connect_secure(sv[0], psk, DL(3000), &cwhy);
            t.join();
            CHECK(cli && srv && first == T_AUTH_INIT);
            if (cli && srv) {
                std::atomic<int> bad{0};
                std::thread echo([&] {
                    Frame f;
                    for (int i = 0; i < 300; i++) {
                        if (srv->recv(f, DL(5000)) != 1) {
                            bad++;
                            return;
                        }
                        if (!srv->send(f.type | 0x80, f.id, f.payload, DL(5000))) {
                            bad++;
                            return;
                        }
                    }
                });
                for (int i = 0; i < 300; i++) {
                    Bytes payload = crypto::random_bytes(i * 37 % 5000);
                    if (!cli->send(0x02, i, payload, DL(5000))) {
                        bad++;
                        break;
                    }
                    Frame f;
                    if (cli->recv(f, DL(5000)) != 1 || f.type != 0x82 || f.id != static_cast<uint32_t>(i) || f.payload != payload) {
                        bad++;
                        break;
                    }
                }
                echo.join();
                CHECK(bad == 0);
                // a clean close is reported as one
                close(sv[0]);
                Frame f;
                CHECK(srv->recv(f, DL(2000)) == 0);
            }
            close(sv[1]);
        }
        // wrong secret: both sides fail, with a reason that helps
        {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::unique_ptr<Channel> srv;
            std::string swhy, cwhy;
            int first = -1;
            Bytes wrong = crypto::random_bytes(32);
            // the server knows the wrong secret's id too (as if two Macs were paired), but the client lies about its secret via a different one
            auto lookup2 = [&](const Bytes&) -> std::optional<Bytes> { return psk; };
            std::thread t([&] { srv = accept_secure(sv[1], lookup2, DL(3000), &swhy, &first); });
            auto cli = connect_secure(sv[0], wrong, DL(3000), &cwhy);
            close(sv[0]);
            t.join();
            CHECK(!cli && !srv && has(cwhy, "did not prove"));
            close(sv[1]);
        }
        // a client with an unknown key id: the server closes without a word
        {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::unique_ptr<Channel> srv;
            std::string swhy, cwhy;
            std::thread t([&] {
                srv = accept_secure(sv[1], lookup, DL(3000), &swhy);
                close(sv[1]);
            });
            auto cli = connect_secure(sv[0], crypto::random_bytes(32), DL(3000), &cwhy);
            t.join();
            CHECK(!cli && !srv && has(swhy, "unknown pairing key") && has(cwhy, "closed"));
            close(sv[0]);
        }
        // a legacy plaintext client (HELLO, type 1): refused, and the server knows what it was
        {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::unique_ptr<Channel> srv;
            std::string swhy;
            int first = -1;
            Writer w;
            w.u16(3);
            send_frame(sv[0], 0x01, 1, w.b, DL(2000));
            srv = accept_secure(sv[1], lookup, DL(2000), &swhy, &first);
            CHECK(!srv && first == 0x01 && has(swhy, "not an authenticated client"));
            close(sv[0]);
            close(sv[1]);
        }
        // garbage, an absurd length, a silent peer, a peer that hangs up
        {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::string why;
            const uint8_t junk[16] = {0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
            write_full(sv[0], junk, sizeof junk, DL(1000));
            CHECK(!accept_secure(sv[1], lookup, DL(1000), &why) && !why.empty());
            close(sv[0]);
            close(sv[1]);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            auto t0 = std::chrono::steady_clock::now();
            CHECK(!accept_secure(sv[1], lookup, DL(300), &why) && has(why, "no handshake"));
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
            CHECK(ms >= 250 && ms < 3000);  // it waited its deadline, not forever and not zero
            close(sv[0]);
            CHECK(!accept_secure(sv[1], lookup, DL(1000), &why) && has(why, "closed"));
            close(sv[1]);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            close(sv[1]);
            std::string cwhy;
            CHECK(!connect_secure(sv[0], psk, DL(1000), &cwhy) && !cwhy.empty());
            close(sv[0]);
        }
        // a server that answers the handshake with an ERROR frame: the client reports its text
        {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::thread t([&] {
                Frame f;
                recv_frame(sv[1], f, DL(2000));
                Writer w;
                w.u32(1);
                w.str("go away");
                send_frame(sv[1], 0xFF, f.id, w.b, DL(2000));
            });
            std::string cwhy;
            CHECK(!connect_secure(sv[0], psk, DL(2000), &cwhy) && has(cwhy, "refused") && has(cwhy, "go away"));
            t.join();
            close(sv[0]);
            close(sv[1]);
        }
        // a frame that fails authentication after the handshake is an error, not data
        {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::unique_ptr<Channel> srv;
            std::string swhy, cwhy;
            std::thread t([&] { srv = accept_secure(sv[1], lookup, DL(3000), &swhy); });
            auto cli = connect_secure(sv[0], psk, DL(3000), &cwhy);
            t.join();
            CHECK(cli && srv);
            uint8_t forged[40];
            memset(forged, 0x41, sizeof forged);
            forged[0] = 0;
            forged[1] = 0;
            forged[2] = 0;
            forged[3] = 36;
            write_full(sv[0], forged, sizeof forged, DL(1000));
            Frame f;
            errno = 0;
            CHECK(srv->recv(f, DL(2000)) == -1 && errno == EBADMSG);
            uint8_t absurd[4] = {0x7f, 0xff, 0xff, 0xff};
            write_full(sv[0], absurd, 4, DL(1000));
            errno = 0;
            CHECK(srv->recv(f, DL(2000)) == -1);
            close(sv[0]);
            close(sv[1]);
        }
        // a server that never sends the final confirmation (hangs up after the reply)
        {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::thread t([&] {
                Frame f;
                recv_frame(sv[1], f, DL(2000));
                ServerHandshake sh(lookup);
                auto reply = sh.on_init(f.payload);
                send_frame(sv[1], T_AUTH_INIT | 0x80, f.id, *reply, DL(2000));
                recv_frame(sv[1], f, DL(2000));
                close(sv[1]);
            });
            std::string cwhy;
            CHECK(!connect_secure(sv[0], psk, DL(2000), &cwhy) && has(cwhy, "closed the connection after the handshake"));
            t.join();
            close(sv[0]);
        }
    }

    printf("== details that only a deliberately wrong peer can show\n");
    {
        auto lookup = [&](const Bytes& id) -> std::optional<Bytes> { return id == key_id(psk) ? std::optional<Bytes>(psk) : std::nullopt; };
        // nonces never repeat: the same frame sealed 600 times gives 600 different results (a repeated nonce would repeat the output)
        {
            auto p = handshake(psk);
            std::set<Bytes> seen;
            for (int i = 0; i < 600; i++) seen.insert(p->c.seal(0x02, 1, Bytes{'n', 'o', 'n', 'c', 'e'}));
            CHECK(seen.size() == 600);
        }
        // a session can be taken out of a handshake once
        {
            ClientHandshake ch(psk);
            ServerHandshake sh(lookup);
            auto reply = sh.on_init(ch.init());
            auto fin = ch.on_reply(*reply);
            CHECK(fin && ch.session().has_value() && !ch.session().has_value());
            CHECK(sh.on_finish(*fin).has_value());
        }
        // a finish that is one byte too short or too long is refused (fresh handshakes: a finish is single-use)
        for (int variant = 0; variant < 2; variant++) {
            ClientHandshake ch(psk);
            ServerHandshake sh(lookup);
            auto reply = sh.on_init(ch.init());
            auto fin = ch.on_reply(*reply);
            Bytes m = *fin;
            if (variant == 0)
                m.pop_back();
            else
                m.push_back(0);
            CHECK(!sh.on_finish(m));
        }
        // sending more than a frame can hold fails and says why; the channel stays usable
        {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::unique_ptr<Channel> srv;
            std::string swhy, cwhy;
            std::thread t([&] { srv = accept_secure(sv[1], lookup, DL(3000), &swhy); });
            auto cli = connect_secure(sv[0], psk, DL(3000), &cwhy);
            t.join();
            CHECK(cli && srv);
            errno = 0;
            CHECK(!cli->send(0x02, 1, Bytes(MAX_FRAME), DL(1000)) && errno == EMSGSIZE);
            CHECK(cli->send(0x02, 2, Bytes{'o', 'k'}, DL(1000)));
            Frame f;
            CHECK(srv->recv(f, DL(1000)) == 1 && f.id == 2);
            // frames whose declared length is below the minimum or absurdly large are protocol errors, immediately (not a wait for bytes)
            uint8_t tiny[4] = {0, 0, 0, 10};
            write_full(sv[0], tiny, 4, DL(1000));
            errno = 0;
            CHECK(srv->recv(f, DL(1000)) == -1 && errno == EPROTO);
            close(sv[0]);
            close(sv[1]);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::thread t2([&] { srv = accept_secure(sv[1], lookup, DL(3000), &swhy); });
            auto cli2 = connect_secure(sv[0], psk, DL(3000), &cwhy);
            t2.join();
            uint8_t huge[4] = {0x7f, 0xff, 0xff, 0xff};
            write_full(sv[0], huge, 4, DL(1000));
            auto t0 = std::chrono::steady_clock::now();
            errno = 0;
            CHECK(srv->recv(f, DL(3000)) == -1 && errno == EPROTO);
            CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count() < 1000);
            close(sv[0]);
            close(sv[1]);
        }
        // a peer that misbehaves in the handshake is refused by the other side; each case below breaks exactly one rule
        auto bad_server = [&](int variant, std::string* cwhy) {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::thread t([&, variant] {
                Frame f;
                recv_frame(sv[1], f, DL(2000));
                ServerHandshake sh(lookup);
                auto reply = sh.on_init(f.payload);
                send_frame(sv[1], variant == 0 ? 0x55 : (T_AUTH_INIT | 0x80), f.id, *reply, DL(2000));  // variant 0: right bytes, wrong message type
                if (variant == 0) {
                    char c;
                    read(sv[1], &c, 1);
                    return;
                }
                recv_frame(sv[1], f, DL(2000));
                auto sess = sh.on_finish(f.payload);
                if (!sess) return;
                Channel ch(sv[1], std::move(*sess));
                if (variant == 1) ch.send(0x99, f.id, Bytes{}, DL(2000));                     // a sealed final message of the wrong type
                if (variant == 2) ch.send(T_AUTH_FINISH | 0x80, f.id, Bytes{'x'}, DL(2000));  // the right type but carrying data
            });
            auto cli = connect_secure(sv[0], psk, DL(2000), cwhy);
            close(sv[0]);
            t.join();
            close(sv[1]);
            return cli != nullptr;
        };
        std::string w;
        CHECK(!bad_server(0, &w) && has(w, "unexpected answer"));
        CHECK(!bad_server(1, &w) && has(w, "unexpected final"));
        CHECK(!bad_server(2, &w) && has(w, "unexpected final"));
        // a client that sends the right bytes in a message of the wrong type, or a wrong proof: refused; a wrong proof is told so, in plain
        for (int variant = 0; variant < 2; variant++) {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::unique_ptr<Channel> srv;
            std::string swhy;
            std::thread t([&] { srv = accept_secure(sv[1], lookup, DL(2000), &swhy); });
            ClientHandshake ch(psk);
            send_frame(sv[0], T_AUTH_INIT, 1, ch.init(), DL(2000));
            Frame f;
            recv_frame(sv[0], f, DL(2000));
            auto fin = ch.on_reply(f.payload);
            if (variant == 0)
                send_frame(sv[0], 0x33, 2, *fin, DL(2000));  // right proof, wrong message type
            else
                send_frame(sv[0], T_AUTH_FINISH, 2, Bytes(32, 0x42), DL(2000));  // right type, wrong proof
            Frame answer;
            int r = recv_frame(sv[0], answer, DL(2000));
            t.join();
            CHECK(!srv);
            if (variant == 0)
                CHECK(has(swhy, "unexpected handshake message"));
            else
                CHECK(r == 1 && answer.type == 0xFF && has(swhy, "did not prove") && answer.payload.size() > 6 &&
                      std::string(answer.payload.begin() + 6, answer.payload.end()) == "authentication failed");
            close(sv[0]);
            close(sv[1]);
        }
        // an ERROR frame whose text claims to be longer than the frame is not trusted
        {
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            std::thread t([&] {
                Frame f;
                recv_frame(sv[1], f, DL(2000));
                Writer e;
                e.u32(1);
                e.u16(500);  // claims 500 bytes of text, carries 3
                e.bytes(reinterpret_cast<const uint8_t*>("abc"), 3);
                send_frame(sv[1], 0xFF, f.id, e.b, DL(2000));
            });
            std::string cwhy;
            CHECK(!connect_secure(sv[0], psk, DL(2000), &cwhy) && has(cwhy, "unreadable error"));
            t.join();
            close(sv[0]);
            close(sv[1]);
        }
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
