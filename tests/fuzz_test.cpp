// Fuzzing of everything that reads bytes or text from outside: the wire reader, frame decoder, secure-channel handshake and sealed frames, the recovery
// phrase, the discovery record and device entries, service options, the control socket, and the device server itself (open and paired, over real sockets).
//
// This is a deterministic fuzzer, not libFuzzer (Apple's clang does not ship it): a seeded generator makes inputs from valid examples by structure-aware
// mutation (bit flips, extreme lengths, truncation, splicing) and from nothing. It runs under ASan/UBSan, so an out-of-bounds read or an undefined shift is
// a failure even when the program would carry on. Besides "does not crash" it checks PROPERTIES: what a parser accepts must be valid and re-encode to the same
// thing; no single flipped bit of a sealed frame is accepted; no single typo in a recovery phrase is accepted; a server survives everything and still answers.
//
//   TIERFS_FUZZ_SEED=N      (default: time-based; always printed, so a failure can be replayed)
//   TIERFS_FUZZ_SCALE=N     multiplies the iteration counts (default 1; about a minute under ASan)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <set>

#include "../core/crypto.hpp"
#include "../core/daemon.hpp"
#include "../core/deviceclient.hpp"
#include "../core/devicestore.hpp"
#include "../core/discovery.hpp"
#include "../core/securechannel.hpp"
#include "../core/service.hpp"
#include "../core/wire.hpp"

extern char** environ;
using namespace tierfs;
namespace fs = std::filesystem;
using crypto::Bytes;

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
// For properties checked thousands of times: report the first few violations, count them all, print one PASS line for the lot.
static std::atomic<int> g_prop_bad{0};
#define PROP(cond, what)                                                                   \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            if (g_prop_bad++ < 5) printf("      violated at line %d: %s\n", __LINE__, what); \
        }                                                                                  \
    } while (0)
static void report(const char* name, long runs) {
    static time_t last = time(nullptr);
    time_t now = time(nullptr);
    CHECK(g_prop_bad == 0);
    printf("      %s: %ld inputs, %lds\n", name, runs, static_cast<long>(now - last));
    last = now;
    g_prop_bad = 0;
}

// ---------------------------------------------------------------- generator

struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed * 0x9E3779B97F4A7C15ull + 0x1234567) { next(); next(); }
    uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    uint64_t below(uint64_t n) { return n ? next() % n : 0; }
    bool chance(int percent) { return below(100) < static_cast<uint64_t>(percent); }
    Bytes bytes(size_t n) {
        Bytes v(n);
        for (auto& b : v) b = static_cast<uint8_t>(next());
        return v;
    }
};

static const uint32_t EXTREME[] = {0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff, 0x80000000u, 0xfffffffe, 0xffffffffu, 1u << 24, (16u << 20) + 1};

// One to four structure-blind mutations of a valid example.
static Bytes mutate(Bytes v, Rng& r) {
    int n = 1 + static_cast<int>(r.below(4));
    for (int k = 0; k < n; k++) {
        switch (r.below(8)) {
            case 0:
                if (!v.empty()) v[r.below(v.size())] ^= static_cast<uint8_t>(1u << r.below(8));
                break;
            case 1:
                if (!v.empty()) v[r.below(v.size())] = static_cast<uint8_t>(r.next());
                break;
            case 2: {   // a length-like field overwritten with an extreme value
                if (v.size() >= 4) {
                    size_t at = r.below(v.size() - 3);
                    uint32_t x = EXTREME[r.below(sizeof EXTREME / sizeof EXTREME[0])];
                    int w = 1 + static_cast<int>(r.below(4));
                    for (int i = 0; i < w && at + i < v.size(); i++) v[at + i] = static_cast<uint8_t>(x >> (8 * (w - 1 - i)));
                }
                break;
            }
            case 3:
                v.resize(r.below(v.size() + 1));   // truncation
                break;
            case 4: {
                Bytes ins = r.bytes(1 + r.below(16));
                v.insert(v.begin() + static_cast<long>(r.below(v.size() + 1)), ins.begin(), ins.end());
                break;
            }
            case 5:
                if (!v.empty()) {
                    size_t a = r.below(v.size()), len = 1 + r.below(std::min<size_t>(16, v.size() - a));
                    v.erase(v.begin() + static_cast<long>(a), v.begin() + static_cast<long>(a + len));
                }
                break;
            case 6:
                if (!v.empty()) {   // splice a piece of itself somewhere else
                    size_t a = r.below(v.size()), len = 1 + r.below(std::min<size_t>(16, v.size() - a));
                    Bytes piece(v.begin() + static_cast<long>(a), v.begin() + static_cast<long>(a + len));
                    v.insert(v.begin() + static_cast<long>(r.below(v.size() + 1)), piece.begin(), piece.end());
                }
                break;
            default:
                if (v.size() < (1u << 16)) v.insert(v.end(), r.below(64), static_cast<uint8_t>(r.chance(50) ? 0xff : 0x00));
        }
    }
    return v;
}
static std::string mutate_text(const std::string& s, Rng& r) {
    Bytes b(s.begin(), s.end());
    Bytes m = mutate(b, r);
    return std::string(m.begin(), m.end());
}

static std::string rtext(Rng& r, size_t n) {
    Bytes b = r.bytes(n);
    return std::string(b.begin(), b.end());
}

static std::string tmpdir(const char* tag) {
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-fuzz-" + tag + "-XXXXXX";
    std::vector<char> buf(t.begin(), t.end());
    buf.push_back(0);
    return mkdtemp(buf.data());
}
static uint16_t port_base() { return getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9571; }

// ---------------------------------------------------------------- a device server to attack

struct Server {
    pid_t pid = 0;
    uint16_t port;
    explicit Server(uint16_t p) : port(p) {}
    bool start(const std::string& store, const std::vector<std::string>& extra = {}) {
        std::vector<std::string> a = {"tierfs-device", store, std::to_string(port), "127.0.0.1"};
        a.insert(a.end(), extra.begin(), extra.end());
        std::vector<char*> av;
        for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
        av.push_back(nullptr);
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
        posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
        const char* path = getenv("TIERFS_DEVICE_SERVER") ? getenv("TIERFS_DEVICE_SERVER") : "./build/tierfs-device";
        int rc = posix_spawn(&pid, path, &fa, nullptr, av.data(), environ);
        posix_spawn_file_actions_destroy(&fa);
        if (rc != 0) return false;
        for (int i = 0; i < 100; i++) {
            int fd = raw_connect();
            if (fd >= 0) { close(fd); return true; }
            usleep(50000);
        }
        return false;
    }
    bool alive() {
        if (!pid) return false;
        int st = 0;
        return waitpid(pid, &st, WNOHANG) == 0;
    }
    int raw_connect() const {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) { close(fd); return -1; }
        timeval tv{0, 30000};   // never wait long for a reply: the server may rightly say nothing
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        return fd;
    }
    void stop() {
        if (!pid) return;
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        pid = 0;
    }
    ~Server() { stop(); }
};

static Bytes frame(uint8_t type, uint32_t id, const Bytes& payload) {
    Writer w;
    w.u32(static_cast<uint32_t>(5 + payload.size()));
    w.u8(type);
    w.u32(id);
    w.bytes(payload.data(), payload.size());
    return w.b;
}
static void drain(int fd) {   // read and discard whatever the server says, briefly
    uint8_t buf[4096];
    for (int i = 0; i < 2; i++)
        if (read(fd, buf, sizeof buf) <= 0) break;
}
static void send_all(int fd, const Bytes& b) {
    size_t off = 0;
    while (off < b.size()) {
        ssize_t n = send(fd, b.data() + off, b.size() - off, 0);
        if (n <= 0) return;
        off += static_cast<size_t>(n);
    }
}

// Valid request payloads of every device message, to mutate.
static std::vector<std::pair<uint8_t, Bytes>> request_seeds() {
    std::vector<std::pair<uint8_t, Bytes>> v;
    auto hash = [](Writer& w) { for (int i = 0; i < 32; i++) w.u8(static_cast<uint8_t>(i)); };
    { Writer w; w.u16(DEVICE_PROTO_VERSION); v.push_back({MSG_HELLO, w.b}); }
    v.push_back({MSG_DEV_INFO, {}});
    { Writer w; w.str(std::string(32, 'a')); v.push_back({MSG_DEV_BIND, w.b}); }
    { Writer w; w.u32(2); w.str(std::string(64, 'a')); w.str(std::string(64, 'b')); v.push_back({MSG_DEV_HAS_CHUNKS, w.b}); }
    { Writer w; w.str(std::string(64, 'c')); hash(w); Bytes blob(100, 7); w.blob(blob.data(), blob.size()); v.push_back({MSG_DEV_PUT_CHUNK, w.b}); }
    { Writer w; w.str(std::string(64, 'c')); v.push_back({MSG_DEV_GET_CHUNK, w.b}); }
    { Writer w; w.str(std::string(32, 'f')); w.i64(1); hash(w); Bytes blob(60, 9); w.blob(blob.data(), blob.size()); w.u32(1); w.str(std::string(64, 'c')); v.push_back({MSG_DEV_PUT_MANIFEST, w.b}); }
    { Writer w; w.str(std::string(32, 'f')); w.i64(1); v.push_back({MSG_DEV_GET_MANIFEST, w.b}); }
    { Writer w; w.u64(0); w.u32(100); v.push_back({MSG_DEV_LIST_MANIFESTS, w.b}); }
    { Writer w; w.u32(1); w.u8(0); w.str(std::string(64, 'c')); w.i64(0); for (int i = 0; i < 32; i++) w.u8(1); v.push_back({MSG_DEV_AUDIT, w.b}); }
    { Writer w; w.u32(1); w.str(std::string(32, 'f')); w.i64(1); v.push_back({MSG_DEV_DELETE_MANIFESTS, w.b}); }
    v.push_back({MSG_DEV_GC_STATUS, {}});
    { Writer w; w.u64(3600); w.u32(10); w.u8(1); v.push_back({MSG_DEV_SWEEP, w.b}); }
    return v;
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    uint64_t seed = getenv("TIERFS_FUZZ_SEED") ? strtoull(getenv("TIERFS_FUZZ_SEED"), nullptr, 10) : static_cast<uint64_t>(time(nullptr));
    int scale = getenv("TIERFS_FUZZ_SCALE") ? std::max(1, atoi(getenv("TIERFS_FUZZ_SCALE"))) : 1;
    printf("fuzz seed %llu scale %d (replay: TIERFS_FUZZ_SEED=%llu)\n", (unsigned long long)seed, scale, (unsigned long long)seed);
    Rng r(seed);
    long runs;

    {
        printf("== the wire reader never reads outside its buffer\n");
        runs = 0;
        for (int i = 0; i < 20000 * scale; i++, runs++) {
            Bytes buf = r.bytes(r.below(80));
            Reader rd(buf);
            try {
                for (int op = 0; op < 24; op++) {
                    switch (r.below(8)) {
                        case 0: rd.u8(); break;
                        case 1: rd.u16(); break;
                        case 2: rd.u32(); break;
                        case 3: rd.u64(); break;
                        case 4: rd.str(); break;
                        case 5: rd.blob(r.chance(50) ? 64 : (1u << 20)); break;
                        case 6: rd.i64(); break;
                        default: rd.need(r.below(100));
                    }
                    PROP(rd.pos <= rd.n, "the reader moved past the end");
                }
            } catch (const std::exception&) {
            }
        }
        report("reader", runs);
    }

    {
        printf("== read_grow: the bytes that were sent, however many, and memory only as they arrive\n");
        for (size_t n : {size_t(0), size_t(1), size_t(65535), size_t(65536), size_t(65537), size_t(200000), size_t(1u << 20) + 3}) {
            int sv[2];
            CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
            Bytes data = r.bytes(n);
            std::thread w([&] { send_all(sv[0], data); });
            std::vector<uint8_t> got;
            CHECK(read_grow(sv[1], got, n, now_ms() + 5000) == 1 && got == data);
            w.join();
            close(sv[0]);
            close(sv[1]);
        }
        {   // the peer goes away part-way: an error, not a short buffer; away at the start: a clean 0
            int sv[2];
            CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
            Bytes part = r.bytes(70000);
            std::thread w([&] { send_all(sv[0], part); close(sv[0]); });   // (a socket holds far less than 70000 bytes: it needs a reader to finish)
            std::vector<uint8_t> got;
            errno = 0;
            CHECK(read_grow(sv[1], got, 100000, now_ms() + 5000) == -1 && errno == ECONNRESET);
            w.join();
            close(sv[1]);
            CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
            close(sv[0]);
            CHECK(read_grow(sv[1], got, 100000, now_ms() + 5000) == 0);
            close(sv[1]);
            // a peer that announces a huge length and sends nothing costs one step of memory, and the deadline ends the wait
            CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
            int64_t t0 = now_ms();
            CHECK(read_grow(sv[1], got, 16u << 20, now_ms() + 150) == -1 && errno == EAGAIN && got.capacity() < (1u << 20) && now_ms() - t0 < 2000);
            close(sv[0]);
            close(sv[1]);
        }
    }

    {
        printf("== frames read from a socket: any bytes, never a crash or a hang\n");
        runs = 0;
        for (int i = 0; i < 3000 * scale; i++, runs++) {
            int sv[2];
            CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
            Bytes in = r.chance(50) ? r.bytes(r.below(64)) : mutate(frame(MSG_DEV_PUT_CHUNK, 7, r.bytes(r.below(40))), r);
            if (in.size() > 60000) in.resize(60000);
            send_all(sv[0], in);
            close(sv[0]);   // EOF after the bytes: a short frame must end the read, not wait
            Frame f;
            int rc = recv_frame(sv[1], f, now_ms() + 2000);
            PROP(rc == 1 || rc == 0 || rc == -1, "odd result");
            if (rc == 1) PROP(f.payload.size() + 5 <= MAX_FRAME, "a frame larger than the limit was accepted");
            close(sv[1]);
        }
        report("frames", runs);
    }

    {
        printf("== the discovery record and device entries: what is accepted is valid and re-encodes the same\n");
        runs = 0;
        discovery::Advert good;
        good.key_id = "0123456789abcdef";
        good.paired = true;
        Bytes seed_txt = discovery::encode_txt(good);
        for (int i = 0; i < 40000 * scale; i++, runs++) {
            Bytes t = r.chance(20) ? r.bytes(r.below(80)) : mutate(seed_txt, r);
            discovery::Advert a;
            if (discovery::parse_txt(t.data(), t.size(), &a)) {
                PROP(a.key_id.empty() || discovery::valid_key_id(a.key_id), "accepted a bad key id");
                PROP(!a.paired || !a.key_id.empty(), "accepted a paired device without a key id");
                Bytes again = discovery::encode_txt(a);
                discovery::Advert b;
                PROP(!again.empty() && discovery::parse_txt(again.data(), again.size(), &b) && b.key_id == a.key_id && b.paired == a.paired, "does not round-trip");
            }
            std::string spec = r.chance(25) ? std::string("mdns:") + rtext(r, r.below(30)) : mutate_text("mdns:kitchen-pi@0123456789abcdef", r);
            std::string err;
            if (auto m = discovery::parse_mdns_spec(spec, &err)) {
                PROP(discovery::valid_key_id(m->key_id), "accepted a bad key id in a spec");
                PROP(m->name.empty() || discovery::valid_instance_name(m->name), "accepted a bad name in a spec");
                PROP(discovery::is_mdns_spec(spec), "accepted something that is not an mdns: entry");
            } else {
                PROP(!err.empty(), "refused without saying why");
            }
            // choosing: whatever is picked is paired, has the key id, a host and a port
            std::vector<discovery::Found> found;
            for (int k = 0; k < 4; k++) {
                discovery::Found f;
                f.name = std::string(r.chance(70) ? "n" : "m") + std::to_string(r.below(3));
                f.host = r.chance(80) ? "h.local" : "";
                f.port = static_cast<uint16_t>(r.chance(80) ? 9100 : 0);
                f.key_id = r.chance(60) ? "0123456789abcdef" : "fedcba9876543210";
                f.paired = r.chance(60);
                found.push_back(f);
            }
            if (auto p = discovery::pick(found, "0123456789abcdef")) PROP(p->paired && p->key_id == "0123456789abcdef" && !p->host.empty() && p->port != 0, "picked a device it must not");
            std::string nm = discovery::instance_name_from_host(rtext(r, r.below(100)));
            PROP(discovery::valid_instance_name(nm), "made an invalid instance name");
        }
        report("discovery", runs);
    }

    {
        printf("== the recovery phrase: no crash on any text, and no single typo is accepted\n");
        runs = 0;
        std::string err;
        for (int i = 0; i < 300 * scale; i++) {
            crypto::SecretKey k = crypto::SecretKey::random();
            std::string phrase = crypto::encode_recovery(k);
            auto back = crypto::decode_recovery(phrase, &err);
            PROP(back && memcmp(back->data(), k.data(), 32) == 0, "a good phrase did not decode to its key");
            // every single-character substitution of the symbols, at a few places per phrase
            const std::string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
            for (int t = 0; t < 12; t++, runs++) {
                std::string p = phrase;
                size_t at = r.below(p.size());
                if (p[at] == '-') continue;
                char c = alphabet[r.below(alphabet.size())];
                if (c == p[at]) continue;
                p[at] = c;
                auto got = crypto::decode_recovery(p, &err);
                // (the phrase tolerates look-alike characters; if it accepts, it must be the SAME key)
                PROP(!got || memcmp(got->data(), k.data(), 32) == 0, "a changed phrase decoded to a different key");
            }
            // anything at all: no crash
            for (int t = 0; t < 40; t++, runs++) {
                std::string junk = r.chance(50) ? mutate_text(phrase, r) : rtext(r, r.below(120));
                auto got = crypto::decode_recovery(junk, &err);
                if (got) PROP(junk.find_first_not_of("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789- \t\r\nabcdefghijklmnopqrstuvwxyzOIL") == std::string::npos, "accepted stray characters");
            }
        }
        report("recovery phrase", runs);
    }

    {
        printf("== the secure channel: garbage handshakes are refused, and no flipped bit of a sealed frame is accepted\n");
        runs = 0;
        Bytes psk = r.bytes(chan::PSK_LEN);
        Bytes kid = chan::key_id(psk);
        auto lookup = [&](const Bytes& id) -> std::optional<Bytes> {
            if (id == kid) return psk;
            return std::nullopt;
        };
        // a real client's first message, to mutate
        chan::ClientHandshake seed_client(psk);
        Bytes seed_init = seed_client.init();
        for (int i = 0; i < 6000 * scale; i++, runs++) {
            chan::ServerHandshake sh(lookup);
            Bytes in = r.chance(25) ? r.bytes(r.below(120)) : mutate(seed_init, r);
            auto reply = sh.on_init(in);
            if (reply) {
                // accepted a (possibly altered) init: the finish must still need the secret
                Bytes fin = r.bytes(r.below(100));
                PROP(!sh.on_finish(fin), "accepted a random finish message");
            } else {
                PROP(!sh.on_finish(r.bytes(r.below(100))), "finished a handshake that never started");
            }
        }
        // sealed frames: every single bit flip of the whole wire form is refused (a fresh session pair each time: opening a bad frame kills a session)
        {
            auto pair = [&](std::optional<chan::Session>& client, std::optional<chan::Session>& server) {
                chan::ClientHandshake ch(psk);
                chan::ServerHandshake sh(lookup);
                auto reply = sh.on_init(ch.init());
                auto fin = reply ? ch.on_reply(*reply) : std::nullopt;
                server = fin ? sh.on_finish(*fin) : std::nullopt;
                client = ch.session();
                return reply && fin && server && client;
            };
            int flipped = 0;
            for (int msg = 0; msg < 4 && flipped < 800 * scale; msg++) {
                Bytes payload = r.bytes(1 + r.below(40));
                std::optional<chan::Session> c0, s0;
                CHECK(pair(c0, s0));
                Bytes wire0 = c0->seal(MSG_DEV_INFO, 10 + msg, payload);
                CHECK(!wire0.empty());
                Frame ok;
                CHECK(s0->open(wire0.data(), wire0.data() + 4, wire0.size() - 4, ok) && ok.type == MSG_DEV_INFO && ok.id == static_cast<uint32_t>(10 + msg) && ok.payload == payload);
                for (size_t bit = 0; bit < wire0.size() * 8 && flipped < 800 * scale; bit++, flipped++, runs++) {
                    std::optional<chan::Session> c, s;
                    if (!pair(c, s)) { PROP(false, "could not set up a session"); continue; }
                    Bytes w = c->seal(MSG_DEV_INFO, 10 + msg, payload);
                    w[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
                    Frame out;
                    PROP(!s->open(w.data(), w.data() + 4, w.size() - 4, out), "accepted a frame with a flipped bit");
                }
            }
            // a replayed or reordered frame is refused too
            std::optional<chan::Session> c, s;
            CHECK(pair(c, s));
            Bytes one = c->seal(MSG_DEV_INFO, 1, {1}), two = c->seal(MSG_DEV_INFO, 2, {2});
            Frame f;
            CHECK(!s->open(two.data(), two.data() + 4, two.size() - 4, f));   // out of order
            std::optional<chan::Session> c2, s2;
            CHECK(pair(c2, s2));
            Bytes a1 = c2->seal(MSG_DEV_INFO, 1, {1});
            CHECK(s2->open(a1.data(), a1.data() + 4, a1.size() - 4, f) && !s2->open(a1.data(), a1.data() + 4, a1.size() - 4, f));   // replayed
            // random wire bytes on a live session
            for (int i = 0; i < 2000 * scale; i++, runs++) {
                std::optional<chan::Session> cc, ss;
                if (!pair(cc, ss)) continue;
                Bytes w = r.bytes(4 + r.below(80));
                Frame out;
                PROP(!ss->open(w.data(), w.data() + 4, w.size() - 4, out), "accepted random bytes as a frame");
            }
        }
        report("secure channel", runs);
    }

    {
        printf("== service options and the plist: whatever validates renders into a plist the system's own parser reads\n");
        runs = 0;
        int linted = 0;
        for (int i = 0; i < 4000 * scale; i++, runs++) {
            ServiceSpec s;
            s.name = r.chance(80) ? "projects" : mutate_text("projects", r);
            s.binary = r.chance(80) ? "/Users/me/tierfsd" : mutate_text("/Users/me/tierfsd", r);
            s.mountpoint = r.chance(80) ? "/Users/me/Projects" : mutate_text("/Users/me/Projects", r);
            s.log_dir = r.chance(80) ? "/Users/me/logs" : mutate_text("/Users/me/logs", r);
            std::vector<std::pair<std::string, std::string>> o = {{"origin", "/Users/me/.tierfs/real"}, {"prefix", "/Users/me/Projects/"},
                                                                   {"ledger", "/Users/me/.tierfs/ledger"}, {"keyfile", "keychain"}};
            for (auto& kv : o) {
                if (r.chance(15)) kv.second = mutate_text(kv.second, r);
                if (r.chance(5)) kv.first = mutate_text(kv.first, r);
            }
            if (r.chance(30)) o.push_back({mutate_text("readahead", r), mutate_text("4", r)});
            s.options = o;
            std::string why = validate_service(s);
            if (why.empty()) {
                std::string plist = render_service_plist(s);
                PROP(plist.find('\0') == std::string::npos, "a NUL in the plist");
                if (linted < 25 * scale && r.chance(2)) {
                    std::string tmp = tmpdir("plist") + "/x.plist";
                    std::ofstream(tmp) << plist;
                    std::string cmd = "/usr/bin/plutil -lint '" + tmp + "' >/dev/null 2>&1";
                    bool lint_ok = system(cmd.c_str()) == 0;
                    if (!lint_ok && g_prop_bad < 3) {
                        std::string hex;
                        for (unsigned char ch : s.name + "|" + s.binary + "|" + s.mountpoint + "|" + s.log_dir)
                            hex += (ch >= 0x20 && ch < 0x7f) ? std::string(1, static_cast<char>(ch)) : "\\x" + std::to_string(ch);
                        for (auto& kv : s.options) for (unsigned char ch : kv.first + "=" + kv.second) hex += (ch >= 0x20 && ch < 0x7f) ? std::string(1, static_cast<char>(ch)) : "\\x" + std::to_string(ch);
                        printf("      plist rejected for: %s\n", hex.c_str());
                    }
                    PROP(lint_ok, "the system's plist parser rejects a validated plist");
                    fs::remove_all(fs::path(tmp).parent_path());
                    linted++;
                }
            }
        }
        PROP(true, "");
        report("service options", runs);
    }

    {
        printf("== the control socket: random commands change nothing and crash nothing\n");
        runs = 0;
        std::string root = tmpdir("daemon");
        fs::create_directories(root + "/origin");
        std::string payload(2000, 'x');
        std::ofstream(root + "/origin/a.bin") << payload;
        std::string err, ks = root + "/ks";
        std::string volume;
        {
            auto L = Ledger::open(root + "/ledger", &err);
            CHECK(L);
            volume = L->volume_id();
            CHECK(crypto::make_file_keystore(ks)->store(volume, crypto::SecretKey::random()));
        }
        DaemonConfig c;
        c.ledger_dir = root + "/ledger";
        c.origin_dir = root + "/origin";
        c.logical_prefix = "/Users/me/proj/";
        c.key_file = "dir:" + ks;
        c.maint_seconds = 0;
        c.notify = false;
        c.control_socket = "none";
        auto d = Daemon::create(c, &err);
        CHECK(d && d->start(&err));
        if (d) {
            const char* verbs[] = {"status", "scan", "replicate", "offload", "hydrate", "undelete", "tick", "plan", "approve", "gc-plan", "gc-run", "space", "",
                                   "PLAN", "plan free-now", "approve 0000000000000000", "offload /", "offload /../..", "hydrate /a.bin", "offload /a.bin"};
            for (int i = 0; i < 1500 * scale; i++, runs++) {
                std::string line = verbs[r.below(sizeof verbs / sizeof verbs[0])];
                if (r.chance(60)) {
                    line += " ";
                    switch (r.below(5)) {
                        case 0: line += "/a.bin"; break;
                        case 1: line += std::to_string(static_cast<int64_t>(r.next())); break;
                        case 2: line += "1e999"; break;
                        case 3: line += "../../etc/passwd"; break;
                        default: line += rtext(r, r.below(40));
                    }
                }
                if (r.chance(20)) line = mutate_text(line, r);
                std::string reply = d->control(line);
                PROP(!reply.empty(), "no reply");
                PROP(reply.size() < 1u << 20, "a reply of absurd size");
            }
            d->stop();
        }
        std::ifstream f(root + "/origin/a.bin");
        std::string after((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        PROP(after == payload, "a file changed or went away");
        report("control commands", runs);
        fs::remove_all(root);
    }

    {
        printf("== an open device server: mutated requests of every kind; it survives, still answers, and its store is intact\n");
        runs = 0;
        std::string root = tmpdir("dev");
        {
            Server srv(static_cast<uint16_t>(port_base() + 20));
            CHECK(srv.start(root + "/dev", {"--allow-delete"}));
            auto seeds = request_seeds();
            std::atomic<long> total{0};
            std::vector<std::thread> workers;
            for (int t = 0; t < 4; t++)
                workers.emplace_back([&, t] {   // four attackers at once, each with a generator of its own
                    Rng rt(seed * 31 + static_cast<uint64_t>(t) + 1);
                    for (int i = 0; i < 1500 * scale; i++, total++) {
                        int fd = srv.raw_connect();
                        if (fd < 0) { PROP(false, "could not connect"); break; }
                        int nframes = 1 + static_cast<int>(rt.below(4));
                        if (rt.chance(85)) send_all(fd, frame(MSG_HELLO, 1, seeds[0].second));   // mostly greeted, sometimes not
                        for (int k = 0; k < nframes; k++) {
                            auto& sd = seeds[rt.below(seeds.size())];
                            Bytes p = rt.chance(10) ? rt.bytes(rt.below(200)) : mutate(sd.second, rt);
                            uint8_t type = rt.chance(10) ? static_cast<uint8_t>(rt.next()) : sd.first;
                            Bytes fr = frame(type, static_cast<uint32_t>(2 + k), p);
                            if (rt.chance(10)) fr = mutate(fr, rt);   // and sometimes the framing itself
                            if (fr.size() > 100000) fr.resize(100000);
                            send_all(fd, fr);
                        }
                        drain(fd);
                        close(fd);
                        if (i % 100 == 99) {   // it is still there and still right
                            PROP(srv.alive(), "the server died");
                            int h = srv.raw_connect();
                            bool ok = false;
                            if (h >= 0) {
                                send_all(h, frame(MSG_HELLO, 1, seeds[0].second));
                                send_all(h, frame(MSG_DEV_INFO, 2, {}));
                                Frame f1, f2;
                                ok = recv_frame(h, f1, now_ms() + 3000) == 1 && f1.type == (MSG_HELLO | MSG_REPLY_FLAG) &&
                                     recv_frame(h, f2, now_ms() + 3000) == 1 && f2.type == (MSG_DEV_INFO | MSG_REPLY_FLAG);
                                close(h);
                            }
                            PROP(ok, "the server stopped answering a valid request");
                        }
                    }
                });
            for (auto& w : workers) w.join();
            runs = total;
            PROP(srv.alive(), "the server died");
            srv.stop();
        }
        std::string err;
        auto st = DeviceStore::open(root + "/dev", &err);   // opens only if the store passes its own integrity check
        PROP(st != nullptr, "the store is damaged after the attack");
        report("open device", runs);
        fs::remove_all(root);
    }

    {
        printf("== a paired device server: garbage and altered handshakes, then altered requests inside a real session\n");
        runs = 0;
        std::string root = tmpdir("pair");
        std::string store = root + "/dev";
        fs::create_directories(store);
        Bytes psk = r.bytes(chan::PSK_LEN);
        {
            std::ofstream(store + "/pairing.key") << crypto::to_hex(psk.data(), psk.size()) << "\n";
            chmod((store + "/pairing.key").c_str(), 0600);
        }
        {
            Server srv(static_cast<uint16_t>(port_base() + 21));
            CHECK(srv.start(store));
            chan::ClientHandshake seed_client(psk);
            Bytes seed_init = seed_client.init();
            auto seeds = request_seeds();
            for (int i = 0; i < 1500 * scale; i++, runs++) {
                int fd = srv.raw_connect();
                if (fd < 0) { PROP(false, "could not connect"); break; }
                switch (r.below(3)) {
                    case 0:
                        send_all(fd, r.bytes(r.below(300)));
                        break;
                    case 1:   // an altered AUTH_INIT inside a proper frame
                        send_all(fd, frame(chan::T_AUTH_INIT, 1, mutate(seed_init, r)));
                        break;
                    default: {   // authenticate for real, then send altered requests through the channel
                        std::string why;
                        auto ch = chan::connect_secure(fd, psk, now_ms() + 5000, &why);
                        PROP(ch != nullptr, "could not authenticate with the right secret");
                        if (ch) {
                            for (int k = 0; k < 1 + static_cast<int>(r.below(3)); k++) {
                                auto& sd = seeds[r.below(seeds.size())];
                                ch->send(sd.first, static_cast<uint32_t>(2 + k), r.chance(10) ? r.bytes(r.below(100)) : mutate(sd.second, r));
                            }
                            Frame f;
                            ch->recv(f, now_ms() + 300);
                        }
                    }
                }
                close(fd);
                if (i % 100 == 99) {
                    PROP(srv.alive(), "the server died");
                    int h = srv.raw_connect();
                    bool ok = false;
                    if (h >= 0) {
                        std::string why;
                        auto ch = chan::connect_secure(h, psk, now_ms() + 5000, &why);
                        if (ch) {
                            ch->send(MSG_HELLO, 1, seeds[0].second);
                            Frame f1;
                            ok = ch->recv(f1, now_ms() + 3000) == 1 && f1.type == (MSG_HELLO | MSG_REPLY_FLAG);
                        }
                        close(h);
                    }
                    PROP(ok, "a client with the right secret can no longer connect");
                }
            }
            PROP(srv.alive(), "the server died");
            srv.stop();
        }
        report("paired device", runs);
        fs::remove_all(root);
    }

    printf("\n%s (%d failures) [seed %llu]\n", failures ? "FAILED" : "ALL PASSED", failures, (unsigned long long)seed);
    return failures ? 1 : 0;
}
