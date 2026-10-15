// tierctl: inspect, verify and clear a tierfs cache directory.
//
//   tierctl cache-info   <dir>          read-only; safe while mounted
//   tierctl cache-verify <dir>          re-hash every chunk, drop damaged ones (needs unmounted)
//   tierctl cache-clear  <dir> [--yes]  delete the caches (needs unmounted); dry run without --yes
//   tierctl restore --out <dir> --device host:port[@keyid] [--device ...] [--phrase-file F] [--store S] [--pairing-file F] [--dry-run] [--only
//   /prefix/]
//                                       get files back from the devices with only the recovery phrase
//   tierctl ledger-status <ledger-dir>  health of the ledger: files by state, open steps, quarantine, fsck
//   tierctl pair <host:port> --store keychain|dir:PATH
//                                       pair this Mac with a device: type the code the device shows (`tierfs-device <store> --show-pairing-code`);
//                                       proves the code by authenticating, then stores the secret and prints the key id to use as host:port@keyid
//   tierctl init <ledger-dir> <key-file>
//                                       create a new volume: a fresh key, shown ONCE as a recovery phrase you must write down and prove
//                                       (three groups re-typed on stdin) before anything is saved; then the ledger is created and the
//                                       phrase marked acknowledged. Refuses if either path exists.
//   tierctl check-phrase <key-file>
//                                       type or pipe your paper recovery phrase: says whether it matches the key file (nothing is changed)
//   tierctl ack-backup <ledger-dir> I-HAVE-A-BACKUP
//                                       record that a backup exists, WITH THE TIME: only files unchanged since then can be moved, and it expires (30
//                                       days).
//   tierctl check-backup [folder]
//                                       read-only: what macOS says about Time Machine (destination, latest backup, whether the folder is excluded).
//                                       It changes nothing; you still make the statement with ack-backup.
//   tierctl test-gates <ledger-dir> <test-prefix>
//                                       FOR THROWAWAY TEST LEDGERS ONLY: acknowledges the recovery phrase and treats paths under
//                                       <test-prefix> as covered by the "backup" gate, so tests can offload. Never use on real data.
//   tierctl control <ledger-dir> <command...>
//                                       send a command to a running tierfsd (status, scan, replicate PATH, offload PATH, ...)
//
// cache-clear only ever removes the files tierfs itself creates (chunks/,
// chunks.db*, meta.db*), never "everything in the directory", so pointing it at
// the wrong folder cannot delete anything else.
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <termios.h>
#include <sqlite3.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <ctime>
#include <sys/wait.h>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "../core/chunkcache.hpp"
#include "../core/keysource.hpp"
#include "../core/ledger.hpp"
#include "../core/recovery.hpp"
#include "../core/service.hpp"

namespace fs = std::filesystem;

static uint64_t dir_bytes(const fs::path& p) {
    uint64_t n = 0;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(p, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec))
        if (it->is_regular_file(ec)) n += it->file_size(ec);
    return n;
}

// Opens read-only so it never runs crash-recovery against a live mount.
static bool query_one(const std::string& db, const char* sql, long long& a, long long& b, long long& c) {
    sqlite3* h = nullptr;
    if (sqlite3_open_v2(db.c_str(), &h, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) { if (h) sqlite3_close(h); return false; }
    sqlite3_stmt* s = nullptr;
    bool ok = false;
    if (sqlite3_prepare_v2(h, sql, -1, &s, nullptr) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW) {
        a = sqlite3_column_int64(s, 0);
        b = sqlite3_column_int64(s, 1);
        c = sqlite3_column_int64(s, 2);
        ok = true;
    }
    if (s) sqlite3_finalize(s);
    sqlite3_close(h);
    return ok;
}

// Takes the exclusive lock tierfs holds while mounted. 0 = got it (fd returned).
static int lock_exclusive(const std::string& dir, int& fd) {
    fd = open((dir + "/lock").c_str(), O_CREAT | O_RDWR, 0600);
    if (fd < 0) { perror("lock"); return -1; }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        fprintf(stderr, "tierctl: %s is in use by a running tierfs mount; unmount it first\n", dir.c_str());
        close(fd);
        return -1;
    }
    return 0;
}

static std::string human(uint64_t b) {
    char buf[32];
    if (b >= (1u << 30)) snprintf(buf, sizeof buf, "%.2f GiB", b / double(1u << 30));
    else if (b >= (1u << 20)) snprintf(buf, sizeof buf, "%.1f MiB", b / double(1u << 20));
    else snprintf(buf, sizeof buf, "%llu B", (unsigned long long)b);
    return buf;
}

static bool looks_like_cache(const std::string& dir) {
    return fs::exists(dir + "/chunks.db") || fs::exists(dir + "/meta.db") || fs::exists(dir + "/chunks");
}

// The phrase is never taken from argv (process lists and shell history would keep it).
static bool read_phrase(const std::string& file, std::string& out) {
    out.clear();
    if (!file.empty()) {
        FILE* f = fopen(file.c_str(), "r");
        if (!f) { fprintf(stderr, "tierctl: cannot read %s: %s\n", file.c_str(), strerror(errno)); return false; }
        char buf[512];
        while (fgets(buf, sizeof buf, f)) out += buf;
        fclose(f);
        return true;
    }
    bool tty = isatty(0);
    struct termios old, quiet;
    if (tty) {
        fprintf(stderr, "Recovery phrase (typing is hidden): ");
        tcgetattr(0, &old);
        quiet = old;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(0, TCSANOW, &quiet);
    }
    char buf[512];
    while (fgets(buf, sizeof buf, stdin)) {
        out += buf;
        if (tty) break;   // one line when typed; a piped phrase may span lines
    }
    if (tty) { tcsetattr(0, TCSANOW, &old); fprintf(stderr, "\n"); }
    return true;
}

// "host:port" or "host:port@keyid".
struct DeviceSpec {
    std::string host, key_id;
    uint16_t port = 0;
    bool ok = false;
};
static DeviceSpec parse_device(const std::string& spec) {
    DeviceSpec d;
    std::string addr = spec;
    if (size_t at = spec.find('@'); at != std::string::npos) {
        addr = spec.substr(0, at);
        d.key_id = spec.substr(at + 1);
    }
    size_t colon = addr.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= addr.size()) return d;
    int port = atoi(addr.c_str() + colon + 1);
    if (port <= 0 || port > 65535) return d;
    d.host = addr.substr(0, colon);
    d.port = static_cast<uint16_t>(port);
    d.ok = true;
    return d;
}

// The secret from a pairing code as a device prints it.
static std::optional<tierfs::crypto::Bytes> secret_from_code(const std::string& code, std::string* err) {
    auto k = tierfs::crypto::decode_recovery(code, err);
    if (!k) return std::nullopt;
    return tierfs::crypto::Bytes(k->data(), k->data() + tierfs::crypto::KEY_LEN);
}

// A client for one device. Open devices are used as they are; a paired device needs its secret, found (in order) in the key store (host:port@keyid),
// in the pairing file (lines "host:port code"), or typed at a terminal. The secret is never stored here: restore only reads.
static std::unique_ptr<tierfs::DeviceClient> make_device_client(const std::string& spec, const std::string& store,
                                                                const std::map<std::string, std::string>& codes, int timeout_ms, std::string* err) {
    DeviceSpec d = parse_device(spec);
    if (!d.ok) {
        *err = "device must be host:port or host:port@keyid, got " + spec;
        return nullptr;
    }
    std::string hostport = d.host + ":" + std::to_string(d.port);
    tierfs::crypto::Bytes secret;
    if (!d.key_id.empty()) {
        if (store.empty()) {
            *err = spec + ": a device with a key id needs --store (where its pairing secret is kept)";
            return nullptr;
        }
        auto sec = tierfs::load_pairing_secret(store, d.key_id, err);
        if (!sec) return nullptr;
        secret = *sec;
    } else if (auto it = codes.find(hostport); it != codes.end()) {
        auto sec = secret_from_code(it->second, err);
        if (!sec) {
            *err = hostport + ": the pairing code in the pairing file is not valid: " + *err;
            return nullptr;
        }
        secret = *sec;
    }
    auto client = std::make_unique<tierfs::DeviceClient>(d.host, d.port, timeout_ms, secret);
    if (!secret.empty()) return client;
    tierfs::DevInfo info;
    tierfs::DevRes r = client->info(info);
    if (r.ok() || r.err != EPERM) return client;  // reachable open device, or some other problem the restore itself will report
    // the device says it is paired
    if (!isatty(0)) {
        *err = hostport + ": this device is paired; give its code in a --pairing-file (lines: host:port code), or run this from a terminal";
        return nullptr;
    }
    fprintf(stderr,
            "%s is paired. Pairing code (shown by `tierfs-device <store> --show-pairing-code` on that device; typing is hidden): ", hostport.c_str());
    std::string code;
    if (!read_phrase("", code)) return nullptr;
    auto sec = secret_from_code(code, err);
    for (auto& ch : code) ch = 0;
    if (!sec) {
        *err = hostport + ": " + *err;
        return nullptr;
    }
    auto paired = std::make_unique<tierfs::DeviceClient>(d.host, d.port, timeout_ms, *sec);
    r = paired->info(info);
    if (!r.ok()) {
        *err = hostport + ": " + r.msg;
        return nullptr;
    }
    return paired;
}

static int cmd_pair(int argc, char** argv) {
    const char* usage =
        "usage: tierctl pair <host:port> --store keychain|dir:PATH\n(the pairing code, shown by `tierfs-device <store> --show-pairing-code` on the "
        "device, is read from stdin, hidden on a terminal)\n";
    if (argc < 5 || std::string(argv[3]) != "--store") {
        fputs(usage, stderr);
        return 2;
    }
    DeviceSpec d = parse_device(argv[2]);
    if (!d.ok || !d.key_id.empty()) {
        fputs(usage, stderr);
        return 2;
    }
    std::string source = argv[4], err;
    if (!tierfs::keystore_for(source, &err)) {
        fprintf(stderr, "tierctl: %s\n", err.empty() ? "pairing secrets need a key store: 'keychain' or 'dir:PATH'" : err.c_str());
        return 2;
    }
    std::string code;
    if (!read_phrase("", code)) return 1;
    auto secret = secret_from_code(code, &err);
    for (auto& ch : code) ch = 0;
    if (!secret) {
        fprintf(stderr, "tierctl: the pairing code is not accepted: %s\n", err.c_str());
        return 1;
    }
    tierfs::DeviceClient client(d.host, d.port, 8000, *secret);
    tierfs::DevInfo info;
    tierfs::DevRes r = client.info(info);  // proves the code is right AND that this really is the device that holds it
    if (!r.ok()) {
        fprintf(stderr, "tierctl: could not authenticate with %s:%d: %s\nnothing was saved\n", d.host.c_str(), d.port, r.msg.c_str());
        return 1;
    }
    if (!tierfs::store_pairing_secret(source, *secret, &err)) {
        fprintf(stderr, "tierctl: %s\n", err.c_str());
        return 1;
    }
    std::string id = tierfs::chan::key_id_hex(*secret);
    printf("paired with device %s at %s:%d (key id %s)\nsecret stored in %s as %s\nuse it as:  --device %s:%d@%s   (daemon: devices=%s:%d@%s)\n",
           info.device_id.c_str(), d.host.c_str(), d.port, id.c_str(), source.c_str(), tierfs::pairing_account(id).c_str(), d.host.c_str(), d.port,
           id.c_str(), d.host.c_str(), d.port, id.c_str());
    return 0;
}

static int cmd_restore(int argc, char** argv) {
    std::string out, phrase_file, only, store, pairing_file;
    std::vector<std::string> devs;
    tierfs::RecoveryOptions opt;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        auto val = [&](std::string& dst) { if (i + 1 >= argc) { fprintf(stderr, "tierctl: %s needs a value\n", a.c_str()); return false; } dst = argv[++i]; return true; };
        std::string tmp;
        if (a == "--out") {
            if (!val(out)) return 2;
        } else if (a == "--device") {
            if (!val(tmp)) return 2;
            devs.push_back(tmp);
        } else if (a == "--phrase-file") {
            if (!val(phrase_file)) return 2;
        } else if (a == "--store") {
            if (!val(store)) return 2;
        } else if (a == "--pairing-file") {
            if (!val(pairing_file)) return 2;
        } else if (a == "--only") {
            if (!val(opt.path_prefix)) return 2;
        } else if (a == "--reserve-mb") {
            if (!val(tmp)) return 2;
            opt.reserve_bytes = strtoull(tmp.c_str(), nullptr, 10) << 20;
        } else if (a == "--dry-run") {
            opt.dry_run = true;
        } else {
            fprintf(stderr, "tierctl: unknown option %s\n", a.c_str());
            return 2;
        }
    }
    if (out.empty() || devs.empty()) {
        fprintf(stderr,
                "usage: tierctl restore --out <dir> --device host:port[@keyid] [--device ...] [--phrase-file F] [--store keychain|dir:PATH] "
                "[--pairing-file F]\n                       [--dry-run] [--only /prefix/] [--reserve-mb N]\n");
        return 2;
    }
    std::string phrase;
    if (!read_phrase(phrase_file, phrase)) return 1;
    std::string err;
    auto key = tierfs::crypto::decode_recovery(phrase, &err);
    for (auto& ch : phrase) ch = 0;
    if (!key) { fprintf(stderr, "tierctl: the recovery phrase is not accepted: %s\n", err.c_str()); return 1; }

    std::map<std::string, std::string> codes;  // host:port -> pairing code, from the pairing file
    if (!pairing_file.empty()) {
        std::ifstream pf(pairing_file);
        if (!pf) {
            fprintf(stderr, "tierctl: cannot read %s\n", pairing_file.c_str());
            return 1;
        }
        std::string line;
        while (std::getline(pf, line)) {
            size_t sp = line.find(' ');
            if (line.empty() || line[0] == '#' || sp == std::string::npos) continue;
            codes[line.substr(0, sp)] = line.substr(sp + 1);
        }
    }
    std::vector<std::unique_ptr<tierfs::DeviceClient>> clients;
    std::vector<tierfs::RecoveryDevice> rd;
    for (auto& d : devs) {
        std::string cerr_;
        auto client = make_device_client(d, store, codes, 15000, &cerr_);
        if (!client) {
            fprintf(stderr, "tierctl: %s\n", cerr_.c_str());
            return 2;
        }
        clients.push_back(std::move(client));
        rd.push_back({d, clients.back().get()});
    }
    opt.progress = [](const std::string& s) { fprintf(stderr, "  %s\n", s.c_str()); };
    tierfs::RestoreReport rep = tierfs::recover_from_devices(*key, rd, out, opt);
    fputs(tierfs::format_recovery_report(rep).c_str(), stdout);
    if (!rep.fatal.empty()) return 1;
    return rep.complete() ? 0 : 3;
}

static int cmd_init(int argc, char** argv) {
    const char* usage = "usage: tierctl init <ledger-dir> <key-file>\n       tierctl init <ledger-dir> --store keychain|dir:PATH\n";
    if (argc < 4) {
        fputs(usage, stderr);
        return 2;
    }
    std::string ldir = argv[2], kfile, source;
    bool use_store = std::string(argv[3]) == "--store";
    if (use_store) {
        if (argc < 5) {
            fputs(usage, stderr);
            return 2;
        }
        source = argv[4];
    } else {
        kfile = argv[3];
    }
    std::unique_ptr<tierfs::crypto::KeyStore> store;
    if (use_store) {
        std::string why;
        store = tierfs::keystore_for(source, &why);
        if (!store) {
            fprintf(stderr, "tierctl: %s\n", why.empty() ? "--store must be 'keychain' or 'dir:PATH'" : why.c_str());
            return 2;
        }
    }
    if (fs::exists(ldir + "/ledger.db")) { fprintf(stderr, "tierctl: %s already holds a ledger; nothing was changed\n", ldir.c_str()); return 1; }
    if (!use_store && fs::exists(kfile)) {
        fprintf(stderr, "tierctl: %s already exists; nothing was changed\n", kfile.c_str());
        return 1;
    }
    tierfs::crypto::SecretKey master = tierfs::crypto::SecretKey::random();
    if (!master.valid()) { fprintf(stderr, "tierctl: the system random generator failed\n"); return 1; }
    std::string phrase = tierfs::crypto::encode_recovery(master);
    printf("RECOVERY PHRASE (shown once; it is the ONLY way to get your files back if this Mac is lost):\n\n    %s\n\n", phrase.c_str());
    printf("Write it on paper and keep it away from this Mac. Do not photograph it or save it in a file or a password manager on this Mac.\n");
    std::vector<int> groups = tierfs::crypto::pick_confirm_groups(3);
    for (int g : groups) {
        printf("Type group %d of the phrase: ", g);
        fflush(stdout);
        char buf[128] = {0};
        if (!fgets(buf, sizeof buf, stdin)) { fprintf(stderr, "\ntierctl: no answer; nothing was saved\n"); return 1; }
        std::string typed = buf;
        while (!typed.empty() && (typed.back() == '\n' || typed.back() == '\r')) typed.pop_back();
        if (!tierfs::crypto::check_confirm_group(phrase, g, typed)) { fprintf(stderr, "tierctl: that is not group %d; nothing was saved. Start again.\n", g); return 1; }
    }
    if (!use_store) {
        std::error_code ec;
        fs::create_directories(fs::path(kfile).parent_path().empty() ? fs::path(".") : fs::path(kfile).parent_path(), ec);
        int fd = ::open(kfile.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
            fprintf(stderr, "tierctl: cannot create %s: %s\n", kfile.c_str(), strerror(errno));
            return 1;
        }
        std::string hex = tierfs::crypto::to_hex(master.data(), 32) + "\n";
        bool wrote = write(fd, hex.data(), hex.size()) == static_cast<ssize_t>(hex.size()) && fsync(fd) == 0;
        close(fd);
        if (!wrote) {
            unlink(kfile.c_str());
            fprintf(stderr, "tierctl: cannot write the key file\n");
            return 1;
        }
    }
    std::string err;
    auto L = tierfs::Ledger::open(ldir, &err);
    if (!L) {
        fprintf(stderr, "tierctl: cannot create the ledger: %s%s\n", err.c_str(),
                use_store ? "" : (" (the key file " + kfile + " was written; delete it before retrying)").c_str());
        return 1;
    }
    std::string volume = L->volume_id();
    if (use_store && !store->store(volume, master)) {
        L.reset();  // the ledger was just created and holds nothing: remove it so a retry starts clean
        for (const char* f : {"ledger.db", "ledger.db-wal", "ledger.db-shm", "ledger.lock", "ledger.reserve"}) unlink((ldir + "/" + f).c_str());
        fprintf(stderr, "tierctl: could not store the key in %s (macOS may have refused access); nothing was saved. Start again.\n", source.c_str());
        return 1;
    }
    L->set_meta("recovery_acked", "1");
    L->ensure_reserve(64u << 20);
    printf("\nCreated volume %s\n  ledger:   %s\n", volume.c_str(), ldir.c_str());
    if (use_store)
        printf("  key:      stored in %s (account %s); give the daemon  keyfile=%s\n", source.c_str(), volume.c_str(), source.c_str());
    else
        printf("  key file: %s (mode 0600; development form: prefer --store keychain)\n", kfile.c_str());
    printf("Offloading stays refused until you also record a backup: tierctl ack-backup %s I-HAVE-A-BACKUP\n", ldir.c_str());
    return 0;
}

static int cmd_check_phrase(int argc, char** argv) {
    const char* usage =
        "usage: tierctl check-phrase <key-file>\n       tierctl check-phrase --store keychain|dir:PATH <ledger-dir>\n(the phrase is read from stdin, "
        "hidden on a terminal)\n";
    if (argc < 3) {
        fputs(usage, stderr);
        return 2;
    }
    std::string where, source, volume;
    std::optional<tierfs::crypto::SecretKey> stored;
    if (std::string(argv[2]) == "--store") {
        if (argc < 5) {
            fputs(usage, stderr);
            return 2;
        }
        source = argv[3];
        std::string err;
        auto L = tierfs::Ledger::open(argv[4], &err);
        if (!L) {
            fprintf(stderr, "tierctl: cannot open the ledger: %s\n", err.c_str());
            return 1;
        }
        volume = L->volume_id();
        stored = tierfs::load_master_key(source, volume, &err);
        if (!stored) {
            fprintf(stderr, "tierctl: %s\n", err.c_str());
            return 1;
        }
        where = source + " (volume " + volume + ")";
    } else {
        std::string err;
        stored = tierfs::load_master_key(argv[2], "", &err);
        if (!stored) {
            fprintf(stderr, "tierctl: %s\n", err.c_str());
            return 1;
        }
        where = argv[2];
    }
    std::string phrase;
    if (!read_phrase("", phrase)) return 1;
    std::string err;
    auto key = tierfs::crypto::decode_recovery(phrase, &err);
    for (auto& ch : phrase) ch = 0;
    if (!key) { printf("NOT VALID: %s\n", err.c_str()); return 1; }
    if (!(*key == *stored)) {
        printf("This is a valid phrase, but for a DIFFERENT key than %s.\n", where.c_str());
        return 1;
    }
    printf("MATCHES: this phrase restores the key in %s\n", where.c_str());
    return 0;
}

// Runs tmutil (or the program in TIERFS_TMUTIL, for tests) and returns its combined output and exit status.
static int run_tmutil(const std::string& args, std::string* out) {
    const char* bin = getenv("TIERFS_TMUTIL");
    std::string cmd = std::string(bin ? bin : "/usr/bin/tmutil") + " " + args + " 2>&1";
    FILE* f = popen(cmd.c_str(), "r");
    if (!f) {
        *out = "cannot run tmutil";
        return -1;
    }
    char buf[2048];
    out->clear();
    while (size_t n = fread(buf, 1, sizeof buf, f)) out->append(buf, n);
    int st = pclose(f);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

// Read-only: what macOS says about Time Machine. It changes nothing; the owner still makes the statement with ack-backup.
static int cmd_check_backup(int argc, char** argv) {
    std::string folder = argc > 2 ? argv[2] : "";
    std::string out;
    run_tmutil("destinationinfo", &out);
    if (out.find("No destinations configured") != std::string::npos) {
        printf(
            "NO BACKUP: Time Machine has no destination configured. Set one up (System Settings > General > Time Machine) before moving any file.\n");
        return 3;
    }
    if (out.find("Operation not permitted") != std::string::npos || out.find("not permitted") != std::string::npos) {
        printf(
            "CANNOT TELL: macOS will not let this terminal read Time Machine. Give your terminal app Full Disk Access (System Settings > Privacy & "
            "Security), or check by hand.\n");
        return 3;
    }
    std::string name;
    {
        size_t p = out.find("Name");
        if (p != std::string::npos) {
            size_t e = out.find('\n', p);
            size_t c = out.find(':', p);
            if (c != std::string::npos && c < e) name = out.substr(c + 1, e - c - 1);
        }
    }
    while (!name.empty() && name[0] == ' ') name.erase(0, 1);
    printf("destination: %s\n", name.empty() ? "(configured)" : name.c_str());
    int rc = run_tmutil("latestbackup", &out);
    if (rc != 0 || out.find("not permitted") != std::string::npos || out.find("No machine directory") != std::string::npos ||
        out.find("Failed") != std::string::npos) {
        std::string first = out.substr(0, out.find('\n'));
        printf("CANNOT TELL: no readable latest backup (%s). The destination may be disconnected, or this terminal needs Full Disk Access.\n",
               first.c_str());
        return 3;
    }
    // .../2026-10-11-120000
    std::string path = out.substr(0, out.find('\n'));
    size_t slash = path.rfind('/');
    std::string stamp = slash == std::string::npos ? path : path.substr(slash + 1);
    struct tm tm_ = {};
    if (strptime(stamp.c_str(), "%Y-%m-%d-%H%M%S", &tm_) == nullptr) {
        printf("CANNOT TELL: unexpected latest-backup name \"%s\"\n", stamp.c_str());
        return 3;
    }
    tm_.tm_isdst = -1;
    time_t at = mktime(&tm_);
    long long hours = (static_cast<long long>(time(nullptr)) - at) / 3600;
    printf("latest backup: %s (%lld hour(s) ago)\n", stamp.c_str(), hours);
    if (!folder.empty()) {
        run_tmutil("isexcluded '" + folder + "'", &out);
        if (out.find("[Excluded]") != std::string::npos) {
            printf("NOT COVERED: %s is excluded from Time Machine.\n", folder.c_str());
            return 3;
        }
        printf("%s is included in Time Machine.\n", folder.c_str());
    }
    printf("OK: a backup exists. If it is new enough, record it with: tierctl ack-backup <ledger-dir> I-HAVE-A-BACKUP\n");
    return 0;
}

static int cmd_ack_backup(int argc, char** argv) {
    if (argc < 4 || std::string(argv[3]) != "I-HAVE-A-BACKUP") { fprintf(stderr, "usage: tierctl ack-backup <ledger-dir> I-HAVE-A-BACKUP\n(this records a statement; make sure it is true: with no backup, a bug could destroy the only copy of a file)\n"); return 2; }
    if (!fs::exists(std::string(argv[2]) + "/ledger.db")) { fprintf(stderr, "tierctl: %s has no ledger.db\n", argv[2]); return 1; }
    std::string err;
    auto L = tierfs::Ledger::open(argv[2], &err);
    if (!L) { fprintf(stderr, "tierctl: cannot open the ledger: %s\n", err.c_str()); return 1; }
    if (!L->ack_backup().ok) {
        fprintf(stderr, "tierctl: cannot record it\n");
        return 1;
    }
    time_t at = static_cast<time_t>(std::stoll(L->get_meta("backup_acked_at").value_or("0")));
    char when[64];
    strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", localtime(&at));
    printf(
        "recorded at %s: a backup exists.\nOnly files created or changed BEFORE this moment can be moved off the Mac, and the statement expires "
        "after %s days.\n"
        "After you change files, make a new backup and run this again.\n",
        when, L->get_meta("backup_max_age_days").value_or("30").c_str());
    return 0;
}

static int cmd_test_gates(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: tierctl test-gates <ledger-dir> <test-prefix>\n"); return 2; }
    std::string err;
    auto L = tierfs::Ledger::open(argv[2], &err);
    if (!L) { fprintf(stderr, "tierctl: cannot open the ledger: %s\n", err.c_str()); return 1; }
    L->set_meta("recovery_acked", "1");
    L->set_meta("test_prefix", argv[3]);
    L->ensure_reserve(1 << 20);
    printf("ledger %s: recovery phrase marked acknowledged, %s treated as a test area, reserve present\n", argv[2], argv[3]);
    return 0;
}

static int cmd_control(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: tierctl control <ledger-dir> <command...>\n"); return 2; }
    std::string line = argv[3];
    for (int i = 4; i < argc; i++) line += std::string(" ") + argv[i];
    std::string sock = std::string(argv[2]) + "/control.sock";
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (sock.size() >= sizeof sa.sun_path) { fprintf(stderr, "tierctl: the socket path is too long\n"); return 1; }
    strcpy(sa.sun_path, sock.c_str());
    if (connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) { fprintf(stderr, "tierctl: no running tierfsd answers at %s: %s\n", sock.c_str(), strerror(errno)); return 1; }
    line += "\n";
    if (write(fd, line.data(), line.size()) < 0) { close(fd); return 1; }
    std::string reply;
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) reply.append(buf, static_cast<size_t>(n));
    close(fd);
    fputs(reply.c_str(), stdout);
    return reply.size() >= 3 && reply.compare(reply.size() - 3, 3, "OK\n") == 0 ? 0 : 3;
}

static int cmd_ledger_status(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: tierctl ledger-status <ledger-dir>\n"); return 2; }
    std::string dir = argv[2];
    if (!fs::exists(dir + "/ledger.db")) { fprintf(stderr, "tierctl: %s has no ledger.db (nothing was created)\n", dir.c_str()); return 1; }
    std::string err;
    auto L = tierfs::Ledger::open(dir, &err);
    if (!L) { fprintf(stderr, "tierctl: cannot open the ledger: %s\n", err.c_str()); return 1; }
    printf("ledger:      %s\nvolume:      %s\n", dir.c_str(), L->volume_id().c_str());
    std::string backup_text = "NO";
    if (L->get_meta("backup_acked").value_or("") == "1") {
        long long at = atoll(L->get_meta("backup_acked_at").value_or("0").c_str());
        if (at <= 0)
            backup_text = "yes (NO DATE: run ack-backup again)";
        else {
            time_t tt = static_cast<time_t>(at);
            char when[64];
            strftime(when, sizeof when, "%Y-%m-%d %H:%M", localtime(&tt));
            long long days = (static_cast<long long>(time(nullptr)) - at) / 86400;
            backup_text = std::string("yes (recorded ") + when + ", " + std::to_string(days) + " day(s) ago" +
                          (days > atoll(L->get_meta("backup_max_age_days").value_or("30").c_str()) ? ", EXPIRED" : "") + ")";
        }
    }
    printf("recovery phrase acknowledged: %s;  backup acknowledged: %s\n", L->get_meta("recovery_acked").value_or("") == "1" ? "yes" : "NO",
           backup_text.c_str());
    for (auto& d : L->list_devices())
        printf("device:      %s  %-16s class %s  %s\n", d.device_id.substr(0, 8).c_str(), d.name.c_str(), d.cls.c_str(), d.state.c_str());
    std::map<std::string, int> by_state;
    for (auto& f : L->list_files()) by_state[tierfs::to_string(f.state)]++;
    for (auto& kv : by_state) printf("files:       %-11s %d\n", kv.first.c_str(), kv.second);
    auto intents = L->open_intents();
    printf("open steps:  %zu%s\n", intents.size(), intents.empty() ? "" : "   (an interrupted drop, purge or restore: it will be finished or undone at the next start)");
    for (auto& i : intents) printf("             %s %s v%lld\n", i.kind.c_str(), i.file_id.substr(0, 8).c_str(), static_cast<long long>(i.version));
    printf("quarantine:  held %zu, purging %zu, purged %zu, restoring %zu, restored %zu\n",
           L->list_quarantine(tierfs::QuarantineState::HELD).size(), L->list_quarantine(tierfs::QuarantineState::PURGING).size(),
           L->list_quarantine(tierfs::QuarantineState::PURGED).size(), L->list_quarantine(tierfs::QuarantineState::RESTORING).size(),
           L->list_quarantine(tierfs::QuarantineState::RESTORED).size());
    auto problems = L->fsck();
    printf("consistency: %s\n", problems.empty() ? "ok" : "PROBLEMS");
    for (auto& p : problems) printf("  - %s\n", p.c_str());
    return problems.empty() && intents.empty() ? 0 : 3;
}

// ---------------------------------------------------------------- tierctl service: tierfsd as a LaunchAgent

extern char** environ;

// Runs a program (no shell) and collects what it prints. -1 if it could not be started.
static int run_program(const std::vector<std::string>& argv_in, std::string* out) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], 1);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], 2);
    posix_spawn_file_actions_addclose(&fa, pipefd[0]);
    std::vector<char*> av;
    for (auto& a : argv_in) av.push_back(const_cast<char*>(a.c_str()));
    av.push_back(nullptr);
    pid_t pid = 0;
    int rc = posix_spawn(&pid, argv_in[0].c_str(), &fa, nullptr, av.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    close(pipefd[1]);
    if (rc != 0) {
        close(pipefd[0]);
        return -1;
    }
    std::string text;
    char buf[1024];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof buf)) > 0) text.append(buf, static_cast<size_t>(n));
    close(pipefd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (out) *out = text;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static std::string read_whole(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static int cmd_service(int argc, char** argv) {
    const char* usage =
        "usage: tierctl service plist|install|uninstall|status --name NAME [--mountpoint DIR] [-o key=value ...]\n"
        "         [--binary PATH] [--log-dir DIR] [--agents-dir DIR] [--run-at-load] [--load] [--force]\n"
        "  plist      print the LaunchAgent plist (changes nothing)\n"
        "  install    write ~/Library/LaunchAgents/local.tierfs.NAME.plist; with --load also start it (see docs/RUNBOOK.md: mounting is not proven "
        "yet)\n"
        "  uninstall  stop it and remove the plist (only a plist that is this service's)\n"
        "  status     is the plist there, is the agent loaded\n"
        "the -o options are the ones tierfsd takes (origin, prefix, ledger, keyfile are required; keyfile is 'keychain', 'dir:/path' or a key file "
        "path)\n";
    if (argc < 3) {
        fputs(usage, stderr);
        return 2;
    }
    std::string action = argv[2];
    if (action != "plist" && action != "install" && action != "uninstall" && action != "status") {
        fputs(usage, stderr);
        return 2;
    }
    tierfs::ServiceSpec spec;
    std::string agents_dir;
    bool load = false, force = false;
    const char* home = getenv("HOME");
    for (int i = 3; i < argc; i++) {
        std::string a = argv[i];
        auto val = [&](std::string& dst) {
            if (i + 1 >= argc) {
                fprintf(stderr, "tierctl: %s needs a value\n", a.c_str());
                return false;
            }
            dst = argv[++i];
            return true;
        };
        if (a == "--name") {
            if (!val(spec.name)) return 2;
        } else if (a == "--mountpoint") {
            if (!val(spec.mountpoint)) return 2;
        } else if (a == "--binary") {
            if (!val(spec.binary)) return 2;
        } else if (a == "--log-dir") {
            if (!val(spec.log_dir)) return 2;
        } else if (a == "--agents-dir") {
            if (!val(agents_dir)) return 2;
        } else if (a == "--run-at-load")
            spec.run_at_load = true;
        else if (a == "--load")
            load = true;
        else if (a == "--force")
            force = true;
        else if (a == "-o") {
            std::string kv;
            if (!val(kv)) return 2;
            size_t eq = kv.find('=');
            spec.options.emplace_back(kv.substr(0, eq), eq == std::string::npos ? "" : kv.substr(eq + 1));
        } else {
            fprintf(stderr, "tierctl: unknown option %s\n", a.c_str());
            return 2;
        }
    }
    if (agents_dir.empty() && home) agents_dir = std::string(home) + "/Library/LaunchAgents";
    if (spec.log_dir.empty() && home) spec.log_dir = std::string(home) + "/Library/Logs/tierfs";
    if (spec.binary.empty()) {  // tierfsd next to this program
        char self[4096];
        uint32_t sz = sizeof self;
        if (_NSGetExecutablePath(self, &sz) == 0) spec.binary = (fs::path(fs::weakly_canonical(self)).parent_path() / "tierfsd").string();
    }
    if (agents_dir.empty()) {
        fprintf(stderr, "tierctl: no home directory: give --agents-dir\n");
        return 2;
    }
    const std::string label = tierfs::service_label(spec.name);
    const std::string plist_path = agents_dir + "/" + label + ".plist";
    const char* lc = getenv("TIERFS_LAUNCHCTL");
    const std::string launchctl = lc ? lc : "/bin/launchctl";
    const std::string domain = "gui/" + std::to_string(getuid());

    if (action == "uninstall" || action == "status") {
        if (spec.name.empty() || spec.name[0] == '.' || spec.name.find('/') != std::string::npos) {
            fprintf(stderr, "tierctl: give a valid --name\n");
            return 2;
        }
        bool present = fs::exists(plist_path);
        if (action == "status") {
            std::string out;
            int rc = run_program({launchctl, "print", domain + "/" + label}, &out);
            printf("service:  %s\nplist:    %s (%s)\nagent:    %s\n", label.c_str(), plist_path.c_str(), present ? "present" : "absent",
                   rc == 0 ? "loaded" : "not loaded");
            return 0;
        }
        if (present && read_whole(plist_path).find("<string>" + label + "</string>") == std::string::npos) {
            fprintf(stderr, "tierctl: %s does not look like this service's plist; leaving it alone\n", plist_path.c_str());
            return 1;
        }
        std::string out;
        int rc = run_program({launchctl, "bootout", domain + "/" + label}, &out);
        if (rc == 0) printf("stopped %s\n", label.c_str());
        if (present) {
            std::error_code ec;
            fs::remove(plist_path, ec);
            if (ec) {
                fprintf(stderr, "tierctl: cannot remove %s: %s\n", plist_path.c_str(), ec.message().c_str());
                return 1;
            }
            printf("removed %s\n", plist_path.c_str());
        } else {
            printf("%s was not installed\n", label.c_str());
        }
        return 0;
    }

    std::string bad = tierfs::validate_service(spec);
    if (!bad.empty()) {
        fprintf(stderr, "tierctl: %s\n", bad.c_str());
        return 2;
    }
    std::string xml = tierfs::render_service_plist(spec);
    if (action == "plist") {
        fputs(xml.c_str(), stdout);
        return 0;
    }

    // install
    struct stat bst;
    if (stat(spec.binary.c_str(), &bst) != 0 || !S_ISREG(bst.st_mode) || access(spec.binary.c_str(), X_OK) != 0) {
        fprintf(stderr, "tierctl: %s is not an executable file (use --binary)\n", spec.binary.c_str());
        return 1;
    }
    if (load && getenv("TIERFS_I_ACCEPT_A_REBOOT") == nullptr) {
        fprintf(stderr,
                "tierctl: refusing to start the mount: mounting with FUSE-T has crashed a Mac (kernel panic in the NFS client) and is not proven "
                "yet; see docs/ADR 0006.\n"
                "         Install without --load, or set TIERFS_I_ACCEPT_A_REBOOT=1 if you accept that.\n");
        return 1;
    }
    std::error_code ec;
    if (fs::exists(plist_path)) {
        if (read_whole(plist_path) == xml && !force) {
            printf("%s is already installed (nothing changed)\n", plist_path.c_str());
        } else if (!force) {
            fprintf(stderr, "tierctl: %s exists and differs; pass --force to replace it\n", plist_path.c_str());
            return 1;
        }
    }
    fs::create_directories(agents_dir, ec);
    fs::create_directories(spec.log_dir, ec);
    if (ec) {
        fprintf(stderr, "tierctl: cannot create the directories: %s\n", ec.message().c_str());
        return 1;
    }
    if (!fs::exists(plist_path) || read_whole(plist_path) != xml) {
        std::string tmp = plist_path + ".new";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            f << xml;
            if (!f) {
                fprintf(stderr, "tierctl: cannot write %s\n", tmp.c_str());
                return 1;
            }
        }
        chmod(tmp.c_str(), 0644);
        if (rename(tmp.c_str(), plist_path.c_str()) != 0) {
            unlink(tmp.c_str());
            fprintf(stderr, "tierctl: cannot install %s: %s\n", plist_path.c_str(), strerror(errno));
            return 1;
        }
        printf("installed %s\n", plist_path.c_str());
    }
    if (load) {
        std::string out;
        int rc = run_program({launchctl, "bootstrap", domain, plist_path}, &out);
        if (rc != 0) {
            fprintf(stderr, "tierctl: launchctl bootstrap failed (%d): %s", rc, out.c_str());
            return 1;
        }
        printf("started %s\n", label.c_str());
    } else {
        printf("not started. To start it: launchctl bootstrap %s %s\n", domain.c_str(), plist_path.c_str());
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "check-backup")
        return cmd_check_backup(argc, argv);  // takes an optional folder, not a directory to inspect
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s cache-info|cache-verify|cache-clear <cache-dir> [--yes] | restore --out <dir> --device host:port ... | ledger-status "
                "<ledger-dir> | service plist|install|uninstall|status ...\n",
                argv[0]);
        return 2;
    }
    std::string cmd = argv[1], dir = argv[2];
    if (cmd == "restore") return cmd_restore(argc, argv);
    if (cmd == "ledger-status") return cmd_ledger_status(argc, argv);
    if (cmd == "test-gates") return cmd_test_gates(argc, argv);
    if (cmd == "init") return cmd_init(argc, argv);
    if (cmd == "pair") return cmd_pair(argc, argv);
    if (cmd == "check-phrase") return cmd_check_phrase(argc, argv);
    if (cmd == "ack-backup") return cmd_ack_backup(argc, argv);
    if (cmd == "control") return cmd_control(argc, argv);
    if (cmd == "service") return cmd_service(argc, argv);
    if (!fs::is_directory(dir)) { fprintf(stderr, "tierctl: %s is not a directory\n", dir.c_str()); return 1; }
    if (!looks_like_cache(dir)) { fprintf(stderr, "tierctl: %s does not look like a tierfs cache\n", dir.c_str()); return 1; }

    if (cmd == "cache-info") {
        int fd;
        bool in_use = lock_exclusive(dir, fd) != 0;
        if (!in_use) close(fd);
        // lock_exclusive printed an error when busy; for info that is just a status.
        long long chunks = 0, bytes = 0, files = 0, attrs = 0, dirs = 0, unused = 0;
        query_one(dir + "/chunks.db", "SELECT COUNT(*), COALESCE(SUM(len),0), COUNT(DISTINCT path) FROM chunks", chunks, bytes, files);
        query_one(dir + "/meta.db", "SELECT (SELECT COUNT(*) FROM attrs), (SELECT COUNT(*) FROM dirs), 0", attrs, dirs, unused);
        printf("cache:     %s\nstatus:    %s\n", dir.c_str(), in_use ? "IN USE by a running mount" : "idle");
        printf("data:      %lld chunks, %s, %lld files\n", chunks, human((uint64_t)bytes).c_str(), files);
        printf("metadata:  %lld entries, %lld listings\n", attrs, dirs);
        printf("on disk:   %s total\n", human(dir_bytes(dir)).c_str());
        return 0;
    }
    if (cmd == "cache-verify") {
        int fd;
        if (lock_exclusive(dir, fd) != 0) return 1;
        tierfs::ChunkCache c(dir, ~0ull);
        if (!c.ok()) { fprintf(stderr, "tierctl: chunk cache unreadable (it will be rebuilt on next mount)\n"); close(fd); return 1; }
        uint64_t bad = 0, checked = c.verify_all(&bad);
        printf("checked %llu chunks: %llu damaged%s\n", (unsigned long long)checked, (unsigned long long)bad,
               bad ? " (removed; they will be refetched)" : "");
        close(fd);
        return bad ? 3 : 0;
    }
    if (cmd == "cache-clear") {
        bool yes = argc > 3 && strcmp(argv[3], "--yes") == 0;
        int fd;
        if (lock_exclusive(dir, fd) != 0) return 1;
        const char* names[] = {"chunks", "chunks.db", "chunks.db-wal", "chunks.db-shm", "meta.db", "meta.db-wal", "meta.db-shm"};
        uint64_t total = 0;
        for (const char* n : names) {
            fs::path p = fs::path(dir) / n;
            std::error_code ec;
            if (!fs::exists(p, ec)) continue;
            uint64_t sz = fs::is_directory(p, ec) ? dir_bytes(p) : fs::file_size(p, ec);
            total += sz;
            printf("%s %s (%s)\n", yes ? "removing" : "would remove", p.c_str(), human(sz).c_str());
            if (yes) fs::remove_all(p, ec);
        }
        printf("%s %s%s\n", yes ? "freed" : "would free", human(total).c_str(), yes ? "" : "  (re-run with --yes)");
        close(fd);
        return 0;
    }
    fprintf(stderr, "tierctl: unknown command %s\n", cmd.c_str());
    return 2;
}
