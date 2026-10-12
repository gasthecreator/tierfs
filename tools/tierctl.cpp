// tierctl: inspect, verify and clear a tierfs cache directory.
//
//   tierctl cache-info   <dir>          read-only; safe while mounted
//   tierctl cache-verify <dir>          re-hash every chunk, drop damaged ones (needs unmounted)
//   tierctl cache-clear  <dir> [--yes]  delete the caches (needs unmounted); dry run without --yes
//   tierctl restore --out <dir> --device host:port [--device ...] [--phrase-file F] [--dry-run] [--only /prefix/]
//                                       get files back from the devices with only the recovery phrase
//   tierctl ledger-status <ledger-dir>  health of the ledger: files by state, open steps, quarantine, fsck
//   tierctl init <ledger-dir> <key-file>
//                                       create a new volume: a fresh key, shown ONCE as a recovery phrase you must write down and prove
//                                       (three groups re-typed on stdin) before anything is saved; then the ledger is created and the
//                                       phrase marked acknowledged. Refuses if either path exists.
//   tierctl check-phrase <key-file>
//                                       type or pipe your paper recovery phrase: says whether it matches the key file (nothing is changed)
//   tierctl ack-backup <ledger-dir> I-HAVE-A-BACKUP
//                                       record that a backup of the folder exists (Time Machine or similar). Offloading refuses without it.
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
#include <termios.h>
#include <sqlite3.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../core/chunkcache.hpp"
#include "../core/ledger.hpp"
#include "../core/recovery.hpp"

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

static int cmd_restore(int argc, char** argv) {
    std::string out, phrase_file, only;
    std::vector<std::string> devs;
    tierfs::RecoveryOptions opt;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        auto val = [&](std::string& dst) { if (i + 1 >= argc) { fprintf(stderr, "tierctl: %s needs a value\n", a.c_str()); return false; } dst = argv[++i]; return true; };
        std::string tmp;
        if (a == "--out") { if (!val(out)) return 2; }
        else if (a == "--device") { if (!val(tmp)) return 2; devs.push_back(tmp); }
        else if (a == "--phrase-file") { if (!val(phrase_file)) return 2; }
        else if (a == "--only") { if (!val(opt.path_prefix)) return 2; }
        else if (a == "--reserve-mb") { if (!val(tmp)) return 2; opt.reserve_bytes = strtoull(tmp.c_str(), nullptr, 10) << 20; }
        else if (a == "--dry-run") opt.dry_run = true;
        else { fprintf(stderr, "tierctl: unknown option %s\n", a.c_str()); return 2; }
    }
    if (out.empty() || devs.empty()) {
        fprintf(stderr, "usage: tierctl restore --out <dir> --device host:port [--device ...] [--phrase-file F] [--dry-run] [--only /prefix/] [--reserve-mb N]\n");
        return 2;
    }
    std::string phrase;
    if (!read_phrase(phrase_file, phrase)) return 1;
    std::string err;
    auto key = tierfs::crypto::decode_recovery(phrase, &err);
    for (auto& ch : phrase) ch = 0;
    if (!key) { fprintf(stderr, "tierctl: the recovery phrase is not accepted: %s\n", err.c_str()); return 1; }

    std::vector<std::unique_ptr<tierfs::DeviceClient>> clients;
    std::vector<tierfs::RecoveryDevice> rd;
    for (auto& d : devs) {
        size_t colon = d.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= d.size()) { fprintf(stderr, "tierctl: device must be host:port, got %s\n", d.c_str()); return 2; }
        int port = atoi(d.c_str() + colon + 1);
        if (port <= 0 || port > 65535) { fprintf(stderr, "tierctl: bad port in %s\n", d.c_str()); return 2; }
        clients.push_back(std::make_unique<tierfs::DeviceClient>(d.substr(0, colon), static_cast<uint16_t>(port), 15000));
        rd.push_back({d, clients.back().get()});
    }
    opt.progress = [](const std::string& s) { fprintf(stderr, "  %s\n", s.c_str()); };
    tierfs::RestoreReport rep = tierfs::recover_from_devices(*key, rd, out, opt);
    fputs(tierfs::format_recovery_report(rep).c_str(), stdout);
    if (!rep.fatal.empty()) return 1;
    return rep.complete() ? 0 : 3;
}

static int cmd_init(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: tierctl init <ledger-dir> <key-file>\n"); return 2; }
    std::string ldir = argv[2], kfile = argv[3];
    if (fs::exists(ldir + "/ledger.db")) { fprintf(stderr, "tierctl: %s already holds a ledger; nothing was changed\n", ldir.c_str()); return 1; }
    if (fs::exists(kfile)) { fprintf(stderr, "tierctl: %s already exists; nothing was changed\n", kfile.c_str()); return 1; }
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
    std::error_code ec;
    fs::create_directories(fs::path(kfile).parent_path().empty() ? fs::path(".") : fs::path(kfile).parent_path(), ec);
    int fd = ::open(kfile.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { fprintf(stderr, "tierctl: cannot create %s: %s\n", kfile.c_str(), strerror(errno)); return 1; }
    std::string hex = tierfs::crypto::to_hex(master.data(), 32) + "\n";
    bool wrote = write(fd, hex.data(), hex.size()) == static_cast<ssize_t>(hex.size()) && fsync(fd) == 0;
    close(fd);
    if (!wrote) { unlink(kfile.c_str()); fprintf(stderr, "tierctl: cannot write the key file\n"); return 1; }
    std::string err;
    auto L = tierfs::Ledger::open(ldir, &err);
    if (!L) { fprintf(stderr, "tierctl: cannot create the ledger: %s (the key file %s was written; delete it before retrying)\n", err.c_str(), kfile.c_str()); return 1; }
    L->set_meta("recovery_acked", "1");
    L->ensure_reserve(64u << 20);
    printf("\nCreated volume %s\n  ledger:   %s\n  key file: %s (mode 0600; development form, the Keychain comes later)\n", L->volume_id().c_str(), ldir.c_str(), kfile.c_str());
    printf("Offloading stays refused until you also record a backup: tierctl ack-backup %s I-HAVE-A-BACKUP\n", ldir.c_str());
    return 0;
}

static int cmd_check_phrase(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: tierctl check-phrase <key-file>   (the phrase is read from stdin, hidden on a terminal)\n"); return 2; }
    std::ifstream kf(argv[2]);
    std::string hex;
    if (!kf || !std::getline(kf, hex)) { fprintf(stderr, "tierctl: cannot read %s\n", argv[2]); return 1; }
    auto raw = tierfs::crypto::from_hex(hex);
    if (!raw || raw->size() != 32) { fprintf(stderr, "tierctl: %s is not a key file\n", argv[2]); return 1; }
    std::string phrase;
    if (!read_phrase("", phrase)) return 1;
    std::string err;
    auto key = tierfs::crypto::decode_recovery(phrase, &err);
    for (auto& ch : phrase) ch = 0;
    if (!key) { printf("NOT VALID: %s\n", err.c_str()); return 1; }
    if (!(*key == tierfs::crypto::SecretKey(raw->data()))) { printf("This is a valid phrase, but for a DIFFERENT key than %s.\n", argv[2]); return 1; }
    printf("MATCHES: this phrase restores the key in %s\n", argv[2]);
    return 0;
}

static int cmd_ack_backup(int argc, char** argv) {
    if (argc < 4 || std::string(argv[3]) != "I-HAVE-A-BACKUP") { fprintf(stderr, "usage: tierctl ack-backup <ledger-dir> I-HAVE-A-BACKUP\n(this records a statement; make sure it is true: with no backup, a bug could destroy the only copy of a file)\n"); return 2; }
    if (!fs::exists(std::string(argv[2]) + "/ledger.db")) { fprintf(stderr, "tierctl: %s has no ledger.db\n", argv[2]); return 1; }
    std::string err;
    auto L = tierfs::Ledger::open(argv[2], &err);
    if (!L) { fprintf(stderr, "tierctl: cannot open the ledger: %s\n", err.c_str()); return 1; }
    L->set_meta("backup_acked", "1");
    printf("recorded: a backup exists\n");
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
    printf("recovery phrase acknowledged: %s;  backup acknowledged: %s\n", L->get_meta("recovery_acked").value_or("") == "1" ? "yes" : "NO",
           L->get_meta("backup_acked").value_or("") == "1" ? "yes" : "NO");
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

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s cache-info|cache-verify|cache-clear <cache-dir> [--yes] | restore --out <dir> --device host:port ... | ledger-status <ledger-dir>\n", argv[0]);
        return 2;
    }
    std::string cmd = argv[1], dir = argv[2];
    if (cmd == "restore") return cmd_restore(argc, argv);
    if (cmd == "ledger-status") return cmd_ledger_status(argc, argv);
    if (cmd == "test-gates") return cmd_test_gates(argc, argv);
    if (cmd == "init") return cmd_init(argc, argv);
    if (cmd == "check-phrase") return cmd_check_phrase(argc, argv);
    if (cmd == "ack-backup") return cmd_ack_backup(argc, argv);
    if (cmd == "control") return cmd_control(argc, argv);
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
