#include "daemon.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>

namespace tierfs {
namespace {

std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    size_t i = 0;
    while (i < s.size() && s[i] == ' ') i++;
    return s.substr(i);
}

}  // namespace

std::unique_ptr<Daemon> Daemon::create(const DaemonConfig& cfg, std::string* err) {
    auto fail = [&](const std::string& m) -> std::unique_ptr<Daemon> { if (err) *err = m; return nullptr; };
    if (cfg.ledger_dir.empty() || cfg.origin_dir.empty() || cfg.logical_prefix.empty() || cfg.key_file.empty())
        return fail("ledger, origin, prefix and key file are all required");
    std::unique_ptr<Daemon> d(new Daemon(cfg));
    std::string& pfx = d->cfg_.logical_prefix;
    if (pfx.back() != '/') pfx += '/';

    // the key (development form: a file holding the 32-byte master key as hex)
    std::ifstream kf(cfg.key_file);
    std::string hex;
    if (!kf || !std::getline(kf, hex)) return fail("cannot read the key file " + cfg.key_file);
    auto raw = crypto::from_hex(trim(hex));
    if (!raw || raw->size() != crypto::KEY_LEN) return fail("the key file must hold 64 hex characters");
    crypto::SecretKey master(raw->data());
    d->keys_ = std::make_unique<crypto::Keys>(master);

    std::string lerr;
    d->ledger_ = Ledger::open(cfg.ledger_dir, &lerr);
    if (!d->ledger_) return fail("cannot open the ledger: " + lerr);

    d->replicator_ = std::make_unique<Replicator>(*d->ledger_, *d->keys_, d->ledger_->volume_id());
    const std::string origin = cfg.origin_dir;
    d->engine_ = std::make_unique<DropEngine>(*d->ledger_, *d->replicator_, *d->keys_, d->ledger_->volume_id(), DropPolicy{},
                                              origin + "/.tierfs/quarantine",
                                              [origin, pfx = d->cfg_.logical_prefix](const FileRec& f) { return origin + "/" + f.path.substr(pfx.size()); });
    OverlayConfig oc;
    oc.origin_dir = origin;
    oc.logical_prefix = d->cfg_.logical_prefix;
    oc.write_wait_ms = cfg.write_wait_ms;
    oc.cache_bytes = cfg.cache_bytes;
    d->overlay_ = std::make_unique<Overlay>(*d->ledger_, *d->keys_, DeviceMap{}, oc, d->engine_.get());
    d->scanner_ = std::make_unique<Scanner>(*d->ledger_, *d->overlay_);
    d->probe_ = make_system_probe(origin);
    TierPolicy tp = cfg.policy;
    tp.roots = {d->cfg_.logical_prefix};
    if (tp.exclude.empty()) tp.exclude = {"/.git/"};
    if (cfg.notify) d->notifier_ = std::make_unique<OsascriptNotifier>();
    d->policy_ = std::make_unique<PolicyEngine>(*d->ledger_, *d->replicator_, *d->engine_, *d->probe_, tp,
                                                [origin, pfx = d->cfg_.logical_prefix](const FileRec& f) { return origin + "/" + f.path.substr(pfx.size()); },
                                                d->notifier_.get());
    for (const auto& spec : cfg.devices) {
        size_t colon = spec.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= spec.size()) return fail("a device must be host:port, got " + spec);
        int port = atoi(spec.c_str() + colon + 1);
        if (port <= 0 || port > 65535) return fail("bad port in " + spec);
        Dev dev;
        dev.spec = spec;
        dev.client = std::make_unique<DeviceClient>(spec.substr(0, colon), static_cast<uint16_t>(port), cfg.device_timeout_ms);
        d->devs_.push_back(std::move(dev));
    }
    d->socket_path_ = cfg.control_socket == "none" ? "" : (cfg.control_socket.empty() ? cfg.ledger_dir + "/control.sock" : cfg.control_socket);
    return d;
}

Daemon::~Daemon() { stop(); }

DeviceMap Daemon::devices_snapshot() {
    std::lock_guard<std::mutex> g(devs_mu_);
    DeviceMap m;
    for (auto& d : devs_) if (!d.id.empty()) m[d.id] = d.client.get();
    return m;
}

void Daemon::attach_devices() {
    bool changed = false;
    {
        std::lock_guard<std::mutex> g(devs_mu_);
        for (auto& d : devs_) {
            if (!d.id.empty()) continue;
            std::string id;
            Res r = replicator_->attach(*d.client, d.spec, "B", &id);
            if (r.ok) { d.id = id; changed = true; }
        }
    }
    if (changed) overlay_->set_devices(devices_snapshot());
}

bool Daemon::start(std::string* err) {
    if (started_) return true;
    {   // does the origin volume tell "A" from "a"? The ledger must fold names the same way, or two files could collide (or one be tracked twice)
        long sens = pathconf(cfg_.origin_dir.c_str(), _PC_CASE_SENSITIVE);
        if (sens >= 0) {
            bool want = sens == 1;
            if (ledger_->case_sensitive() != want && !ledger_->set_case_sensitive(want).ok)
                notes_.push_back(std::string("NEEDS ATTENTION: the folder is on a ") + (want ? "case-sensitive" : "case-insensitive") +
                                 " volume but this ledger was created for the other kind; names that differ only in case may be mishandled");
        }
    }
    attach_devices();
    DeviceMap devs = devices_snapshot();
    {   // finish every interrupted step before anything is served
        std::lock_guard<std::mutex> g(overlay_->engine_mutex());
        RecoveryReport er = engine_->recover(devs);
        for (auto& a : er.actions) notes_.push_back("recovered: " + a);
        for (auto& p : er.problems) notes_.push_back("NEEDS ATTENTION: " + p);
    }
    OverlayRecovery orp = overlay_->recover();
    for (auto& a : orp.actions) notes_.push_back("recovered: " + a);
    for (auto& p : orp.problems) notes_.push_back("NEEDS ATTENTION: " + p);
    if (cfg_.scan_at_start) {
        ScanReport sr = scanner_->scan();
        std::ostringstream o;
        o << "scan: " << sr.files_seen << " files, " << sr.tracked_new << " new, " << sr.marked_modified << " modified, " << sr.retired_vanished << " vanished";
        if (sr.aborted) o << " (ABORTED: " << sr.abort_reason << ")";
        notes_.push_back(o.str());
        for (auto& p : sr.problems) notes_.push_back("NEEDS ATTENTION: " + p);
        std::lock_guard<std::mutex> g(last_mu_);
        last_scan_ = o.str();
    }
    if (!socket_path_.empty()) {
        listen_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof sa);
        sa.sun_family = AF_UNIX;
        if (socket_path_.size() >= sizeof sa.sun_path) { if (err) *err = "the control socket path is too long"; return false; }
        strcpy(sa.sun_path, socket_path_.c_str());
        unlink(socket_path_.c_str());
        mode_t old = umask(0177);   // owner only: whoever can open the socket is the user
        int rc = bind(listen_fd_, reinterpret_cast<sockaddr*>(&sa), sizeof sa);
        umask(old);
        if (rc != 0 || listen(listen_fd_, 8) != 0) { if (err) *err = std::string("cannot create the control socket: ") + strerror(errno); close(listen_fd_); listen_fd_ = -1; return false; }
        chmod(socket_path_.c_str(), 0600);
        control_ = std::thread([this] { control_loop(); });
    }
    if (cfg_.maint_seconds > 0) maint_ = std::thread([this] { maintenance_loop(); });
    started_ = true;
    return true;
}

void Daemon::stop() {
    stop_ = true;
    if (maint_.joinable()) maint_.join();
    if (control_.joinable()) control_.join();
    if (listen_fd_ >= 0) { close(listen_fd_); listen_fd_ = -1; if (!socket_path_.empty()) unlink(socket_path_.c_str()); }
    started_ = false;
}

void Daemon::maintenance_loop() {
    auto next = std::chrono::steady_clock::now() + std::chrono::seconds(cfg_.maint_seconds);
    while (!stop_) {
        if (std::chrono::steady_clock::now() < next) { usleep(100000); continue; }
        next = std::chrono::steady_clock::now() + std::chrono::seconds(cfg_.maint_seconds);
        attach_devices();
        ScanReport sr = scanner_->scan();
        {
            std::ostringstream o;
            o << "scan: " << sr.files_seen << " files, " << sr.tracked_new << " new, " << sr.marked_modified << " modified, " << sr.retired_vanished << " vanished";
            if (sr.aborted) o << " (ABORTED: " << sr.abort_reason << ")";
            std::lock_guard<std::mutex> g(last_mu_);
            last_scan_ = o.str();
        }
        if (cfg_.background_replication && !stop_) cmd_tick();
    }
}

void Daemon::control_loop() {
    while (!stop_) {
        struct pollfd p = {listen_fd_, POLLIN, 0};
        if (poll(&p, 1, 200) <= 0) continue;
        int c = accept(listen_fd_, nullptr, nullptr);
        if (c < 0) continue;
        std::string line;
        char ch;
        struct pollfd cp = {c, POLLIN, 0};
        while (line.size() < 4096 && poll(&cp, 1, 2000) > 0 && read(c, &ch, 1) == 1 && ch != '\n') line += ch;
        std::string reply = control(line);
        const char* d = reply.data();
        size_t left = reply.size();
        while (left) { ssize_t n = write(c, d, left); if (n <= 0) break; d += n; left -= static_cast<size_t>(n); }
        close(c);
    }
}

std::string Daemon::cmd_status() {
    std::ostringstream o;
    o << "volume " << ledger_->volume_id() << "\n";
    std::map<std::string, int> by;
    for (auto& f : ledger_->list_files_under(cfg_.logical_prefix)) by[to_string(f.state)]++;
    for (auto& kv : by) o << "files " << kv.first << " " << kv.second << "\n";
    o << "retired " << ledger_->list_retired().size() << "\n";
    o << "quarantine held " << ledger_->list_quarantine(QuarantineState::HELD).size() << "\n";
    o << "open steps " << ledger_->open_intents().size() << "\n";
    {
        std::lock_guard<std::mutex> g(devs_mu_);
        for (auto& d : devs_) o << "device " << d.spec << " " << (d.id.empty() ? "not attached" : "attached " + d.id.substr(0, 8)) << "\n";
    }
    SpaceStatus sp = policy_->space();
    o << "space " << to_string(sp.level) << " free " << sp.info.avail() << " of " << sp.info.total << "\n";
    { std::lock_guard<std::mutex> g(last_mu_); o << last_scan_ << "\n"; }
    for (auto& n : notes_) o << "note " << n << "\n";
    o << "OK\n";
    return o.str();
}

// Files named by a mount path: one file, or every tracked file under a directory.
std::string Daemon::cmd_files(const std::string& path, bool drop) {
    std::string op, lp, rel;
    if (!overlay_->resolve(path, &op, &lp, &rel)) return "ERR not a valid path\n";
    std::vector<FileRec> files;
    if (auto f = ledger_->get_file_by_path(lp)) files.push_back(*f);
    else files = ledger_->list_files_under(lp.empty() || lp.back() == '/' ? lp : lp + "/");
    std::ostringstream o;
    size_t done = 0, refused = 0;
    for (const auto& f : files) {
        if (f.state != FileState::LOCAL && f.state != FileState::REPLICATING && f.state != FileState::REPLICATED) continue;
        std::string why;
        DeviceMap devs = devices_snapshot();
        std::lock_guard<std::mutex> g(overlay_->engine_mutex());
        std::string local = cfg_.origin_dir + "/" + f.path.substr(cfg_.logical_prefix.size());
        bool copied = false;
        for (auto& kv : devs) {
            auto cur = ledger_->get_file(f.file_id);
            if (cur && cur->state == FileState::REPLICATED && ledger_->committed_weight(f.file_id, cur->current_version) >= 2.0) { copied = true; break; }
            ReplicateOutcome r = replicator_->replicate(*kv.second, kv.first, f.file_id, local);
            if (!r.ok) why = r.why;
        }
        auto cur = ledger_->get_file(f.file_id);
        if (!copied) copied = cur && cur->state == FileState::REPLICATED && ledger_->committed_weight(f.file_id, cur->current_version) >= 2.0;
        if (!drop) {
            if (copied) { done++; o << "replicated " << f.path << "\n"; } else { refused++; o << "not replicated " << f.path << ": " << (why.empty() ? "not enough devices" : why) << "\n"; }
            continue;
        }
        if (!copied) { refused++; o << "refused " << f.path << ": could not make enough copies" << (why.empty() ? "" : " (" + why + ")") << "\n"; continue; }
        std::string consent = ledger_->create_consent(f.path, 600, "explicit offload command for " + f.path);
        DropOutcome d = engine_->drop(f.file_id, consent, devs, overlay_->gate());
        if (d.ok) { done++; o << "offloaded " << f.path << "\n"; } else { refused++; o << "refused " << f.path << ": " << d.why << "\n"; }
    }
    o << (drop ? "offloaded " : "replicated ") << done << ", refused " << refused << "\n" << (refused ? "ERR some files were refused\n" : "OK\n");
    return o.str();
}

std::string Daemon::cmd_tick() {
    std::lock_guard<std::mutex> g(overlay_->engine_mutex());
    TickReport t = policy_->tick(devices_snapshot());
    std::ostringstream o;
    o << "space " << to_string(t.space.level) << ", copied " << t.replication.files << " file(s), purged " << t.purged << (t.prompted ? ", prompted" : "") << "\n";
    o << "OK\n";
    return o.str();
}

std::string Daemon::control(const std::string& raw) {
    std::string line = trim(raw);
    size_t sp = line.find(' ');
    std::string cmd = line.substr(0, sp), arg = sp == std::string::npos ? "" : trim(line.substr(sp + 1));
    if (cmd == "status") return cmd_status();
    if (cmd == "scan") {
        ScanReport r = scanner_->scan();
        std::ostringstream o;
        o << "files " << r.files_seen << " new " << r.tracked_new << " modified " << r.marked_modified << " attrs " << r.attrs_updated << " vanished " << r.retired_vanished
          << " unchanged " << r.unchanged << " busy " << r.skipped_busy << "\n";
        for (auto& p : r.problems) o << "problem " << p << "\n";
        if (r.aborted) return o.str() + "ERR scan aborted: " + r.abort_reason + "\n";
        return o.str() + "OK\n";
    }
    if (cmd == "replicate" && !arg.empty()) return cmd_files(arg, false);
    if (cmd == "offload" && !arg.empty()) return cmd_files(arg, true);
    if (cmd == "hydrate" && !arg.empty()) { int r = overlay_->hydrate(arg); return r == 0 ? "OK\n" : "ERR " + std::string(strerror(-r)) + "\n"; }
    if (cmd == "undelete" && !arg.empty()) { int r = overlay_->undelete(arg); return r == 0 ? "OK\n" : "ERR " + std::string(strerror(-r)) + "\n"; }
    if (cmd == "tick") return cmd_tick();
    return "ERR unknown command; try: status, scan, replicate PATH, offload PATH, hydrate PATH, undelete PATH, tick\n";
}

}  // namespace tierfs
