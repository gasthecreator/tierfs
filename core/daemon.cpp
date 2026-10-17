#include "daemon.hpp"

#include "keysource.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
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

    std::string lerr;
    d->ledger_ = Ledger::open(cfg.ledger_dir, &lerr);
    if (!d->ledger_) return fail("cannot open the ledger: " + lerr);

    // the master key: from the Keychain, a development key store, or a key file (see core/keysource.hpp)
    std::string kerr;
    auto master = load_master_key(cfg.key_file, d->ledger_->volume_id(), &kerr);
    if (!master) return fail(kerr);
    d->keys_ = std::make_unique<crypto::Keys>(*master);

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
    oc.readahead_chunks = cfg.readahead_chunks;
    d->overlay_ = std::make_unique<Overlay>(*d->ledger_, *d->keys_, DeviceMap{}, oc, d->engine_.get());
    d->scanner_ = std::make_unique<Scanner>(*d->ledger_, *d->overlay_);
    d->probe_ = cfg.make_probe ? cfg.make_probe(origin) : make_system_probe(origin);
    TierPolicy tp = cfg.policy;
    tp.roots = {d->cfg_.logical_prefix};
    if (tp.exclude.empty()) tp.exclude = {"/.git/"};
    if (std::string bad = validate_thresholds(tp); !bad.empty()) return fail("free-space thresholds: " + bad);
    if (cfg.space_check_seconds < 0 || cfg.space_check_seconds > 86400)
        return fail("the free-space check period must be between 0 and 86400 seconds");
    if (cfg.notify) {  // what the notification says to do is worked out when it is shown, so it can name what stands in the way at that moment
        HintFn hint = [raw = d.get(), dir = cfg.ledger_dir] {
            std::string review = "Review with: tierctl plan '" + dir + "' (nothing moves until you approve)";
            auto b = raw->plan_blockers();
            return b.empty() ? review : "Not ready to run yet: " + b[0] + ". " + review;
        };
        d->notifier_ = cfg.make_notifier ? cfg.make_notifier(hint) : std::make_unique<OsascriptNotifier>(hint);
    }
    d->gc_ = std::make_unique<GarbageCollector>(*d->ledger_, *d->replicator_, *d->keys_, cfg.gc_config);
    d->policy_ = std::make_unique<PolicyEngine>(*d->ledger_, *d->replicator_, *d->engine_, *d->probe_, tp,
                                                [origin, pfx = d->cfg_.logical_prefix](const FileRec& f) { return origin + "/" + f.path.substr(pfx.size()); },
                                                d->notifier_.get());
    for (const auto& spec :
         cfg.devices) {  // "host:port" (open device), "host:port@keyid" (paired: the secret is in the key store), or "mdns:NAME@keyid"
        if (discovery::is_mdns_spec(spec)) {  // a paired device that is looked up on the network instead of being given an address
            std::string merr;
            auto ms = discovery::parse_mdns_spec(spec, &merr);
            if (!ms) return fail(merr);
            std::string perr;
            auto sec = load_pairing_secret(cfg.key_file, ms->key_id, &perr);
            if (!sec) return fail("device " + spec + ": " + perr);
            Dev dev;
            dev.spec = spec;
            dev.mdns_kid = ms->key_id;
            dev.located = false;
            dev.client = std::make_unique<DeviceClient>("", 0, cfg.device_timeout_ms, std::move(*sec));
            d->devs_.push_back(std::move(dev));
            continue;
        }
        std::string addr = spec, kid;
        if (size_t at = spec.find('@'); at != std::string::npos) {
            addr = spec.substr(0, at);
            kid = spec.substr(at + 1);
        }
        size_t colon = addr.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= addr.size())
            return fail("a device must be host:port or host:port@keyid, got " + spec);
        int port = atoi(addr.c_str() + colon + 1);
        if (port <= 0 || port > 65535) return fail("bad port in " + spec);
        crypto::Bytes secret;
        if (!kid.empty()) {
            std::string perr;
            auto sec = load_pairing_secret(cfg.key_file, kid, &perr);
            if (!sec) return fail("device " + spec + ": " + perr);
            secret = *sec;
        }
        Dev dev;
        dev.spec = spec;
        dev.client = std::make_unique<DeviceClient>(addr.substr(0, colon), static_cast<uint16_t>(port), cfg.device_timeout_ms, std::move(secret));
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

// Looks the "mdns:" devices up on the network and points their clients at wherever they are now. Only an advertisement that names the device's key
// id and says it is paired is followed (discovery::pick); the connection that follows still has to authenticate with the pairing secret, so a
// forged advertisement can at worst make a connection fail.
void Daemon::refresh_mdns() {
    std::vector<std::string> kids;
    {
        std::lock_guard<std::mutex> g(devs_mu_);
        for (auto& d : devs_)
            if (!d.mdns_kid.empty() && std::find(kids.begin(), kids.end(), d.mdns_kid) == kids.end()) kids.push_back(d.mdns_kid);
    }
    if (kids.empty()) return;
    std::vector<discovery::Found> found;
    std::string err;
    if (cfg_.discover) {
        found = cfg_.discover(kids);
    } else {
        std::set<std::string> missing(kids.begin(), kids.end());
        found = discovery::browse(cfg_.mdns_timeout_ms, &err, [&](const discovery::Found& f) {  // done as soon as every wanted device has been seen
            if (f.paired) missing.erase(f.key_id);
            return missing.empty();
        });
    }
    {
        std::lock_guard<std::mutex> g(last_mu_);
        mdns_error_ = err;
    }
    std::lock_guard<std::mutex> g(devs_mu_);
    for (auto& d : devs_) {
        if (d.mdns_kid.empty()) continue;
        if (auto f = discovery::pick(found, d.mdns_kid)) {
            d.client->set_endpoint(f->host, f->port);
            d.located = true;
        }
    }
}

void Daemon::attach_devices() {
    refresh_mdns();
    bool changed = false;
    {
        std::lock_guard<std::mutex> g(devs_mu_);
        for (auto& d : devs_) {
            if (!d.id.empty() || !d.located) continue;
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
    if (notifier_ && cfg_.space_check_seconds > 0) space_ = std::thread([this] { space_loop(); });
    started_ = true;
    return true;
}

void Daemon::stop() {
    stop_ = true;
    if (maint_.joinable()) maint_.join();
    if (space_.joinable()) space_.join();
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
        if (cfg_.gc && !stop_) {
            int64_t last = 0;
            if (auto v = ledger_->get_meta("gc_last_run")) last = atoll(v->c_str());
            if (time(nullptr) - last >= cfg_.gc_interval_seconds) cmd_gc(true);
        }
    }
}

// Free space is checked on its own clock: the maintenance pass can spend minutes copying files to the devices, and a person whose disk is filling up
// should not wait for that to hear about it. The check touches no device and moves nothing (PolicyEngine::check_space).
void Daemon::space_loop() {
    auto next = std::chrono::steady_clock::now();  // the first check is at once: starting the daemon on a full disk should say so
    while (!stop_) {
        if (std::chrono::steady_clock::now() < next) {
            usleep(100000);
            continue;
        }
        next = std::chrono::steady_clock::now() + std::chrono::seconds(cfg_.space_check_seconds);
        SpaceCheck c = policy_->check_space();
        std::lock_guard<std::mutex> g(last_mu_);
        if (c.prompt_failed)
            notify_error_ = "the low-space notification could not be shown (is a user session logged in?); it will be tried again";
        else if (c.prompted || c.space.level == SpaceLevel::OK)
            notify_error_.clear();
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
        for (auto& d : devs_) {
            o << "device " << d.spec << " ";
            if (!d.mdns_kid.empty()) o << (d.located ? "at " + d.client->endpoint() + ", " : std::string("not found on the network, "));
            o << (d.id.empty() ? "not attached" : "attached " + d.id.substr(0, 8)) << "\n";
        }
    }
    {
        std::lock_guard<std::mutex> g(last_mu_);
        if (!notify_error_.empty()) o << "note " << notify_error_ << "\n";
    }
    {
        std::lock_guard<std::mutex> g(last_mu_);
        if (!mdns_error_.empty()) o << "note looking for devices on the network failed: " << mdns_error_ << "\n";
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

// `space`: where the free space stands, what the thresholds are, and whether (and when) the person has been told.
std::string Daemon::cmd_space() {
    SpaceStatus sp = policy_->space();
    std::string last;
    if (auto m = ledger_->get_meta("policy.prompt")) {
        int level = 0;
        long long ts = 0;
        if (sscanf(m->c_str(), "%d:%lld", &level, &ts) == 2 && level != 0) {
            char when[64] = {0};
            time_t t = static_cast<time_t>(ts);
            struct tm tmv;
            localtime_r(&t, &tmv);
            strftime(when, sizeof when, "%Y-%m-%d %H:%M", &tmv);
            last = std::string(level == 2 ? "CRITICAL" : "LOW") + " at " + when;
        }
    }
    std::string text = format_space(sp, probe_->local_snapshots(), last);
    text += notifier_ ? "  Checked every " + std::to_string(cfg_.space_check_seconds) + " seconds" + (cfg_.space_check_seconds ? "" : " (off)") +
                            "; notifications are on.\n"
                      : std::string("  Notifications are off (the daemon was started with notify=0).\n");
    {
        std::lock_guard<std::mutex> g(last_mu_);
        if (!notify_error_.empty()) text += "  PROBLEM: " + notify_error_ + "\n";
    }
    return text + "OK\n";
}

std::string Daemon::cmd_tick() {
    std::lock_guard<std::mutex> g(overlay_->engine_mutex());
    TickReport t = policy_->tick(devices_snapshot());
    std::ostringstream o;
    o << "space " << to_string(t.space.level) << ", copied " << t.replication.files << " file(s), purged " << t.purged << (t.prompted ? ", prompted" : "") << "\n";
    o << "OK\n";
    return o.str();
}

// What stands between a plan and its execution, in plain words (the ledger enforces all of it again when a file moves).
std::vector<std::string> Daemon::plan_blockers() {
    std::vector<std::string> b;
    if (ledger_->get_meta("recovery_acked").value_or("") != "1")
        b.push_back("the recovery phrase has not been acknowledged (tierctl init shows it once and asks you to retype part of it)");
    std::string pre = ledger_->get_meta("test_prefix").value_or("");
    bool test_area = !pre.empty() && cfg_.logical_prefix.compare(0, pre.size(), pre) == 0;
    if (!test_area) {
        if (ledger_->get_meta("backup_acked").value_or("") != "1") {
            b.push_back("no backup is recorded: make a backup, then run: tierctl ack-backup '" + cfg_.ledger_dir + "' I-HAVE-A-BACKUP");
        } else {
            long long at = atoll(ledger_->get_meta("backup_acked_at").value_or("0").c_str());
            long long max_days = atoll(ledger_->get_meta("backup_max_age_days").value_or("30").c_str());
            if (max_days < 1) max_days = 30;
            if (at <= 0)
                b.push_back("the recorded backup has no date: run tierctl ack-backup again after a backup");
            else if (static_cast<long long>(time(nullptr)) - at > max_days * 86400)
                b.push_back("the recorded backup is older than " + std::to_string(max_days) + " days: back up again, then run tierctl ack-backup");
        }
    }
    if (devices_snapshot().size() < 2) b.push_back("fewer than two devices are connected (see: tierctl control '" + cfg_.ledger_dir + "' status)");
    return b;
}

// `plan [free-now] [GiB]`: builds the plan a person should read before approving anything. Nothing moves.
std::string Daemon::cmd_plan(const std::string& arg) {
    bool free_now = false;
    double gib = -1;
    std::istringstream in(arg);
    std::string tok;
    while (in >> tok) {
        if (tok == "free-now")
            free_now = true;
        else {
            char* end = nullptr;
            double v = strtod(tok.c_str(), &end);
            if (end == tok.c_str() || *end || v <= 0 || v > 1e6) return "ERR usage: plan [free-now] [GiB to free]\n";
            gib = v;
        }
    }
    std::lock_guard<std::mutex> g(overlay_->engine_mutex());
    SpaceStatus st = policy_->space();
    uint64_t need = gib > 0 ? static_cast<uint64_t>(gib * (1ull << 30)) : st.need_bytes;
    if (need == 0) {
        std::lock_guard<std::mutex> pg(plan_mu_);
        pending_plan_.reset();
        return "Disk space is fine (" + human_bytes(st.info.avail()) + " free of " + human_bytes(st.info.total) +
               "): nothing needs to move. To plan anyway: plan <GiB to free>\n" + "OK\n";
    }
    TierPlan plan = policy_->plan(need, free_now);  // (freeing space NOW, without the undo period, is only ever what the person asked for)
    PlanContext ctx;
    ctx.blockers = plan_blockers();
    ctx.devices = devices_snapshot().size();
    ctx.quarantine_days = static_cast<int>(cfg_.policy.drop.quarantine_seconds / 86400);
    ctx.valid_minutes = cfg_.plan_ttl_seconds / 60;
    ctx.approve_command = "tierctl control '" + cfg_.ledger_dir + "' approve";
    std::string text = format_plan_review(plan, ctx);
    {
        std::lock_guard<std::mutex> pg(plan_mu_);
        if (plan.entries.empty())
            pending_plan_.reset();
        else {
            pending_plan_ = plan;
            pending_at_ = static_cast<int64_t>(time(nullptr));
        }
    }
    return text + "OK\n";
}

// `approve <plan id>`: executes exactly the plan that was shown, once.
std::string Daemon::cmd_approve(const std::string& arg) {
    std::string id = trim(arg);
    if (id.size() < 8 || id.find_first_not_of("0123456789abcdef") != std::string::npos)
        return "ERR give the plan id shown by plan (at least 8 hex characters)\n";
    std::lock_guard<std::mutex> g(overlay_->engine_mutex());
    TierPlan plan;
    {
        std::lock_guard<std::mutex> pg(plan_mu_);
        if (!pending_plan_) return "ERR there is no plan to approve: run plan first\n";
        if (pending_plan_->digest.compare(0, id.size(), id) != 0)
            return "ERR that is not the plan that was last shown (" + pending_plan_->digest.substr(0, 16) + "): run plan again and read it\n";
        if (static_cast<int64_t>(time(nullptr)) - pending_at_ > cfg_.plan_ttl_seconds) {
            pending_plan_.reset();
            return "ERR the plan is too old to approve: run plan again (the files, the devices and the free space may have changed)\n";
        }
        auto blockers = plan_blockers();
        if (!blockers.empty()) {  // not consumed: fix the problem and approve again
            std::string e = "ERR the plan cannot run yet:";
            for (auto& b : blockers) e += " " + b + ";";
            return e + "\n";
        }
        plan = *pending_plan_;
        pending_plan_.reset();  // a plan is approved once
    }
    std::string err;
    Approval ap = policy_->approve(plan, &err);
    if (ap.plan_digest.empty()) return "ERR " + err + "\n";
    ExecReport rep = policy_->execute(plan, ap, devices_snapshot(), overlay_->gate());
    return format_exec_report(rep) + (rep.rejected ? "ERR rejected\n" : "OK\n");
}

std::string Daemon::cmd_gc(bool run) {
    std::lock_guard<std::mutex> g(overlay_->engine_mutex());
    DeviceMap devs = devices_snapshot();
    GcReport r = run ? gc_->run(devs) : gc_->plan(devs);
    if (run) ledger_->set_meta("gc_last_run", std::to_string(time(nullptr)));
    std::string out = format_gc_report(r);
    for (const auto& kv : devs) {  // a device keeps what it deleted for a while (ADR-0017): say so, so that freed space is not expected at once
        GcStatus st;
        if (!kv.second->gc_status(st).ok() || st.trash_files == 0) continue;
        out += "  device " + kv.first.substr(0, 8) + ": " + std::to_string(st.trash_files) + " file(s) (" + human_bytes(st.trash_bytes) +
               ") are in its trash and are removed for good " + std::to_string(st.trash_retention_s / 86400) +
               " day(s) after deletion; to undo, stop the device and run: tierfs-device <store> --restore-trash\n";
    }
    return out + "OK\n";
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
    if (cmd == "plan") return cmd_plan(arg);
    if (cmd == "space") return cmd_space();
    if (cmd == "approve") return cmd_approve(arg);
    if (cmd == "gc-plan") return cmd_gc(false);
    if (cmd == "gc-run") return cmd_gc(true);
    return "ERR unknown command; try: status, scan, replicate PATH, offload PATH, hydrate PATH, undelete PATH, tick\n";
}

}  // namespace tierfs
