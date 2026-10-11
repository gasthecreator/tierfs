#include "policy.hpp"

#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <algorithm>
#include <cstdio>
#include <set>

extern char** environ;

namespace tierfs {
namespace {

std::string gib(uint64_t bytes) {
    char buf[32];
    if (bytes >= (1ull << 30)) snprintf(buf, sizeof buf, "%.1f GiB", bytes / double(1ull << 30));
    else snprintf(buf, sizeof buf, "%.1f MiB", bytes / double(1ull << 20));
    return buf;
}

std::string idle_text(int64_t seconds) {
    char buf[32];
    if (seconds >= 2 * 86400) snprintf(buf, sizeof buf, "%lld days", static_cast<long long>(seconds / 86400));
    else snprintf(buf, sizeof buf, "%lld hours", static_cast<long long>(seconds / 3600));
    return buf;
}

// Roots must end in '/', so "/Users/me/Proj" cannot silently cover "/Users/me/Projects2/".
std::string normalise_root(std::string r) {
    if (!r.empty() && r.back() != '/') r += '/';
    return r;
}

int64_t activity_of(const FileRec& f) { return std::max(f.last_access, f.mtime); }

}  // namespace

const char* to_string(SpaceLevel l) {
    switch (l) {
        case SpaceLevel::OK: return "OK";
        case SpaceLevel::LOW: return "LOW";
        case SpaceLevel::CRITICAL: return "CRITICAL";
    }
    return "?";
}

PolicyEngine::PolicyEngine(Ledger& ledger, Replicator& replicator, DropEngine& engine, SpaceProbe& probe, TierPolicy policy,
                           OriginResolver resolver, Notifier* notifier)
    : ledger_(ledger), replicator_(replicator), engine_(engine), probe_(probe), policy_(std::move(policy)),
      resolve_(std::move(resolver)), notifier_(notifier) {
    for (auto& r : policy_.roots) r = normalise_root(r);
}

// ---------------------------------------------------------------- free space

SpaceLevel PolicyEngine::level_for(const SpaceInfo& info, const TierPolicy& p) {
    uint64_t avail = info.avail();
    uint64_t low = std::max<uint64_t>(p.low_free_bytes, static_cast<uint64_t>(p.low_free_fraction * info.total));
    uint64_t crit = std::max<uint64_t>(p.critical_free_bytes, static_cast<uint64_t>(p.critical_free_fraction * info.total));
    if (avail < crit) return SpaceLevel::CRITICAL;
    if (avail < low) return SpaceLevel::LOW;
    return SpaceLevel::OK;
}

SpaceStatus PolicyEngine::space() {
    SpaceStatus s;
    s.info = probe_.measure();
    s.low_threshold = std::max<uint64_t>(policy_.low_free_bytes, static_cast<uint64_t>(policy_.low_free_fraction * s.info.total));
    s.critical_threshold = std::max<uint64_t>(policy_.critical_free_bytes, static_cast<uint64_t>(policy_.critical_free_fraction * s.info.total));
    s.target_free = static_cast<uint64_t>(s.low_threshold * policy_.headroom);
    s.level = level_for(s.info, policy_);
    uint64_t avail = s.info.avail();
    s.need_bytes = (s.level != SpaceLevel::OK && avail < s.target_free) ? s.target_free - avail : 0;
    return s;
}

// ---------------------------------------------------------------- which files

std::string PolicyEngine::root_of(const std::string& path) const {
    for (const auto& r : policy_.roots)
        if (!r.empty() && path.compare(0, r.size(), r) == 0) return r;
    return "";
}

bool PolicyEngine::is_excluded(const std::string& path) const {
    if (path.find("/.tierfs") != std::string::npos) return true;   // our own bookkeeping is never tiered
    for (const auto& e : policy_.exclude)
        if (!e.empty() && path.find(e) != std::string::npos) return true;
    return false;
}

double PolicyEngine::attainable_weight() {
    double w = 0;
    for (const auto& d : ledger_.list_devices())
        if (d.state == "active") w += d.cls == "C" ? 0.5 : 1.0;
    return w;
}

PolicyEngine::Verdict PolicyEngine::classify(const FileRec& f, int64_t now, int64_t idle_threshold, bool include_replicated_enough) {
    Verdict v;
    v.root = root_of(f.path);
    if (v.root.empty()) { v.skip_reason = "outside the managed folders"; return v; }
    if (is_excluded(f.path)) { v.skip_reason = "excluded path"; return v; }
    if (f.state != FileState::LOCAL && f.state != FileState::REPLICATING && f.state != FileState::REPLICATED) {
        v.skip_reason = std::string("state ") + to_string(f.state);
        return v;
    }
    if (!f.local_present) { v.skip_reason = "no local bytes"; return v; }
    if (f.size < policy_.min_size) { v.skip_reason = "too small"; return v; }
    if (now - activity_of(f) < idle_threshold) { v.skip_reason = "not cold enough"; return v; }

    double w = f.current_version > 0 ? ledger_.committed_weight(f.file_id, f.current_version) : 0.0;
    bool enough = w >= policy_.drop.min_weight;
    if (f.state == FileState::REPLICATED && enough) {
        if (!include_replicated_enough) { v.skip_reason = "already has enough copies"; return v; }
        v.eligible = true;
        return v;
    }
    if (attainable_weight() < policy_.drop.min_weight) {
        v.skip_reason = "not enough trusted devices to ever hold enough copies";
        return v;
    }
    v.eligible = true;
    v.needs_replication = true;
    return v;
}

// ---------------------------------------------------------------- plan

std::string PolicyEngine::compute_digest(const TierPlan& plan) {
    std::string m = "tierfs-plan-v1\n" + std::to_string(plan.created_at) + "|" + (plan.free_now ? "1" : "0") + "|" +
                    std::to_string(plan.need_bytes) + "\n";
    for (const auto& e : plan.entries)
        m += e.file_id + "|" + std::to_string(e.generation) + "|" + std::to_string(e.size) + "|" + e.root + "|" + (e.needs_replication ? "1" : "0") + "\n";
    return crypto::sha256_hex(reinterpret_cast<const uint8_t*>(m.data()), m.size());
}

TierPlan PolicyEngine::plan(uint64_t need_bytes, bool free_now) {
    TierPlan p;
    p.space = space();
    p.need_bytes = need_bytes;
    p.free_now = free_now;
    const int64_t now = ledger_.now();
    p.created_at = now;

    struct Cand { PlanEntry e; double score; };
    std::vector<Cand> cands;
    if (need_bytes > 0) {
        for (const auto& f : ledger_.list_files()) {
            Verdict v = classify(f, now, policy_.min_idle_seconds, true);
            if (!v.eligible) { p.skipped[v.skip_reason]++; continue; }
            Cand c;
            c.e.file_id = f.file_id;
            c.e.path = f.path;
            c.e.root = v.root;
            c.e.size = f.size;
            c.e.version = f.current_version;
            c.e.generation = f.generation;
            c.e.idle_seconds = now - activity_of(f);
            c.e.needs_replication = v.needs_replication;
            // The biggest, coldest files first: size times idle days. Simple enough to explain to the user.
            c.score = static_cast<double>(f.size) * (static_cast<double>(c.e.idle_seconds) / 86400.0);
            cands.push_back(std::move(c));
        }
        std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
            if (a.score != b.score) return a.score > b.score;
            return a.e.path < b.e.path;
        });
        uint64_t acc = 0;
        size_t used = 0;
        for (; used < cands.size() && p.entries.size() < policy_.max_files_per_plan && acc < need_bytes; used++) {
            acc += cands[used].e.size;
            p.bytes_total += cands[used].e.size;
            if (cands[used].e.needs_replication) p.bytes_to_replicate += cands[used].e.size;
            p.entries.push_back(cands[used].e);
        }
        if (used < cands.size()) p.skipped["eligible, but not needed to reach the target"] += cands.size() - used;
        if (p.bytes_total < need_bytes && !cands.empty() && used == cands.size())
            p.warnings.push_back("even every eligible file would free only " + gib(p.bytes_total) + " of the " + gib(need_bytes) + " needed");
    }

    if (need_bytes > 0 && p.entries.empty()) p.warnings.push_back("no eligible files: nothing can be freed automatically");
    if (int snaps = probe_.local_snapshots(); snaps > 0 && need_bytes > 0)
        p.warnings.push_back(std::to_string(snaps) + " APFS local snapshot(s) exist and keep deleted data alive: freed space may not appear until they are thinned");
    if (ledger_.get_meta("recovery_acked").value_or("") != "1")
        p.warnings.push_back("the recovery phrase has not been acknowledged: moving files will be refused");
    if (ledger_.get_meta("backup_acked").value_or("") != "1")
        p.warnings.push_back("no backup has been acknowledged: moving real files will be refused");
    if (attainable_weight() < policy_.drop.min_weight)
        p.warnings.push_back("fewer trusted devices than the copies required: files cannot be moved safely");
    if (need_bytes > 0 && !p.free_now && p.space.level == SpaceLevel::CRITICAL)
        p.warnings.push_back("space is critical but this plan keeps the quarantine period: nothing will be freed until it ends");
    p.digest = compute_digest(p);
    return p;
}

// ---------------------------------------------------------------- approval

Approval PolicyEngine::approve(const TierPlan& plan, std::string* error) {
    Approval a;
    auto fail = [&](const std::string& why) { if (error) *error = why; return Approval{}; };
    if (plan.digest != compute_digest(plan)) return fail("the plan was altered after it was built");
    if (plan.entries.empty()) return fail("there is nothing in this plan to approve");
    std::map<std::string, std::pair<size_t, uint64_t>> per_root;
    for (const auto& e : plan.entries) {
        per_root[e.root].first++;
        per_root[e.root].second += e.size;
    }
    a.plan_digest = plan.digest;
    a.free_now = plan.free_now;
    a.approved_at = ledger_.now();
    for (const auto& kv : per_root) {
        std::string ack = "approved plan " + plan.digest.substr(0, 16) + ": " + std::to_string(kv.second.first) + " files (" + gib(kv.second.second) +
                          ") under " + kv.first + (plan.free_now ? "; free the space NOW" : "; keep the quarantine period") +
                          "; the local copies are deleted for good once verified copies exist and the quarantine ends";
        std::string id = ledger_.create_consent(kv.first, policy_.consent_ttl, ack);
        if (id.empty()) return fail("cannot record the consent for " + kv.first);
        a.consent_by_root[kv.first] = id;
    }
    return a;
}

// ---------------------------------------------------------------- execution

bool PolicyEngine::replicate_to_weight(const FileRec& f0, const DeviceMap& devices, std::vector<std::string>* notes) {
    const std::string local = resolve_(f0);
    for (const auto& kv : devices) {
        auto f = ledger_.get_file(f0.file_id);
        if (!f) return false;
        if (f->current_version > 0 && f->state == FileState::REPLICATED && ledger_.committed_weight(f->file_id, f->current_version) >= policy_.drop.min_weight) return true;
        auto dr = ledger_.get_device(kv.first);
        if (!dr || dr->state != "active" || !kv.second) continue;
        bool already = false;
        if (f->current_version > 0)
            for (const auto& r : ledger_.get_replicas(f->file_id, f->current_version))
                if (r.device_id == kv.first && r.state == ReplicaState::COMMITTED) already = true;
        if (already) continue;
        ReplicateOutcome o = replicator_.replicate(*kv.second, kv.first, f->file_id, local);
        if (!o.ok) {
            if (notes) notes->push_back(f->path + ": replicating to " + kv.first.substr(0, 8) + " failed: " + o.why);
            if (o.file_changed) return false;   // the file is being modified: leave it alone
        }
    }
    auto f = ledger_.get_file(f0.file_id);
    return f && f->current_version > 0 && f->state == FileState::REPLICATED &&
           ledger_.committed_weight(f->file_id, f->current_version) >= policy_.drop.min_weight;
}

ExecReport PolicyEngine::execute(const TierPlan& plan, const Approval& approval, const DeviceMap& devices, FileGate* gate) {
    ExecReport r;
    auto reject = [&](const std::string& why) { r.rejected = true; r.reject_reason = why; return r; };
    if (plan.digest != compute_digest(plan) || approval.plan_digest != plan.digest) return reject("the plan was altered after it was approved");
    if (approval.free_now != plan.free_now) return reject("the approval does not match the plan's mode");
    r.avail_before = probe_.measure().avail();

    uint64_t progress = 0;
    for (const auto& e : plan.entries) {
        if (progress >= plan.need_bytes) { r.target_met = true; break; }
        auto f = ledger_.get_file(e.file_id);
        if (!f) { r.skipped++; r.notes.push_back(e.path + ": no longer tracked"); continue; }
        // Everything is re-checked NOW: the plan is hours old at worst, and files move on.
        if (f->generation != e.generation || f->size != e.size) { r.skipped++; r.notes.push_back(e.path + ": changed since the plan was made"); continue; }
        if (ledger_.now() - activity_of(*f) < policy_.min_idle_seconds) { r.skipped++; r.notes.push_back(e.path + ": used since the plan was made"); continue; }
        if (root_of(f->path) != e.root || is_excluded(f->path)) { r.skipped++; r.notes.push_back(e.path + ": no longer in a managed folder"); continue; }
        if (f->state != FileState::LOCAL && f->state != FileState::REPLICATING && f->state != FileState::REPLICATED) {
            r.skipped++;
            r.notes.push_back(e.path + ": is now " + to_string(f->state));
            continue;
        }
        auto cit = approval.consent_by_root.find(e.root);
        if (cit == approval.consent_by_root.end()) { r.skipped++; r.notes.push_back(e.path + ": its folder was not part of the approval"); continue; }

        {   // the ledger only knows what the filesystem layer told it: look at the file itself too
            struct stat st;
            if (stat(resolve_(*f).c_str(), &st) != 0 || static_cast<uint64_t>(st.st_size) != e.size) {
                r.skipped++;
                r.notes.push_back(e.path + ": the file on disk is not the one that was approved");
                continue;
            }
        }
        bool needed_copy = !(f->state == FileState::REPLICATED && f->current_version > 0 &&
                             ledger_.committed_weight(f->file_id, f->current_version) >= policy_.drop.min_weight);
        if (needed_copy) {
            if (!replicate_to_weight(*f, devices, &r.notes)) { r.failed++; r.notes.push_back(e.path + ": could not reach the required number of copies"); continue; }
            r.replicated++;
            auto after = ledger_.get_file(e.file_id);   // and once more after the copy: it must still be the approved file
            if (!after || after->generation != e.generation || after->size != e.size) {
                r.skipped++;
                r.notes.push_back(e.path + ": changed while being copied");
                continue;
            }
        }
        DropOutcome d = engine_.drop(e.file_id, cit->second, devices, gate);
        if (!d.ok) { r.failed++; r.notes.push_back(e.path + ": " + d.why); continue; }
        r.dropped++;
        r.bytes_dropped += e.size;
        if (plan.free_now) {
            PurgeOutcome p = engine_.purge(d.intent_id, devices, true);
            if (p.ok) { r.purged++; r.bytes_purged += e.size; progress += e.size; }
            else r.notes.push_back(e.path + ": moved to quarantine, but could not be deleted yet: " + p.why);
        } else {
            progress += e.size;   // it will be freed when the quarantine period ends
        }
    }
    if (progress >= plan.need_bytes && plan.need_bytes > 0) r.target_met = true;
    r.avail_after = probe_.measure().avail();
    return r;
}

// ---------------------------------------------------------------- background work

ReplicationReport PolicyEngine::replicate_step(const DeviceMap& devices, uint64_t budget_bytes) {
    ReplicationReport rep;
    const int64_t now = ledger_.now();
    struct Cand { FileRec f; int64_t idle; };
    std::vector<Cand> cands;
    for (const auto& f : ledger_.list_files()) {
        Verdict v = classify(f, now, policy_.replicate_idle_seconds, false);
        if (v.eligible && v.needs_replication) cands.push_back({f, now - activity_of(f)});
    }
    std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
        if (a.idle != b.idle) return a.idle > b.idle;   // the coldest first: they are the likeliest to be moved
        return a.f.path < b.f.path;
    });
    for (const auto& c : cands) {
        if (rep.bytes >= budget_bytes) break;
        if (replicate_to_weight(c.f, devices, &rep.notes)) { rep.files++; rep.bytes += c.f.size; }
        else rep.failed++;
    }
    return rep;
}

size_t PolicyEngine::purge_due(const DeviceMap& devices) {
    size_t n = 0;
    const int64_t now = ledger_.now();
    for (const auto& q : ledger_.list_quarantine(QuarantineState::HELD)) {
        if (now - q.held_at < policy_.drop.quarantine_seconds) continue;
        if (engine_.purge(q.intent_id, devices, false).ok) n++;
    }
    return n;
}

// ---------------------------------------------------------------- prompting

namespace {
bool parse_prompt(const std::string& s, int* level, int64_t* ts) {
    return sscanf(s.c_str(), "%d:%lld", level, reinterpret_cast<long long*>(ts)) == 2;
}
}  // namespace

bool PolicyEngine::should_prompt(SpaceLevel level, int64_t now) {
    int last_level = 0;
    int64_t last_ts = 0;
    auto m = ledger_.get_meta("policy.prompt");
    if (!m || !parse_prompt(*m, &last_level, &last_ts)) return true;
    if (static_cast<int>(level) > last_level) return true;                                // it got worse: say so at once
    return now - last_ts >= policy_.prompt_interval;   // same or better level: at most once per interval
}

void PolicyEngine::record_prompt(SpaceLevel level, int64_t now) {
    ledger_.set_meta("policy.prompt", std::to_string(static_cast<int>(level)) + ":" + std::to_string(now));
}

TickReport PolicyEngine::tick(const DeviceMap& devices) {
    TickReport r;
    const int64_t now = ledger_.now();
    r.space = space();

    // keep the picture of the devices honest
    int64_t last_rec = 0;
    if (auto m = ledger_.get_meta("policy.reconcile")) last_rec = atoll(m->c_str());
    if (now - last_rec >= policy_.reconcile_interval) {
        for (const auto& kv : devices)
            if (kv.second) replicator_.reconcile(*kv.second, kv.first, false);
        ledger_.set_meta("policy.reconcile", std::to_string(now));
        r.reconciled = true;
    }
    if (policy_.auto_purge) r.purged = purge_due(devices);
    r.replication = replicate_step(devices, policy_.replicate_budget_bytes);

    if (r.space.level == SpaceLevel::OK) {
        auto m = ledger_.get_meta("policy.prompt");
        int l = 0;
        int64_t t = 0;
        if (m && parse_prompt(*m, &l, &t) && l != 0) record_prompt(SpaceLevel::OK, now);   // forget: the next shortage prompts immediately
        return r;
    }
    r.plan = plan(r.space.need_bytes, r.space.level == SpaceLevel::CRITICAL);
    if (notifier_ && should_prompt(r.space.level, now)) {
        notifier_->low_space(r.space, r.plan);
        record_prompt(r.space.level, now);
        r.prompted = true;
    }
    return r;
}

// ---------------------------------------------------------------- text

std::string format_plan(const TierPlan& plan) {
    std::string s = "Space: " + gib(plan.space.info.avail()) + " free of " + gib(plan.space.info.total) + " (" + to_string(plan.space.level) + "); " +
                    gib(plan.need_bytes) + " needed to reach the target.\n";
    s += std::to_string(plan.entries.size()) + " file(s), " + gib(plan.bytes_total) + " in all" +
         (plan.bytes_to_replicate ? ", of which " + gib(plan.bytes_to_replicate) + " must be copied to devices first" : std::string()) + ".\n";
    s += plan.free_now ? "Mode: free the space NOW (the quarantine period is skipped, after fresh checks).\n"
                       : "Mode: keep the quarantine period; space is freed when it ends.\n";
    for (const auto& e : plan.entries)
        s += "  " + e.path + "  " + gib(e.size) + ", idle " + idle_text(e.idle_seconds) + (e.needs_replication ? "  [copy first]" : "") + "\n";
    for (const auto& kv : plan.skipped) s += "  not chosen: " + kv.first + " (" + std::to_string(kv.second) + ")\n";
    for (const auto& w : plan.warnings) s += "  WARNING: " + w + "\n";
    s += "Plan " + plan.digest.substr(0, 16) + "\n";
    return s;
}

std::string format_notification(const SpaceStatus& status, const TierPlan& plan) {
    std::string head = std::string(status.level == SpaceLevel::CRITICAL ? "Disk space is critically low" : "Disk space is low") + ": " +
                       gib(status.info.avail()) + " free of " + gib(status.info.total) + ". ";
    if (plan.entries.empty()) return head + "No cold files in your tiered folders can be moved automatically.";
    return head + "tierfs can move " + std::to_string(plan.entries.size()) + " cold file(s) (" + gib(plan.bytes_total) + ") off this Mac. Review and approve to continue.";
}

void OsascriptNotifier::low_space(const SpaceStatus& status, const TierPlan& plan) {
    std::string msg = format_notification(status, plan), esc;
    for (char c : msg) { if (c == '"' || c == '\\') esc += '\\'; esc += c; }
    std::string script = "display notification \"" + esc + "\" with title \"tierfs\"";
    char* argv[] = {const_cast<char*>("osascript"), const_cast<char*>("-e"), const_cast<char*>(script.c_str()), nullptr};
    pid_t pid;
    if (posix_spawn(&pid, "/usr/bin/osascript", nullptr, nullptr, argv, environ) == 0) waitpid(pid, nullptr, 0);
}

}  // namespace tierfs
