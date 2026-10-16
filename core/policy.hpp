// The tiering policy: WHEN to move files off the Mac, and WHICH ones. See docs/DURABLE_STORE.md section 22.
//
// This layer never deletes anything by itself and never acts without the user. It
//   - watches free space (the OS's own figure) and classifies it OK / LOW / CRITICAL,
//   - copies cold files to the devices in the background, so that when space runs short the emergency path is
//     only "audit, then move",
//   - builds a PLAN (an immutable, digest-stamped list of files, with the reasoning and the risks),
//   - turns the user's approval of exactly that digest into scoped, expiring consents,
//   - executes ONLY the approved plan, re-checking every file at the moment it acts, through the drop engine,
//   - and prompts the user, at a rate that does not nag.
// Only folders the user has opted in ("managed roots") are ever considered.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "dropengine.hpp"
#include "spaceprobe.hpp"

namespace tierfs {

enum class SpaceLevel { OK = 0, LOW = 1, CRITICAL = 2 };
const char* to_string(SpaceLevel l);

struct TierPolicy {
    std::vector<std::string> roots;      // logical path prefixes the user opted in, e.g. "/Users/me/Projects/". Empty: nothing is eligible.
    std::vector<std::string> exclude;    // paths containing any of these are never touched (e.g. "/.git/")
    int64_t min_idle_seconds = 30 * 86400;        // "cold": no access and no modification for this long
    int64_t replicate_idle_seconds = 7 * 86400;   // start copying earlier than we would ever drop
    uint64_t min_size = 1u << 20;                 // small files cost more to track than they free
    // Free-space thresholds: the larger of an absolute size and a fraction of the volume.
    uint64_t low_free_bytes = 20ull << 30;
    double low_free_fraction = 0.15;
    uint64_t critical_free_bytes = 8ull << 30;
    double critical_free_fraction = 0.05;
    double headroom = 1.25;                       // aim to end at (low threshold * headroom) free
    size_t max_files_per_plan = 500;
    int64_t consent_ttl = 3600;                   // an approval is good for an hour
    int64_t prompt_interval = 6 * 3600;           // do not repeat the same prompt more often than this
    int64_t prompt_retry = 600;                   // when a notification could not be shown, try again after this long
    int64_t reconcile_interval = 3600;
    bool auto_purge = true;                       // delete quarantined bytes once the quarantine period is over (still fully gated)
    uint64_t replicate_budget_bytes = 4ull << 30; // background copying per tick
    DropPolicy drop;                              // replica weight, audit freshness, quarantine period
};

struct SpaceStatus {
    SpaceInfo info;
    SpaceLevel level = SpaceLevel::OK;
    uint64_t low_threshold = 0, critical_threshold = 0, target_free = 0;
    uint64_t need_bytes = 0;   // how much more must be free to reach the target (0 when already there)
};

struct PlanEntry {
    std::string file_id, path, root;
    uint64_t size = 0;
    int64_t version = 0, generation = 0, idle_seconds = 0;
    bool needs_replication = false;   // not yet on enough devices: copy first, then move
};

struct TierPlan {
    std::vector<PlanEntry> entries;
    uint64_t bytes_total = 0, bytes_to_replicate = 0, need_bytes = 0;
    SpaceStatus space;
    bool free_now = false;            // CRITICAL mode: delete the quarantined bytes right after the move (after fresh audits)
    int64_t created_at = 0;
    std::vector<std::string> warnings;
    std::map<std::string, size_t> skipped;   // why files were not chosen, with counts
    std::string digest;               // what the user approves
};

struct Approval {
    std::string plan_digest;
    bool free_now = false;
    std::map<std::string, std::string> consent_by_root;
    int64_t approved_at = 0;
};

struct ExecReport {
    bool rejected = false;
    std::string reject_reason;
    size_t dropped = 0, replicated = 0, purged = 0, skipped = 0, failed = 0;
    uint64_t bytes_dropped = 0, bytes_purged = 0;
    uint64_t avail_before = 0, avail_after = 0;
    bool target_met = false;
    std::vector<std::string> notes;
};

struct ReplicationReport {
    size_t files = 0, failed = 0;
    uint64_t bytes = 0;
    std::vector<std::string> notes;
};

class Notifier {
public:
    virtual ~Notifier() = default;
    // Tells the person. False if it could not be shown (then it is tried again soon instead of being treated as said).
    virtual bool low_space(const SpaceStatus& status, const TierPlan& plan) = 0;
};

// The cheap, frequent part of the policy: is space short, and has the person been told? Touches no device and moves nothing.
struct SpaceCheck {
    SpaceStatus space;
    bool prompted = false;        // a notification was shown now
    bool prompt_failed = false;   // one was due but could not be shown
    TierPlan plan;                // made only when space is short
};

struct TickReport {
    SpaceStatus space;
    ReplicationReport replication;
    size_t purged = 0;
    bool reconciled = false, prompted = false, prompt_failed = false;
    TierPlan plan;
};

std::string format_plan(const TierPlan& plan);
std::string format_notification(const SpaceStatus& status, const TierPlan& plan, const std::string& hint = "");
// "1.4 GiB", "230 KiB", "12 bytes": the unit that reads well.
std::string human_bytes(uint64_t bytes);

// What a person needs to read before saying yes (docs/adr/0012): what will move, from where, what happens to it, what could go wrong, and exactly how
// to approve.
struct PlanContext {
    std::vector<std::string> blockers;  // what must be fixed before this plan can run, in plain words (the plan is shown, but approving is refused)
    int quarantine_days = 7;
    size_t devices = 0;           // how many devices are connected
    std::string approve_command;  // the command that approves this plan, without the plan id ("tierctl control /path/ledger approve")
    int64_t valid_minutes = 60;
    size_t list_files = 10;  // the largest files are named; the rest are counted
    size_t list_folders = 8;
};
std::string format_plan_review(const TierPlan& plan, const PlanContext& ctx);
// What an executed plan did, in plain words.
std::string format_exec_report(const ExecReport& r);

// What the notification tells the person to do next, worked out when it is shown (so it can say what stands in the way right now).
using HintFn = std::function<std::string()>;

// A macOS notification through osascript (no extra dependencies). Only ever shows text; the user decides.
class OsascriptNotifier : public Notifier {
public:
    explicit OsascriptNotifier(std::string hint = "") : hint_([h = std::move(hint)] { return h; }) {}  // hint: how to review the plan
    explicit OsascriptNotifier(HintFn hint, std::string program = "/usr/bin/osascript") : hint_(std::move(hint)), program_(std::move(program)) {}
    bool low_space(const SpaceStatus& status, const TierPlan& plan) override;

private:
    HintFn hint_;
    std::string program_;   // (a test points this at /usr/bin/true or /usr/bin/false)
};

// The first thing wrong with the thresholds, or empty. Low must be at least as demanding as critical (in bytes and in fraction), fractions are
// below 90%, and nothing is zero-sized in a way that would make every check pass or fail.
std::string validate_thresholds(const TierPolicy& p);
// The `space` report: level, what the thresholds are, how much would have to move, whether the system has snapshots that hold deleted space, and
// when the person was last told.
std::string format_space(const SpaceStatus& s, int local_snapshots, const std::string& last_notice);

class PolicyEngine {
public:
    PolicyEngine(Ledger& ledger, Replicator& replicator, DropEngine& engine, SpaceProbe& probe, TierPolicy policy,
                 OriginResolver resolver, Notifier* notifier = nullptr);

    SpaceStatus space();
    static SpaceLevel level_for(const SpaceInfo& info, const TierPolicy& policy);

    // Read-only: which files would be moved to free `need_bytes`, and why not the others.
    TierPlan plan(uint64_t need_bytes, bool free_now);
    // The user said yes to exactly this plan (by its digest). Creates one consent per managed root, each
    // expiring, each recording what was approved.
    Approval approve(const TierPlan& plan, std::string* error);
    // Acts on the approved plan and nothing else.
    ExecReport execute(const TierPlan& plan, const Approval& approval, const DeviceMap& devices, FileGate* gate = nullptr);

    // Non-destructive background work: copy cold files to devices (within a byte budget).
    ReplicationReport replicate_step(const DeviceMap& devices, uint64_t budget_bytes);
    // Delete quarantined bytes whose period is over (each fully gated by fresh audits in the engine and the ledger).
    size_t purge_due(const DeviceMap& devices);
    // One pass of everything a daemon would do periodically.
    TickReport tick(const DeviceMap& devices);
    // Just the free-space part of a tick: measures, and when short makes the plan and tells the person (rate-limited, retried if it could not be
    // shown). Cheap and safe to call every few seconds from its own thread; calls from several threads are serialised.
    SpaceCheck check_space();

    static std::string compute_digest(const TierPlan& plan);

private:
    struct Verdict {
        bool eligible = false;
        bool needs_replication = false;
        std::string skip_reason;
        std::string root;
    };
    Verdict classify(const FileRec& f, int64_t now, int64_t idle_threshold, bool include_replicated_enough);
    std::string root_of(const std::string& path) const;
    bool is_excluded(const std::string& path) const;
    double attainable_weight();
    bool replicate_to_weight(const FileRec& f, const DeviceMap& devices, std::vector<std::string>* notes);
    bool should_prompt(SpaceLevel level, int64_t now);
    void record_prompt(SpaceLevel level, int64_t now);

    Ledger& ledger_;
    Replicator& replicator_;
    DropEngine& engine_;
    SpaceProbe& probe_;
    TierPolicy policy_;
    OriginResolver resolve_;
    Notifier* notifier_;
    std::mutex prompt_mu_;   // a check and the record of its prompt are one step
};

}  // namespace tierfs
