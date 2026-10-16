// The daemon: everything a mounted tierfs needs, wired together. See docs/DURABLE_STORE.md section 24 (3h-4).
//
// It owns the ledger, the keys, the connections to the devices, the replicator and drop engine, the overlay (the filesystem
// semantics), the scanner and the policy engine, and runs two small threads: a maintenance thread (re-attach devices that
// were down, scan the origin, run the policy's background work) and a control thread that answers a line protocol on a unix
// socket (status, scan, replicate, offload, hydrate, undelete, tick). The FUSE driver is a thin C wrapper around Overlay
// (see tfs_c.h); this class is what it wraps, and what the tests drive without any mount.
//
// What the control socket is: the socket file is created mode 0600 in the ledger directory, so sending a command IS the user's
// explicit action. `offload` therefore creates a short-lived consent for exactly the files named and then goes through the same
// drop engine and ledger gates as everything else (recovery phrase and backup acknowledged, fresh audits of enough replicas...).
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "discovery.hpp"
#include "dropengine.hpp"
#include "gc.hpp"
#include "ledger.hpp"
#include "overlay.hpp"
#include "policy.hpp"
#include "replicator.hpp"
#include "scanner.hpp"
#include "spaceprobe.hpp"

namespace tierfs {

struct DaemonConfig {
    std::string ledger_dir;                  // the ledger and the control socket live here
    std::string origin_dir;                  // the real folder holding the local bytes
    std::string logical_prefix;              // e.g. "/Users/me/Projects/"
    std::string key_file;                    // the key source: "keychain", "dir:PATH", or a key file of 64 hex characters (core/keysource.hpp)
    std::vector<std::string> devices;        // "host:port", "host:port@keyid" or "mdns:NAME@keyid"
    std::string control_socket;              // default: <ledger_dir>/control.sock; "none" disables
    int device_timeout_ms = 5000;
    // "mdns:" device entries are looked up on the network at every maintenance pass (ADR-0013). `discover` is how: given the key ids wanted, it returns
    // what it found (the default asks the system's Bonjour service for up to mdns_timeout_ms; tests give a fake).
    using Discoverer = std::function<std::vector<discovery::Found>(const std::vector<std::string>& key_ids)>;
    Discoverer discover;
    int mdns_timeout_ms = 1500;
    int maint_seconds = 60;                  // maintenance period; 0 = no background thread
    bool background_replication = true;      // the maintenance thread copies cold files to the devices (never moves or deletes anything)
    bool scan_at_start = true;
    bool notify = true;                      // macOS notifications when space runs short (tests turn this off)
    int64_t write_wait_ms = 30000;
    size_t cache_bytes = 64u << 20;
    int readahead_chunks = 4;                // a sequential reader of an offloaded file gets up to this many chunks fetched ahead (0 = off)
    TierPolicy policy;                       // roots are set to the logical prefix (free-space thresholds: low_free_bytes, critical_free_bytes, ...)
    // How often free space is checked, in seconds, by a thread of its own (so a long copy to the devices never delays a warning). 0 = off. The check
    // is one statfs and a ledger read; the person is told at most once per policy.prompt_interval for the same shortage, at once if it gets worse.
    int space_check_seconds = 30;
    // Replacements for the system's free-space measurement and notification, for tests (the notifier is given the function that words its hint).
    std::function<std::unique_ptr<SpaceProbe>(const std::string& origin)> make_probe;
    std::function<std::unique_ptr<Notifier>(HintFn hint)> make_notifier;
    // Garbage collection on the devices (ADR-0010): forgets old versions and deleted files, and has the devices free their space. Off unless asked:
    // `gc` makes the maintenance thread run it every gc_interval_seconds; `gc-plan` and `gc-run` on the control socket work either way.
    bool gc = false;
    int64_t gc_interval_seconds = 86400;
    GcConfig gc_config;
    int64_t plan_ttl_seconds = 3600;  // a space plan can be approved for this long after it was made (then it is stale: make it again)
};

class Daemon {
public:
    static std::unique_ptr<Daemon> create(const DaemonConfig& cfg, std::string* err);
    ~Daemon();
    Daemon(const Daemon&) = delete;
    Daemon& operator=(const Daemon&) = delete;

    // Attaches the devices that are reachable, finishes every interrupted drop/purge/restore/hydration, scans the origin, and
    // starts the threads. Fails (with a reason) only when the ledger or keys are unusable; unreachable devices are retried later.
    bool start(std::string* err);
    void stop();

    Overlay& overlay() { return *overlay_; }
    Ledger& ledger() { return *ledger_; }
    const DaemonConfig& config() const { return cfg_; }
    std::vector<std::string> startup_notes() const { return notes_; }   // what recovery and the first scan did

    // One command line in, one reply out (lines, ending with "OK" or "ERR <reason>"). The socket thread uses this; so do tests.
    std::string control(const std::string& line);

private:
    explicit Daemon(const DaemonConfig& cfg) : cfg_(cfg) {}
    void attach_devices();
    void refresh_mdns();
    DeviceMap devices_snapshot();
    void maintenance_loop();
    void space_loop();
    std::string cmd_space();
    void control_loop();
    std::string cmd_status();
    std::string cmd_files(const std::string& path, bool drop);   // replicate (drop=false) or offload (drop=true)
    std::string cmd_tick();
    std::string cmd_gc(bool run);
    std::string cmd_plan(const std::string& arg);
    std::string cmd_approve(const std::string& arg);
    std::vector<std::string> plan_blockers();

    DaemonConfig cfg_;
    std::unique_ptr<Ledger> ledger_;
    std::unique_ptr<crypto::Keys> keys_;
    struct Dev {
        std::string spec;
        std::unique_ptr<DeviceClient> client;
        std::string id;
        std::string mdns_kid;    // set for an "mdns:" entry: the key id that identifies the device wherever it is
        bool located = true;     // false until an "mdns:" entry has been found on the network once
    };
    std::vector<Dev> devs_;
    std::mutex devs_mu_;
    std::unique_ptr<Replicator> replicator_;
    std::unique_ptr<DropEngine> engine_;
    std::unique_ptr<Overlay> overlay_;
    std::unique_ptr<Scanner> scanner_;
    std::unique_ptr<SpaceProbe> probe_;
    std::unique_ptr<PolicyEngine> policy_;
    std::unique_ptr<GarbageCollector> gc_;
    std::mutex plan_mu_;
    std::optional<TierPlan> pending_plan_;  // the plan a person was last shown: only this one can be approved, and only once
    int64_t pending_at_ = 0;
    std::unique_ptr<Notifier> notifier_;

    std::atomic<bool> stop_{false};
    bool started_ = false;
    std::thread maint_, control_, space_;
    int listen_fd_ = -1;
    std::string socket_path_;
    std::vector<std::string> notes_;
    std::mutex last_mu_;
    std::string last_scan_;
    std::string mdns_error_;   // why the last network lookup failed (guarded by last_mu_)
    std::string notify_error_; // set while the last notification could not be shown (guarded by last_mu_)
};

}  // namespace tierfs
