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
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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
    std::vector<std::string> devices;        // "host:port"
    std::string control_socket;              // default: <ledger_dir>/control.sock; "none" disables
    int device_timeout_ms = 5000;
    int maint_seconds = 60;                  // maintenance period; 0 = no background thread
    bool background_replication = true;      // the maintenance thread copies cold files to the devices (never moves or deletes anything)
    bool scan_at_start = true;
    bool notify = true;                      // macOS notifications when space runs short (tests turn this off)
    int64_t write_wait_ms = 30000;
    size_t cache_bytes = 64u << 20;
    int readahead_chunks = 4;                // a sequential reader of an offloaded file gets up to this many chunks fetched ahead (0 = off)
    TierPolicy policy;                       // roots are set to the logical prefix
    // Garbage collection on the devices (ADR-0010): forgets old versions and deleted files, and has the devices free their space. Off unless asked:
    // `gc` makes the maintenance thread run it every gc_interval_seconds; `gc-plan` and `gc-run` on the control socket work either way.
    bool gc = false;
    int64_t gc_interval_seconds = 86400;
    GcConfig gc_config;
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
    DeviceMap devices_snapshot();
    void maintenance_loop();
    void control_loop();
    std::string cmd_status();
    std::string cmd_files(const std::string& path, bool drop);   // replicate (drop=false) or offload (drop=true)
    std::string cmd_tick();
    std::string cmd_gc(bool run);

    DaemonConfig cfg_;
    std::unique_ptr<Ledger> ledger_;
    std::unique_ptr<crypto::Keys> keys_;
    struct Dev { std::string spec; std::unique_ptr<DeviceClient> client; std::string id; };
    std::vector<Dev> devs_;
    std::mutex devs_mu_;
    std::unique_ptr<Replicator> replicator_;
    std::unique_ptr<DropEngine> engine_;
    std::unique_ptr<Overlay> overlay_;
    std::unique_ptr<Scanner> scanner_;
    std::unique_ptr<SpaceProbe> probe_;
    std::unique_ptr<PolicyEngine> policy_;
    std::unique_ptr<GarbageCollector> gc_;
    std::unique_ptr<Notifier> notifier_;

    std::atomic<bool> stop_{false};
    bool started_ = false;
    std::thread maint_, control_;
    int listen_fd_ = -1;
    std::string socket_path_;
    std::vector<std::string> notes_;
    std::mutex last_mu_;
    std::string last_scan_;
};

}  // namespace tierfs
