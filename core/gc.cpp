#include "gc.hpp"

#include <algorithm>
#include <map>

#include "crashpoint.hpp"

namespace tierfs {

uint64_t GcReport::manifests_deleted() const { uint64_t n = 0; for (auto& d : devices) n += d.manifests_deleted; return n; }
uint64_t GcReport::chunks_swept() const { uint64_t n = 0; for (auto& d : devices) n += d.chunks_swept; return n; }
uint64_t GcReport::bytes_swept() const { uint64_t n = 0; for (auto& d : devices) n += d.bytes_swept; return n; }

namespace {
constexpr size_t MAX_REFUSALS_LISTED = 20;
std::string label(const std::string& file_id, int64_t version) { return file_id.substr(0, 8) + " v" + std::to_string(version); }
}  // namespace

GarbageCollector::GarbageCollector(Ledger& ledger, Replicator& replicator, const crypto::Keys& keys, GcConfig config)
    : ledger_(ledger), replicator_(replicator), keys_(keys), cfg_(std::move(config)), volume_(ledger.volume_id()) {
    if (cfg_.keep_versions < 1) cfg_.keep_versions = 1;
}

// The device must be the one the ledger thinks it is, bound to this volume: otherwise nothing is deleted there.
bool GarbageCollector::check_device(DeviceClient& dev, const std::string& device_id, std::string* why) {
    DevInfo info;
    DevRes r = dev.info(info);
    if (!r.ok()) { *why = "cannot reach it: " + r.msg; return false; }
    if (info.device_id != device_id) { *why = "this is not the device the ledger expects"; return false; }
    if (info.volume_id != volume_) { *why = "it is not bound to this volume"; return false; }
    return true;
}

// A store from before chunk lists existed: for every manifest it holds, read the list inside it (the Mac can decrypt it) and send it back with
// the unchanged blob. The device records the list only for the identical blob and only if it holds every listed chunk.
uint32_t GarbageCollector::send_chunk_lists(DeviceClient& dev, std::string* why) {
    uint32_t sent = 0;
    uint64_t since = 0;
    for (;;) {
        ListReply lr;
        DevRes r = dev.list_manifests(since, 1000, lr);
        if (!r.ok()) { *why = "cannot list its manifests: " + r.msg; return sent; }
        for (const auto& e : lr.entries) {
            since = std::max(since, e.seq);
            std::vector<uint8_t> blob;
            if (!dev.get_manifest(e.file_id, e.version, blob).ok()) continue;
            crypto::Manifest m;
            if (crypto::open_manifest(keys_, volume_, e.file_id, e.version, blob.data(), blob.size(), m) != crypto::OpenError::Ok) continue;
            std::vector<std::string> ids;
            for (const auto& c : m.chunks) ids.push_back(c.chunk_id);
            PutManifestReply pr;
            if (dev.put_manifest(e.file_id, e.version, blob, ids, pr).ok() && pr.existed) sent++;
        }
        if (lr.entries.size() < 1000) break;
    }
    return sent;
}

void GarbageCollector::sweep_device(DeviceClient& dev, GcDeviceReport& dr, bool dry_run) {
    GcStatus st;
    DevRes r = dev.gc_status(st);
    if (!r.ok()) { dr.note = r.err == ENOSYS ? "this device is too old to collect garbage" : "cannot ask its status: " + r.msg; return; }
    dr.status = st;
    dr.deletions_allowed = st.deletions_allowed;
    if (!st.deletions_allowed) { dr.note = "it does not accept deletions (pair it, or start it with --allow-delete)"; return; }
    if (st.manifests_without_refs > 0) {
        std::string n = std::to_string(st.manifests_without_refs) + " manifest(s) need their chunk lists re-sent before it can be swept";
        if (dry_run) { dr.note = n + " (a real run does that)"; return; }
        if (!cfg_.prepare) { dr.note = n; return; }
        std::string why;
        dr.chunk_lists_sent = send_chunk_lists(dev, &why);
        if (!why.empty()) { dr.note = why; return; }
        if (!dev.gc_status(st).ok()) { dr.note = "cannot ask its status again"; return; }
        dr.status = st;
        if (st.manifests_without_refs > 0) {
            dr.note = std::to_string(st.manifests_without_refs) + " manifest(s) could not be given a chunk list (not readable with this volume's keys?); no sweep";
            return;
        }
    }
    if (st.unreferenced_chunks == 0) return;   // nothing to take, and no reason to walk the disk
    for (int round = 0; round < std::max(1, cfg_.sweep_rounds); round++) {
        SweepOut so;
        DevRes sr = dev.sweep(cfg_.sweep_min_age, static_cast<uint32_t>(cfg_.sweep_chunks), dry_run, so);
        if (!sr.ok()) { dr.note = "sweep failed: " + sr.msg; return; }
        dr.chunks_swept += so.chunks_deleted;
        dr.bytes_swept += so.bytes_deleted;
        dr.strays_removed += so.strays_removed;
        if (dry_run || so.chunks_deleted == 0 || so.chunks_left == 0) return;
    }
}

GcReport GarbageCollector::plan(const DeviceMap& devices) {
    GcReport rep;
    rep.dry_run = true;
    auto cands = ledger_.prune_candidates(cfg_.keep_versions, cfg_.rules, cfg_.max_decisions);
    rep.candidates = cands.size();
    rep.owed_total = ledger_.pending_prunes(1u << 30).size();
    std::map<std::string, uint64_t> owed;
    for (const auto& w : ledger_.pending_prunes(1u << 30)) owed[w.device_id]++;
    for (const auto& kv : devices) {
        GcDeviceReport dr;
        dr.device_id = kv.first;
        dr.owed = owed[kv.first];
        std::string why;
        if (!kv.second || !check_device(*kv.second, kv.first, &why)) { dr.note = kv.second ? why : "not connected"; rep.devices.push_back(dr); continue; }
        dr.reachable = true;
        sweep_device(*kv.second, dr, true);
        rep.devices.push_back(dr);
    }
    return rep;
}

GcReport GarbageCollector::run(const DeviceMap& devices) {
    GcReport rep;

    // 1. decide
    auto cands = ledger_.prune_candidates(cfg_.keep_versions, cfg_.rules, cfg_.max_decisions);
    rep.candidates = cands.size();
    for (const auto& c : cands) {
        std::string reason = c.file_deleted ? "the file was deleted and its retention period is over"
                                            : "older than the newest " + std::to_string(cfg_.keep_versions) + " committed versions";
        Res r = ledger_.prune_version(c.file_id, c.version, reason, cfg_.rules);
        if (!r) {
            // The usual obstacle: the newer version was last audited too long ago. Audit it now (the devices must prove they still hold it).
            int64_t w = c.file_deleted ? 0 : ledger_.safe_successor(c.file_id, c.version, cfg_.rules);
            if (w) {
                for (const auto& rp : ledger_.get_replicas(c.file_id, w)) {
                    if (rp.state != ReplicaState::COMMITTED) continue;
                    auto it = devices.find(rp.device_id);
                    if (it == devices.end() || !it->second) continue;
                    replicator_.audit_replica(*it->second, rp.device_id, c.file_id, w);
                    rep.audited++;
                }
                r = ledger_.prune_version(c.file_id, c.version, reason, cfg_.rules);
            }
        }
        if (r) rep.decided++;
        else if (rep.refused.size() < MAX_REFUSALS_LISTED) rep.refused.push_back(label(c.file_id, c.version) + ": " + r.why);
    }
    if (on_step) on_step("decided");
    crash_point("gc.after_decide");

    // 2. delete
    std::map<std::string, std::vector<PruneWork>> by_device;
    for (const auto& w : ledger_.pending_prunes(1u << 30)) by_device[w.device_id].push_back(w);
    std::map<std::string, GcDeviceReport> reports;
    for (const auto& kv : devices) {
        GcDeviceReport& dr = reports[kv.first];
        dr.device_id = kv.first;
        auto work = by_device.find(kv.first);
        dr.owed = work == by_device.end() ? 0 : work->second.size();
        std::string why;
        if (!kv.second) { dr.note = "not connected"; continue; }
        if (!check_device(*kv.second, kv.first, &why)) { dr.note = why; continue; }
        dr.reachable = true;
        if (work == by_device.end()) continue;
        const auto& items = work->second;
        for (size_t at = 0; at < items.size(); at += MAX_DELETE_ITEMS) {
            size_t end = std::min(items.size(), at + MAX_DELETE_ITEMS);
            std::vector<std::pair<std::string, int64_t>> batch;
            for (size_t i = at; i < end; i++) batch.emplace_back(items[i].file_id, items[i].version);
            std::vector<uint8_t> deleted;
            DevRes r = kv.second->delete_manifests(batch, deleted);
            if (!r.ok()) {
                dr.note = r.err == EPERM ? "it does not accept deletions (pair it, or start it with --allow-delete)"
                          : r.err == ENOSYS ? "this device is too old to delete" : "deleting failed: " + r.msg;
                break;
            }
            for (size_t i = at; i < end; i++) {
                if (ledger_.record_pruned(items[i].file_id, items[i].version, kv.first)) dr.manifests_deleted++;
            }
            crash_point("gc.after_delete_batch");
        }
        DevInfo info;   // deleting moved the device's commit sequence; keep our high-water mark in step so a later rollback still shows
        if (kv.second->info(info).ok()) ledger_.observe_device(kv.first, info.epoch, info.seq);
        if (on_step) on_step("device_done");
    }
    if (on_step) on_step("deleted");

    // 3. sweep
    for (auto& kv : reports) {
        GcDeviceReport& dr = kv.second;
        if (!dr.reachable || !cfg_.sweep || !dr.note.empty()) continue;   // (a device that refused the deletions is not swept either)
        sweep_device(*devices.at(kv.first), dr, false);
    }
    for (auto& kv : reports) rep.devices.push_back(kv.second);
    rep.owed_total = ledger_.pending_prunes(1u << 30).size();
    return rep;
}

std::string format_gc_report(const GcReport& r) {
    std::string s = r.dry_run ? "garbage collection (plan only, nothing changed):\n" : "garbage collection:\n";
    s += "  versions the rules would let go of: " + std::to_string(r.candidates) + "\n";
    if (!r.dry_run) s += "  decided now: " + std::to_string(r.decided) + " (audited " + std::to_string(r.audited) + " newer versions first)\n";
    for (const auto& x : r.refused) s += "  refused: " + x + "\n";
    s += "  deletions still owed by devices: " + std::to_string(r.owed_total) + "\n";
    for (const auto& d : r.devices) {
        s += "  device " + d.device_id.substr(0, 8) + ": ";
        if (!d.reachable) s += "not reachable";
        else s += "owed " + std::to_string(d.owed) + ", manifests deleted " + std::to_string(d.manifests_deleted) + ", chunks " + (r.dry_run ? "that a sweep would take " : "swept ") +
                  std::to_string(d.chunks_swept) + " (" + std::to_string(d.bytes_swept) + " bytes)" + (d.strays_removed ? ", " + std::to_string(d.strays_removed) + " stray files" : "");
        if (!d.note.empty()) s += " -- " + d.note;
        s += "\n";
    }
    return s;
}

}  // namespace tierfs
