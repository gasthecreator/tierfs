#include "replicator.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

#include "crashpoint.hpp"

namespace tierfs {
namespace {

using crypto::Bytes;

// What identifies "the same file, unmodified": a write changes the size or the modification time
// (to the nanosecond), a replace changes the inode.
struct Snap {
    int64_t size = 0, mtime_s = 0, mtime_ns = 0;
    uint64_t ino = 0;
    int32_t dev = 0;
};
bool same(const Snap& a, const Snap& b) {
    return a.size == b.size && a.mtime_s == b.mtime_s && a.mtime_ns == b.mtime_ns && a.ino == b.ino && a.dev == b.dev;
}
bool take_snap(int fd, Snap& s, std::string* err) {
    struct stat st;
    if (fstat(fd, &st) != 0) { *err = std::string("cannot stat: ") + strerror(errno); return false; }
    if (!S_ISREG(st.st_mode)) { *err = "not a regular file"; return false; }
    s.size = st.st_size;
    s.mtime_s = st.st_mtimespec.tv_sec;
    s.mtime_ns = st.st_mtimespec.tv_nsec;
    s.ino = st.st_ino;
    s.dev = st.st_dev;
    return true;
}

bool read_at(int fd, uint64_t off, size_t len, Bytes& buf) {
    buf.resize(len);
    size_t got = 0;
    while (got < len) {
        ssize_t r = pread(fd, buf.data() + got, len - got, static_cast<off_t>(off + got));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;   // shorter than the plan says: the file shrank
        got += static_cast<size_t>(r);
    }
    return true;
}

size_t chunk_count(uint64_t size) { return static_cast<size_t>((size + REPL_CHUNK - 1) / REPL_CHUNK); }
size_t chunk_len(uint64_t size, size_t idx) {
    return static_cast<size_t>(std::min<uint64_t>(REPL_CHUNK, size - static_cast<uint64_t>(idx) * REPL_CHUNK));
}

std::string manifest_object_id(const std::string& file_id, int64_t version) { return "m:" + file_id + ":" + std::to_string(version); }

uint32_t rand_below(uint32_t n) {
    uint32_t limit = UINT32_MAX - (UINT32_MAX % n);
    for (;;) {
        Bytes r = crypto::random_bytes(4);
        if (r.size() != 4) return 0;
        uint32_t v = (uint32_t(r[0]) << 24) | (uint32_t(r[1]) << 16) | (uint32_t(r[2]) << 8) | r[3];
        if (v < limit) return v % n;
    }
}

std::vector<Challenge> make_challenges(const crypto::Keys& k, const std::string& object_id, const Bytes& blob,
                                       uint32_t first_n, size_t count) {
    std::vector<Challenge> out;
    for (size_t i = 0; i < count; i++) {
        uint32_t n = first_n + static_cast<uint32_t>(i);
        out.push_back({n, crypto::audit_response_hex(crypto::audit_nonce(k, object_id, n), blob.data(), blob.size())});
    }
    return out;
}

// One audit request item plus the answer we expect.
struct Expect {
    AuditItem item;
    std::string response;
    std::string label;
};

// Sends the items (in groups of 64) and returns a description of everything that did not check out.
std::vector<std::string> run_audits(DeviceClient& dev, const std::vector<Expect>& items, DevRes* transport_error) {
    std::vector<std::string> bad;
    for (size_t off = 0; off < items.size(); off += MAX_AUDIT_ITEMS) {
        size_t n = std::min(MAX_AUDIT_ITEMS, items.size() - off);
        std::vector<AuditItem> req;
        for (size_t i = 0; i < n; i++) req.push_back(items[off + i].item);
        std::vector<AuditOut> outs;
        DevRes r = dev.audit(req, outs);
        if (!r.ok() || outs.size() != n) {
            *transport_error = r.ok() ? DevRes{EPROTO, "wrong number of audit answers"} : r;
            return bad;
        }
        for (size_t i = 0; i < n; i++) {
            const Expect& e = items[off + i];
            if (outs[i].status == 1) bad.push_back(e.label + ": the device does not have it");
            else if (outs[i].status != 0) bad.push_back(e.label + ": the device could not read it");
            else if (outs[i].response_hex != e.response) bad.push_back(e.label + ": the device's answer does not match (wrong or damaged bytes)");
        }
    }
    return bad;
}

std::string short_id(const std::string& id) { return id.substr(0, 12); }

}  // namespace

Replicator::Replicator(Ledger& ledger, const crypto::Keys& keys, std::string volume_id, ReplicateOptions opt)
    : ledger_(ledger), keys_(keys), volume_(std::move(volume_id)), opt_(opt) {}

// ---------------------------------------------------------------- attach

Res Replicator::attach(DeviceClient& dev, const std::string& name, const std::string& cls, std::string* device_id,
                       DeviceObservation* observation) {
    DevInfo info;
    DevRes r = dev.info(info);
    if (!r.ok()) return Res{false, "cannot reach the device: " + r.msg, ""};
    DevRes b = dev.bind(volume_);
    if (!b.ok()) return Res{false, b.err == EPERM ? "this device belongs to a different volume" : "cannot bind the device: " + b.msg, ""};
    if (!ledger_.get_device(info.device_id)) {
        if (!ledger_.register_device(info.device_id, name, cls)) return Res{false, "cannot register the device in the ledger (bad class?)", ""};
    }
    DeviceObservation obs = ledger_.observe_device(info.device_id, info.epoch, info.seq);
    if (observation) *observation = obs;
    if (obs == DeviceObservation::Unknown) return Res{false, "the ledger could not record the device", ""};
    if (device_id) *device_id = info.device_id;
    return Res{true, "", info.device_id};
}

// ---------------------------------------------------------------- replicate

ReplicateOutcome Replicator::replicate(DeviceClient& dev, const std::string& device_id, const std::string& file_id,
                                       const std::string& local_path) {
    ReplicateOutcome out;
    auto fail = [&](const std::string& why) { out.ok = false; out.why = why; return out; };
    auto step = [&](const char* name) { if (on_step) on_step(name); };

    auto file = ledger_.get_file(file_id);
    if (!file) return fail("unknown file");
    auto dr = ledger_.get_device(device_id);
    if (!dr) return fail("unknown device (attach it first)");
    if (dr->state != "active") return fail("device is " + dr->state + "; reconcile it first");
    if (!file->local_present) return fail("local bytes are not present");

    DevInfo info;
    DevRes ir = dev.info(info);
    if (!ir.ok()) return fail("cannot reach the device: " + ir.msg);
    if (info.device_id != device_id) return fail("this is not the device the ledger expects");
    if (info.volume_id != volume_) return fail("the device is not bound to this volume");
    DeviceObservation obs = ledger_.observe_device(device_id, info.epoch, info.seq);
    if (obs == DeviceObservation::Rollback || obs == DeviceObservation::EpochChanged)
        return fail("the device was restored or reset since we last saw it; reconcile it first");

    int fd = ::open(local_path.c_str(), O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return fail("cannot open " + local_path + ": " + strerror(errno));
    struct FdCloser { int fd; ~FdCloser() { close(fd); } } closer{fd};

    // The file was modified (or replaced) while we were reading it. Tell the ledger so nothing that was
    // prepared against the old bytes can ever be committed or dropped.
    auto changed = [&](const std::string& why) {
        out.file_changed = true;
        Snap now;
        std::string e;
        if (take_snap(fd, now, &e)) ledger_.note_local_modified(file_id, static_cast<uint64_t>(now.size), now.mtime_s);
        return fail(why);
    };

    int64_t version = file->current_version;
    FileState state = file->state;

    // ---- an already committed replica? ----
    if (state == FileState::REPLICATING || state == FileState::REPLICATED) {
        for (const auto& r : ledger_.get_replicas(file_id, version)) {
            if (r.device_id == device_id && r.state == ReplicaState::COMMITTED) {
                if (state == FileState::REPLICATING) {
                    Res f = ledger_.finish_replication(file_id, version);
                    if (!f) return fail("cannot finish: " + f.why);
                }
                out.ok = out.already_done = true;
                out.version = version;
                return out;
            }
        }
    } else if (state != FileState::LOCAL) {
        return fail(std::string("file is ") + to_string(state) + "; only LOCAL, REPLICATING or REPLICATED files can be replicated");
    }

    // ---- pass 1: plan (only for a version that does not exist yet) ----
    if (state == FileState::LOCAL) {
        Snap s0;
        std::string err;
        if (!take_snap(fd, s0, &err)) return fail(err);
        size_t n = chunk_count(static_cast<uint64_t>(s0.size));
        if (n * 80 > MAX_MANIFEST_BLOB - (1u << 20)) return fail("file is too large for one manifest (protocol v3 limit)");
        std::vector<ChunkRec> recs;
        Bytes buf;
        for (size_t idx = 0; idx < n; idx++) {
            size_t len = chunk_len(static_cast<uint64_t>(s0.size), idx);
            if (!read_at(fd, static_cast<uint64_t>(idx) * REPL_CHUNK, len, buf)) return changed("the file shrank while it was being read");
            std::string cid = crypto::chunk_id(keys_, buf.data(), buf.size());
            Bytes blob = crypto::seal_chunk(keys_, volume_, cid, buf.data(), buf.size());
            if (cid.empty() || blob.empty()) return fail("cannot seal a chunk");
            recs.push_back({static_cast<uint32_t>(idx), cid, static_cast<uint32_t>(len), crypto::sha256_hex(blob.data(), blob.size())});
        }
        step("pass1_done");
        Snap s1;
        if (!take_snap(fd, s1, &err)) return fail(err);
        if (!same(s0, s1)) return changed("the file was modified while it was being read");
        Res br = ledger_.begin_replication(file_id, recs, static_cast<uint64_t>(s0.size), s0.mtime_s);
        if (!br) return fail("ledger refused the plan: " + br.why);
        version = atoll(br.id.c_str());
        crash_point("repl.after_begin");
    }
    out.version = version;

    // ---- pass 2: upload and verify ----
    step("pass2_start");
    auto fr = ledger_.get_file(file_id);
    std::vector<ChunkRec> recs = ledger_.get_chunks(file_id, version);
    out.chunks_total = recs.size();
    Snap s2;
    {
        std::string err;
        if (!take_snap(fd, s2, &err)) return fail(err);
    }
    if (static_cast<uint64_t>(s2.size) != fr->size) return changed("the file's size differs from the plan");

    // our replica row
    {
        std::optional<ReplicaRec> mine;
        for (const auto& r : ledger_.get_replicas(file_id, version))
            if (r.device_id == device_id) mine = r;
        if (!mine || mine->state == ReplicaState::MISSING || mine->state == ReplicaState::AUDIT_FAILED) {
            Res sr = ledger_.set_replica(file_id, version, device_id, ReplicaState::PENDING);
            if (!sr) return fail("ledger: " + sr.why);
        }
    }

    std::vector<std::string> ids;
    for (const auto& r : recs) ids.push_back(r.chunk_id);
    std::vector<bool> have;
    {
        DevRes hr = dev.has_chunks(ids, have);
        if (!hr.ok() || have.size() != ids.size()) return fail("cannot ask the device what it has: " + hr.msg);
    }

    step("pass2_after_has");   // (test hook) the window in which another writer can slip a chunk in

    // which newly uploaded chunks to audit before committing (existing ones are always audited)
    std::set<size_t> sample;
    {
        std::vector<uint32_t> order(recs.size());
        for (size_t i = 0; i < order.size(); i++) order[i] = static_cast<uint32_t>(i);
        for (size_t i = order.size(); i > 1; i--) std::swap(order[i - 1], order[rand_below(static_cast<uint32_t>(i))]);
        for (size_t i = 0; i < std::min(opt_.verify_chunks, order.size()); i++) sample.insert(order[i]);
    }

    crypto::FileHmac fh(keys_);
    std::vector<Expect> audits;
    Bytes buf;
    for (size_t idx = 0; idx < recs.size(); idx++) {
        const ChunkRec& rec = recs[idx];
        if (!read_at(fd, static_cast<uint64_t>(idx) * REPL_CHUNK, rec.len, buf)) return changed("the file shrank while it was being read");
        if (crypto::chunk_id(keys_, buf.data(), buf.size()) != rec.chunk_id) return changed("chunk " + std::to_string(idx) + " no longer matches the plan: the file was modified");
        Bytes blob = crypto::seal_chunk(keys_, volume_, rec.chunk_id, buf.data(), buf.size());
        if (blob.empty() || crypto::sha256_hex(blob.data(), blob.size()) != rec.blob_sha256) return changed("chunk " + std::to_string(idx) + " no longer seals to the planned bytes");
        fh.update(buf.data(), buf.size());

        {   // We hold this blob right now, so topping up its one-time audit pool is nearly free: do it whenever it is low.
            size_t left = ledger_.challenges_left(file_id, version, static_cast<int64_t>(idx));
            if (left < opt_.challenges_per_chunk)
                ledger_.add_challenges(file_id, version, static_cast<int64_t>(idx),
                                       make_challenges(keys_, rec.chunk_id, blob, ledger_.next_challenge_n(file_id, version, static_cast<int64_t>(idx)),
                                                       opt_.challenges_per_chunk - left));
        }

        bool present = have[idx];
        if (!present) {
            PutChunkReply pr;
            DevRes r = dev.put_chunk(rec.chunk_id, blob, pr);
            if (!r.ok()) return fail("upload of chunk " + std::to_string(idx) + " failed: " + r.msg);
            if (pr.existed) {
                // somebody (an earlier attempt, another file) got there first: it must be our bytes
                if (pr.sha256_hex != rec.blob_sha256) {
                    ledger_.set_replica(file_id, version, device_id, ReplicaState::MISSING);
                    return fail("the device holds DIFFERENT bytes under chunk " + short_id(rec.chunk_id) + " (conflict; it cannot be overwritten)");
                }
                present = true;
            } else {
                out.chunks_uploaded++;
                out.bytes_uploaded += blob.size();
            }
        }
        if (present) out.chunks_already_present++;
        if (present || sample.count(idx)) {
            Expect e;
            e.item.kind = 0;
            e.item.id = rec.chunk_id;
            e.item.nonce = crypto::random_bytes(32);   // fresh and secret: the device cannot have prepared an answer
            e.response = crypto::audit_response_hex(e.item.nonce, blob.data(), blob.size());
            e.label = "chunk " + std::to_string(idx) + " (" + short_id(rec.chunk_id) + ")";
            audits.push_back(std::move(e));
        }
        if (idx + 1 == (recs.size() + 1) / 2 && recs.size() >= 2) {
            step("pass2_mid");   // (test hook) an already-read chunk can still change after this point
            crash_point("repl.mid_upload");
        }
    }

    Snap s3;
    {
        std::string err;
        if (!take_snap(fd, s3, &err)) return fail(err);
        if (!same(s2, s3)) return changed("the file was modified while it was being uploaded");
    }

    // ---- verify before committing anything ----
    DevRes transport;
    std::vector<std::string> bad = run_audits(dev, audits, &transport);
    out.chunks_audited = audits.size();
    if (!transport.ok()) return fail("audit could not complete: " + transport.msg);
    if (!bad.empty()) {
        ledger_.set_replica(file_id, version, device_id, ReplicaState::MISSING);
        return fail("the device failed its audit: " + bad.front() + (bad.size() > 1 ? " (+" + std::to_string(bad.size() - 1) + " more)" : ""));
    }
    {
        std::optional<ReplicaRec> mine;
        for (const auto& r : ledger_.get_replicas(file_id, version))
            if (r.device_id == device_id) mine = r;
        if (mine && mine->state == ReplicaState::PENDING) {
            Res u = ledger_.set_replica(file_id, version, device_id, ReplicaState::UPLOADED);
            if (!u) return fail("ledger: " + u.why);
        }
    }
    crash_point("repl.before_manifest");

    // ---- manifest ----
    crypto::Manifest m;
    m.file_id = file_id;
    m.version = version;
    m.prev_version = version > 1 ? version - 1 : 0;
    m.path = fr->path;
    m.mode = fr->mode;
    m.mtime = fr->mtime;
    m.size = fr->size;
    m.file_hmac = fh.finish_hex();
    {
        ssize_t nlen = flistxattr(fd, nullptr, 0, 0);
        if (nlen > 0) {
            std::string names(static_cast<size_t>(nlen), '\0');
            nlen = flistxattr(fd, &names[0], names.size(), 0);
            std::vector<std::string> list;
            for (size_t p = 0; nlen > 0 && p < static_cast<size_t>(nlen);) {
                list.emplace_back(names.c_str() + p);
                p += list.back().size() + 1;
            }
            std::sort(list.begin(), list.end());   // deterministic order: the same file gives the same manifest bytes
            for (const auto& name : list) {
                ssize_t vlen = fgetxattr(fd, name.c_str(), nullptr, 0, 0, 0);
                if (vlen < 0) continue;
                Bytes value(static_cast<size_t>(vlen));
                if (vlen > 0 && fgetxattr(fd, name.c_str(), value.data(), value.size(), 0, 0) != vlen) continue;
                m.xattrs.emplace_back(name, std::move(value));
            }
        }
    }
    for (const auto& r : recs) m.chunks.push_back({r.chunk_id, r.len});
    Bytes mblob = crypto::seal_manifest(keys_, volume_, m);
    if (mblob.empty()) return fail("cannot seal the manifest (an extended attribute too large, or too many chunks)");
    std::string msha = crypto::sha256_hex(mblob.data(), mblob.size());
    Res hr = ledger_.set_manifest_hash(file_id, version, msha);
    if (!hr) return changed("the file's metadata changed since an earlier attempt at this version; abandoning it");
    {
        size_t left = ledger_.challenges_left(file_id, version, MANIFEST_CHALLENGE_IDX);
        if (left < opt_.challenges_per_chunk)
            ledger_.add_challenges(file_id, version, MANIFEST_CHALLENGE_IDX,
                                   make_challenges(keys_, manifest_object_id(file_id, version), mblob,
                                                   ledger_.next_challenge_n(file_id, version, MANIFEST_CHALLENGE_IDX), opt_.challenges_per_chunk - left));
    }

    PutManifestReply mr;
    DevRes pm = dev.put_manifest(file_id, version, mblob, ids, mr);
    if (!pm.ok()) return fail("the device refused the manifest: " + pm.msg);
    if (mr.sha256_hex != msha) {
        ledger_.set_replica(file_id, version, device_id, ReplicaState::MISSING);
        return fail("the device holds a DIFFERENT manifest for this version (conflict)");
    }
    crash_point("repl.after_manifest_put");   // the device has committed; the ledger does not know yet

    {   // audit the manifest too
        Expect e;
        e.item.kind = 1;
        e.item.id = file_id;
        e.item.version = version;
        e.item.nonce = crypto::random_bytes(32);
        e.response = crypto::audit_response_hex(e.item.nonce, mblob.data(), mblob.size());
        e.label = "manifest";
        DevRes t2;
        std::vector<std::string> mb = run_audits(dev, {e}, &t2);
        if (!t2.ok()) return fail("manifest audit could not complete: " + t2.msg);
        if (!mb.empty()) {
            ledger_.set_replica(file_id, version, device_id, ReplicaState::MISSING);
            return fail("the device failed its manifest audit: " + mb.front());
        }
    }

    Res cr = ledger_.set_replica(file_id, version, device_id, ReplicaState::COMMITTED, static_cast<int64_t>(mr.seq));
    if (!cr) return fail("ledger: " + cr.why);
    ledger_.observe_device(device_id, info.epoch, mr.seq);
    crash_point("repl.before_finish");

    auto cur = ledger_.get_file(file_id);
    if (cur && cur->state == FileState::REPLICATING) {
        Res f = ledger_.finish_replication(file_id, version);
        if (!f) { out.file_changed = true; return fail("cannot finish: " + f.why); }
    }
    out.ok = true;
    return out;
}

// ---------------------------------------------------------------- audit one replica

AuditReport Replicator::audit_replica(DeviceClient& dev, const std::string& device_id, const std::string& file_id, int64_t version) {
    AuditReport rep;
    auto reps = ledger_.get_replicas(file_id, version);
    bool is_committed = false;
    for (const auto& r : reps) if (r.device_id == device_id && r.state == ReplicaState::COMMITTED) is_committed = true;
    if (!is_committed) { rep.why = "there is no committed replica of this version on that device"; return rep; }
    if (!ledger_.has_version(file_id, version)) { rep.why = "unknown version"; return rep; }

    std::vector<ChunkRec> chunks = ledger_.get_chunks(file_id, version);
    std::vector<Expect> items;
    std::vector<size_t> refetch;   // chunks whose challenge pool is used up
    for (const auto& c : chunks) {
        auto ch = ledger_.take_challenge(file_id, version, c.idx);
        if (!ch) { refetch.push_back(c.idx); continue; }
        Expect e;
        e.item.kind = 0;
        e.item.id = c.chunk_id;
        e.item.nonce = crypto::audit_nonce(keys_, c.chunk_id, ch->n);
        e.response = ch->response;
        e.label = "chunk " + std::to_string(c.idx) + " (" + short_id(c.chunk_id) + ")";
        items.push_back(std::move(e));
    }
    bool manifest_refetch = false;
    {
        auto ch = ledger_.take_challenge(file_id, version, MANIFEST_CHALLENGE_IDX);
        if (!ch) manifest_refetch = true;
        else {
            Expect e;
            e.item.kind = 1;
            e.item.id = file_id;
            e.item.version = version;
            e.item.nonce = crypto::audit_nonce(keys_, manifest_object_id(file_id, version), ch->n);
            e.response = ch->response;
            e.label = "manifest";
            items.push_back(std::move(e));
        }
    }
    rep.items = items.size();
    DevRes transport;
    rep.failures = run_audits(dev, items, &transport);
    if (!transport.ok()) { rep.why = "audit could not complete: " + transport.msg; return rep; }   // nothing recorded: the device may just be offline
    rep.answered_ok = items.size() - rep.failures.size();

    // A used-up pool: download the real thing, verify it end to end, and mint a fresh pool from it.
    for (size_t idx : refetch) {
        const ChunkRec& c = chunks[idx];
        Bytes blob, plain;
        DevRes g = dev.get_chunk(c.chunk_id, blob);
        if (!g.ok()) { rep.failures.push_back("chunk " + std::to_string(idx) + ": download failed: " + g.msg); continue; }
        if (crypto::open_chunk(keys_, volume_, c.chunk_id, blob.data(), blob.size(), plain) != crypto::OpenError::Ok ||
            crypto::sha256_hex(blob.data(), blob.size()) != c.blob_sha256) {
            rep.failures.push_back("chunk " + std::to_string(idx) + ": the stored bytes do not verify");
            continue;
        }
        ledger_.add_challenges(file_id, version, c.idx, make_challenges(keys_, c.chunk_id, blob, ledger_.next_challenge_n(file_id, version, c.idx), opt_.challenges_per_chunk));
        rep.refetched++;
        rep.items++;
        rep.answered_ok++;
    }
    if (manifest_refetch) {
        Bytes blob;
        crypto::Manifest m;
        DevRes g = dev.get_manifest(file_id, version, blob);
        auto want = ledger_.get_manifest_hash(file_id, version);
        if (!g.ok()) rep.failures.push_back("manifest: download failed: " + g.msg);
        else if (crypto::open_manifest(keys_, volume_, file_id, version, blob.data(), blob.size(), m) != crypto::OpenError::Ok ||
                 (want && crypto::sha256_hex(blob.data(), blob.size()) != *want))
            rep.failures.push_back("manifest: the stored bytes do not verify");
        else {
            ledger_.add_challenges(file_id, version, MANIFEST_CHALLENGE_IDX,
                                   make_challenges(keys_, manifest_object_id(file_id, version), blob, ledger_.next_challenge_n(file_id, version, MANIFEST_CHALLENGE_IDX), opt_.challenges_per_chunk));
            rep.refetched++;
            rep.items++;
            rep.answered_ok++;
        }
    }

    rep.ok = rep.failures.empty();
    std::string detail = rep.ok ? std::to_string(rep.items) + " objects verified" : rep.failures.front();
    ledger_.record_audit(file_id, version, device_id, rep.ok, detail);
    if (!rep.ok) rep.why = "the replica failed its audit";
    return rep;
}

// ---------------------------------------------------------------- fetch

Res Replicator::fetch_version(DeviceClient& dev, const std::string& file_id, int64_t version,
                              const std::function<bool(const uint8_t*, size_t)>& sink, crypto::Manifest* manifest_out) {
    Bytes mb;
    DevRes g = dev.get_manifest(file_id, version, mb);
    if (!g.ok()) return Res{false, "cannot fetch the manifest: " + g.msg, ""};
    crypto::Manifest m;
    crypto::OpenError oe = crypto::open_manifest(keys_, volume_, file_id, version, mb.data(), mb.size(), m);
    if (oe != crypto::OpenError::Ok) return Res{false, std::string("the manifest does not verify: ") + crypto::to_string(oe), ""};
    crypto::FileHmac fh(keys_);
    uint64_t total = 0;
    for (const auto& c : m.chunks) {
        Bytes blob, plain;
        DevRes cg = dev.get_chunk(c.chunk_id, blob);
        if (!cg.ok()) return Res{false, "cannot fetch chunk " + short_id(c.chunk_id) + ": " + cg.msg, ""};
        crypto::OpenError ce = crypto::open_chunk(keys_, volume_, c.chunk_id, blob.data(), blob.size(), plain);
        if (ce != crypto::OpenError::Ok) return Res{false, "chunk " + short_id(c.chunk_id) + " does not verify: " + crypto::to_string(ce), ""};
        if (plain.size() != c.len) return Res{false, "chunk " + short_id(c.chunk_id) + " has the wrong length", ""};
        fh.update(plain.data(), plain.size());
        total += plain.size();
        if (!sink(plain.data(), plain.size())) return Res{false, "the receiver stopped the transfer", ""};
    }
    if (total != m.size) return Res{false, "the chunks do not add up to the file size", ""};
    if (fh.finish_hex() != m.file_hmac) return Res{false, "the whole-file check failed: the reassembled file is not the original", ""};
    if (manifest_out) *manifest_out = std::move(m);
    return Res{true, "", ""};
}

// ---------------------------------------------------------------- reconcile

ReconcileReport Replicator::reconcile(DeviceClient& dev, const std::string& device_id, bool deep) {
    ReconcileReport rep;
    auto fail = [&](const std::string& why) { rep.ok = false; rep.why = why; return rep; };

    DevInfo info;
    DevRes ir = dev.info(info);
    if (!ir.ok()) return fail("cannot reach the device: " + ir.msg);
    if (info.device_id != device_id) return fail("this is not the device the ledger expects");
    if (info.volume_id != volume_) return fail("the device is not bound to this volume");
    DeviceObservation obs = ledger_.observe_device(device_id, info.epoch, info.seq);
    if (obs == DeviceObservation::Unknown) return fail("unknown device");
    rep.first_contact = obs == DeviceObservation::First;
    rep.rolled_back = obs == DeviceObservation::Rollback;
    rep.epoch_changed = obs == DeviceObservation::EpochChanged;

    // the device's complete commit log
    std::map<std::pair<std::string, int64_t>, ManifestEntry> on_dev;
    uint64_t since = 0;
    for (;;) {
        ListReply lr;
        DevRes r = dev.list_manifests(since, 1000, lr);
        if (!r.ok()) return fail("cannot list the device's manifests: " + r.msg);
        for (auto& e : lr.entries) { since = std::max(since, e.seq); on_dev[{e.file_id, e.version}] = e; }
        if (lr.entries.size() < 1000) break;
    }

    auto replica_state = [&](const std::string& f, int64_t v) -> std::optional<ReplicaState> {
        for (const auto& r : ledger_.get_replicas(f, v)) if (r.device_id == device_id) return r.state;
        return std::nullopt;
    };

    // 1. what the device has, against what the ledger recorded
    for (const auto& kv : on_dev) {
        const ManifestEntry& e = kv.second;
        std::string label = e.file_id + ":" + std::to_string(e.version);
        if (!ledger_.has_version(e.file_id, e.version)) { rep.unknown_manifests.push_back(label); continue; }
        if (ledger_.is_version_pruned(e.file_id, e.version)) {   // it was deleted on purpose; a device that was away still has it: it is not a copy to adopt
            if (ledger_.queue_prune(e.file_id, e.version, device_id)) rep.pruned_leftovers.push_back(label);
            continue;
        }
        auto expected = ledger_.get_manifest_hash(e.file_id, e.version);
        if (!expected) { rep.unknown_manifests.push_back(label + " (no recorded hash to compare with)"); continue; }
        auto st = replica_state(e.file_id, e.version);
        if (*expected != e.sha256_hex) {
            rep.conflicts.push_back(label);
            if (st == ReplicaState::COMMITTED) ledger_.record_audit(e.file_id, e.version, device_id, false, "the device's manifest differs from the recorded one");
            continue;
        }
        if (!st || *st != ReplicaState::COMMITTED) {
            Res a = ledger_.adopt_replica(e.file_id, e.version, device_id, static_cast<int64_t>(e.seq));
            if (a) rep.adopted.push_back(label);
        }
    }

    // 2. what the ledger believes the device has, against what it lists
    for (const auto& r : ledger_.replicas_on_device(device_id)) {
        if (r.state != ReplicaState::COMMITTED) continue;
        rep.replicas_checked++;
        if (!on_dev.count({r.file_id, r.version})) {
            rep.manifests_missing.push_back(r.file_id + ":" + std::to_string(r.version));
            ledger_.set_replica(r.file_id, r.version, device_id, ReplicaState::MISSING);
        }
    }

    // 3. chunk presence for everything still committed
    for (const auto& r : ledger_.replicas_on_device(device_id)) {
        if (r.state != ReplicaState::COMMITTED) continue;
        std::vector<std::string> ids;
        for (const auto& c : ledger_.get_chunks(r.file_id, r.version)) ids.push_back(c.chunk_id);
        std::vector<bool> have;
        if (!ids.empty() && dev.has_chunks(ids, have).ok() && have.size() == ids.size()) {
            size_t missing = 0;
            for (bool h : have) if (!h) missing++;
            if (missing) {
                rep.chunks_missing.push_back(r.file_id + ":" + std::to_string(r.version) + " (" + std::to_string(missing) + " chunks)");
                ledger_.record_audit(r.file_id, r.version, device_id, false, std::to_string(missing) + " chunks are missing from the device");
            }
        }
    }

    // 4. a suspect device earns its standing back only by passing audits of everything it still claims
    auto devrec = ledger_.get_device(device_id);
    bool suspect = devrec && devrec->state == "suspect";
    if (suspect || deep) {
        for (const auto& r : ledger_.replicas_on_device(device_id)) {
            if (r.state != ReplicaState::COMMITTED) continue;
            AuditReport ar = audit_replica(dev, device_id, r.file_id, r.version);
            rep.audited++;
            if (!ar.ok) rep.audit_failed++;
        }
    }
    if (suspect && rep.audit_failed == 0) {
        Res c = ledger_.clear_device_suspect(device_id, info.seq);
        rep.suspect_cleared = c.ok;
    }
    rep.ok = true;
    return rep;
}

}  // namespace tierfs
