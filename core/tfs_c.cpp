#include "tfs_c.h"

#include <cerrno>
#include <cstring>

#include "daemon.hpp"

using namespace tierfs;

struct tfs_ctx {
    std::unique_ptr<Daemon> daemon;
    Overlay& ov() { return daemon->overlay(); }
};

namespace {
template <class F> auto guarded(F f) -> decltype(f()) {
    try { return f(); } catch (...) { return static_cast<decltype(f())>(-EIO); }
}
int kind_code(OvKind k) { return k == OvKind::Dir ? 0 : k == OvKind::File ? 1 : k == OvKind::Symlink ? 2 : 3; }
}  // namespace

tfs_ctx *tfs_open(const tfs_options *o, char *err, size_t errlen) {
    auto say = [&](const std::string& m) { if (err && errlen) snprintf(err, errlen, "%s", m.c_str()); };
    try {
        DaemonConfig c;
        c.ledger_dir = o->ledger ? o->ledger : "";
        c.origin_dir = o->origin ? o->origin : "";
        c.logical_prefix = o->prefix ? o->prefix : "";
        c.key_file = o->keyfile ? o->keyfile : "";
        if (o->devices) {
            std::string all = o->devices, cur;
            for (char ch : all + "+") { if (ch == '+') { if (!cur.empty()) c.devices.push_back(cur); cur.clear(); } else cur += ch; }
        }
        if (o->control) c.control_socket = o->control;
        c.maint_seconds = o->maint_seconds;
        if (o->write_wait_ms > 0) c.write_wait_ms = o->write_wait_ms;
        c.background_replication = o->background != 0;
        c.notify = o->notify != 0;
        c.scan_at_start = o->scan_at_start != 0;
        if (o->cache_mb > 0) c.cache_bytes = static_cast<size_t>(o->cache_mb) << 20;
        if (o->readahead >= 0) c.readahead_chunks = o->readahead;  // negative: the daemon's default
        c.gc = o->gc != 0;
        if (o->gc_keep_versions > 0) c.gc_config.keep_versions = o->gc_keep_versions;
        if (o->gc_retention_days > 0) c.gc_config.rules.deleted_retention_seconds = static_cast<int64_t>(o->gc_retention_days) * 86400;
        if (o->low_gb > 0) c.policy.low_free_bytes = static_cast<uint64_t>(o->low_gb) << 30;
        if (o->critical_gb > 0) c.policy.critical_free_bytes = static_cast<uint64_t>(o->critical_gb) << 30;
        if (o->low_pct > 0) c.policy.low_free_fraction = o->low_pct / 100.0;
        if (o->critical_pct > 0) c.policy.critical_free_fraction = o->critical_pct / 100.0;
        if (o->space_check >= 0) c.space_check_seconds = o->space_check;  // negative: the daemon's default
        std::string e;
        auto d = Daemon::create(c, &e);
        if (!d) { say(e); return nullptr; }
        if (!d->start(&e)) { say(e); return nullptr; }
        auto* ctx = new tfs_ctx;
        ctx->daemon = std::move(d);
        return ctx;
    } catch (const std::exception& ex) {
        say(std::string("unexpected error: ") + ex.what());
        return nullptr;
    }
}

void tfs_close(tfs_ctx *c) { if (c) { c->daemon->stop(); delete c; } }

size_t tfs_startup_notes(tfs_ctx *c, char *buf, size_t size) {
    std::string all;
    for (auto& n : c->daemon->startup_notes()) all += n + "\n";
    if (buf && size) snprintf(buf, size, "%s", all.c_str());
    return all.size();
}

int tfs_getattr(tfs_ctx *c, const char *path, tfs_stat *st) {
    return guarded([&] {
        OvStat s;
        int r = c->ov().getattr(path, &s);
        if (r == 0 && st) {
            st->kind = kind_code(s.kind);
            st->size = s.size;
            st->mtime = s.mtime;
            st->mtime_nsec = s.mtime_nsec;
            st->mode = s.mode;
            st->remote = s.remote;
            st->nlink = s.nlink;
            st->ino = s.ino;
        }
        return r;
    });
}

int tfs_readdir(tfs_ctx *c, const char *path, tfs_dir_cb cb, void *cbctx) {
    return guarded([&] {
        std::vector<OvEntry> es;
        int r = c->ov().readdir(path, &es);
        if (r != 0) return r;
        for (auto& e : es) if (cb(cbctx, e.name.c_str(), kind_code(e.kind), e.remote, e.ino)) break;
        return 0;
    });
}

int tfs_readlink(tfs_ctx *c, const char *path, char *buf, size_t size) {
    return guarded([&] {
        std::string t;
        int r = c->ov().readlink(path, &t);
        if (r != 0) return r;
        if (size) snprintf(buf, size, "%s", t.c_str());
        return 0;
    });
}

int tfs_open_file(tfs_ctx *c, const char *path, int flags, uint64_t *fh) { return guarded([&] { return c->ov().open(path, flags, fh); }); }
int tfs_create(tfs_ctx *c, const char *path, uint32_t mode, int flags, uint64_t *fh) { return guarded([&] { return c->ov().create(path, mode, flags, fh); }); }
int64_t tfs_read(tfs_ctx *c, uint64_t fh, uint64_t offset, size_t size, void *buf) { return guarded([&] { return c->ov().read_fh(fh, offset, size, static_cast<uint8_t*>(buf)); }); }
int64_t tfs_write(tfs_ctx *c, uint64_t fh, uint64_t offset, const void *buf, size_t size) { return guarded([&] { return c->ov().write_fh(fh, offset, static_cast<const uint8_t*>(buf), size); }); }
int tfs_ftruncate(tfs_ctx *c, uint64_t fh, uint64_t size) { return guarded([&] { return c->ov().ftruncate(fh, size); }); }
int tfs_fsync(tfs_ctx *c, uint64_t fh) { return guarded([&] { return c->ov().fsync_fh(fh); }); }
int tfs_release(tfs_ctx *c, uint64_t fh) { return guarded([&] { return c->ov().release(fh); }); }
int tfs_truncate(tfs_ctx *c, const char *path, uint64_t size) { return guarded([&] { return c->ov().truncate(path, size); }); }
int tfs_mkdir(tfs_ctx *c, const char *path, uint32_t mode) { return guarded([&] { return c->ov().mkdir(path, mode); }); }
int tfs_rmdir(tfs_ctx *c, const char *path) { return guarded([&] { return c->ov().rmdir(path); }); }
int tfs_unlink(tfs_ctx *c, const char *path) { return guarded([&] { return c->ov().unlink(path); }); }
int tfs_rename(tfs_ctx *c, const char *from, const char *to) { return guarded([&] { return c->ov().rename(from, to); }); }
int tfs_symlink(tfs_ctx *c, const char *target, const char *linkpath) { return guarded([&] { return c->ov().symlink(target, linkpath); }); }
int tfs_link(tfs_ctx* c, const char* from, const char* to) {
    return guarded([&] { return c->ov().link(from, to); });
}

static LockType lock_type_of(int t) { return t == 0 ? LockType::Read : t == 1 ? LockType::Write : LockType::Unlock; }
static int lock_code_of(LockType t) { return t == LockType::Read ? 0 : t == LockType::Write ? 1 : 2; }

int tfs_getlk(tfs_ctx* c, uint64_t fh, uint64_t owner, int* type, uint64_t* start, uint64_t* len, uint64_t* blocker) {
    return guarded([&] {
        if (!type || !start || !len) return -EINVAL;
        LockInfo lk;
        lk.type = lock_type_of(*type);
        lk.start = *start;
        lk.len = *len;
        int r = c->ov().getlk(fh, owner, &lk);
        if (r == 0) {
            *type = lock_code_of(lk.type);
            *start = lk.start;
            *len = lk.len;
            if (blocker) *blocker = lk.owner;
        }
        return r;
    });
}
int tfs_setlk(tfs_ctx* c, uint64_t fh, uint64_t owner, int type, uint64_t start, uint64_t len) {
    return guarded([&] { return c->ov().setlk(fh, owner, LockRange{lock_type_of(type), start, len}); });
}
int tfs_flock(tfs_ctx* c, uint64_t fh, uint64_t owner, int type) {
    return guarded([&] { return c->ov().flock_op(fh, owner, lock_type_of(type)); });
}
int tfs_unlock_owner(tfs_ctx* c, uint64_t fh, uint64_t owner) {
    return guarded([&] { return c->ov().unlock_owner(fh, owner); });
}

int tfs_chmod(tfs_ctx *c, const char *path, uint32_t mode) { return guarded([&] { return c->ov().chmod(path, mode); }); }
int tfs_chown(tfs_ctx *c, const char *path, int64_t uid, int64_t gid) { return guarded([&] { return c->ov().chown(path, uid, gid); }); }
int tfs_utimens(tfs_ctx *c, const char *path, int has_mtime, int64_t mtime) {
    return guarded([&] { return c->ov().utimens(path, has_mtime ? std::optional<int64_t>(mtime) : std::nullopt); });
}
int tfs_statfs(tfs_ctx *c, tfs_fsstat *out) {
    return guarded([&] {
        Overlay::FsStats s;
        int r = c->ov().statfs(&s);
        if (r == 0 && out) { out->block_size = s.block_size; out->blocks = s.blocks; out->blocks_free = s.blocks_free; out->blocks_avail = s.blocks_avail; out->files = s.files; out->files_free = s.files_free; }
        return r;
    });
}
int64_t tfs_getxattr(tfs_ctx *c, const char *path, const char *name, void *buf, size_t size) { return guarded([&] { return c->ov().getxattr(path, name, static_cast<uint8_t*>(buf), size); }); }
int64_t tfs_listxattr(tfs_ctx *c, const char *path, char *buf, size_t size) { return guarded([&] { return c->ov().listxattr(path, buf, size); }); }
int tfs_setxattr(tfs_ctx *c, const char *path, const char *name, const void *value, size_t size, int flags) { return guarded([&] { return c->ov().setxattr(path, name, static_cast<const uint8_t*>(value), size, flags); }); }
int tfs_removexattr(tfs_ctx *c, const char *path, const char *name) { return guarded([&] { return c->ov().removexattr(path, name); }); }
