/*
 * tierfsd: the tiered-storage filesystem. A FUSE-T driver that is only a translation layer: every callback hands the request to
 * the daemon (core/tfs_c.h), which does all the thinking (the origin folder, the ledger, the devices, the write gate...).
 *
 *   ./build/tierfsd -o origin=<dir>,prefix=<logical prefix>,ledger=<dir>,keyfile=<file>,devices=host:port+host:port <mountpoint>
 *
 * It always runs in the foreground (-f is added): the daemon owns threads, which a fork would silently kill. Run it from a shell
 * with & or under launchd.
 *
 * The mountpoint must NOT be the origin folder (the daemon reads the origin through its path, which would then lead back into
 * this filesystem). To show the files at their original path, move the real folder aside (a rename on the same volume) and mount
 * over the old path.
 *
 * Errors: every callback returns the daemon's -errno. Network failures are EIO (FUSE-T turns other errnos into misleading ones;
 * see docs/PHASE2.md).
 */
#define FUSE_USE_VERSION 26
#include <fuse.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#include "../core/tfs_c.h"

static tfs_ctx *g_ctx;

static void fill_stat(struct stat *st, const tfs_stat *a) {
    memset(st, 0, sizeof(*st));
    st->st_uid = getuid(); /* everything here is yours */
    st->st_gid = getgid();
    st->st_mtimespec.tv_sec = (time_t)a->mtime;
    st->st_mtimespec.tv_nsec = (long)a->mtime_nsec;
    st->st_atimespec = st->st_ctimespec = st->st_mtimespec;
    st->st_blksize = 1 << 20;
    switch (a->kind) {
    case 0: st->st_mode = S_IFDIR | (a->mode & 07777); st->st_nlink = 2; break;
    case 2: st->st_mode = S_IFLNK | 0777; st->st_nlink = 1; st->st_size = (off_t)a->size; break;
    default: st->st_mode = S_IFREG | (a->mode & 07777); st->st_nlink = 1; st->st_size = (off_t)a->size; break;
    }
    st->st_blocks = (blkcnt_t)((a->size + 511) / 512);
}

static int g_trace;

static int t_getattr(const char *path, struct stat *st) {
    tfs_stat a;
    int rc = tfs_getattr(g_ctx, path, &a);
    if (g_trace) fprintf(stderr, "TRACE getattr %s -> %d (kind %d size %llu remote %d)\n", path, rc, rc ? -1 : a.kind, rc ? 0ull : (unsigned long long)a.size, rc ? 0 : a.remote);
    if (rc) return rc;
    fill_stat(st, &a);
    return 0;
}

static int t_fgetattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void)fi;
    return t_getattr(path, st);
}

static int t_readlink(const char *path, char *buf, size_t size) { return tfs_readlink(g_ctx, path, buf, size); }

struct dir_ctx { void *buf; fuse_fill_dir_t fill; };

static int dir_cb(void *ctx, const char *name, int kind, int remote) {
    struct dir_ctx *d = ctx;
    struct stat st;
    (void)remote;
    memset(&st, 0, sizeof st);
    st.st_mode = kind == 0 ? S_IFDIR : kind == 2 ? S_IFLNK : S_IFREG;
    return d->fill(d->buf, name, &st, 0) != 0; /* nonzero: the buffer is full */
}

static int t_readdir(const char *path, void *buf, fuse_fill_dir_t fill, off_t off, struct fuse_file_info *fi) {
    (void)off;
    (void)fi;
    struct dir_ctx d = {buf, fill};
    fill(buf, ".", NULL, 0);
    fill(buf, "..", NULL, 0);
    return tfs_readdir(g_ctx, path, dir_cb, &d);
}

static int t_open(const char *path, struct fuse_file_info *fi) {
    uint64_t fh = 0;
    int rc = tfs_open_file(g_ctx, path, fi->flags, &fh);
    if (rc) return rc;
    fi->fh = fh;
    return 0;
}

static int t_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    uint64_t fh = 0;
    int rc = tfs_create(g_ctx, path, (uint32_t)mode, fi->flags, &fh);
    if (rc) return rc;
    fi->fh = fh;
    return 0;
}

static int t_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)path;
    int64_t n = tfs_read(g_ctx, fi->fh, (uint64_t)off, size, buf);
    return n < 0 ? (int)n : (int)n;
}

static int t_write(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)path;
    int64_t n = tfs_write(g_ctx, fi->fh, (uint64_t)off, buf, size);
    return n < 0 ? (int)n : (int)n;
}

static int t_flush(const char *path, struct fuse_file_info *fi) { (void)path; (void)fi; return 0; }
static int t_fsync(const char *path, int datasync, struct fuse_file_info *fi) { (void)path; (void)datasync; return tfs_fsync(g_ctx, fi->fh); }
static int t_release(const char *path, struct fuse_file_info *fi) { (void)path; return tfs_release(g_ctx, fi->fh); }
static int t_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) { (void)path; return tfs_ftruncate(g_ctx, fi->fh, (uint64_t)size); }
static int t_truncate(const char *path, off_t size) { return tfs_truncate(g_ctx, path, (uint64_t)size); }
static int t_mkdir(const char *path, mode_t mode) { return tfs_mkdir(g_ctx, path, (uint32_t)mode); }
static int t_rmdir(const char *path) { return tfs_rmdir(g_ctx, path); }
static int t_unlink(const char *path) { return tfs_unlink(g_ctx, path); }
static int t_rename(const char *from, const char *to) { return tfs_rename(g_ctx, from, to); }
static int t_symlink(const char *target, const char *linkpath) { return tfs_symlink(g_ctx, target, linkpath); }
static int t_chmod(const char *path, mode_t mode) { return tfs_chmod(g_ctx, path, (uint32_t)mode); }
static int t_chown(const char *path, uid_t uid, gid_t gid) {
    return tfs_chown(g_ctx, path, uid == (uid_t)-1 ? -1 : (int64_t)uid, gid == (gid_t)-1 ? -1 : (int64_t)gid);
}

static int t_utimens(const char *path, const struct timespec tv[2]) {
    if (tv[1].tv_nsec == UTIME_OMIT) return tfs_utimens(g_ctx, path, 0, 0);
    int64_t t = tv[1].tv_nsec == UTIME_NOW ? (int64_t)time(NULL) : (int64_t)tv[1].tv_sec;
    return tfs_utimens(g_ctx, path, 1, t);
}

static int t_statfs(const char *path, struct statvfs *sv) {
    (void)path;
    tfs_fsstat s;
    int rc = tfs_statfs(g_ctx, &s);
    if (rc) return rc;
    memset(sv, 0, sizeof *sv);
    sv->f_bsize = (unsigned long)s.block_size;
    sv->f_frsize = (unsigned long)s.block_size;
    sv->f_blocks = s.blocks;
    sv->f_bfree = s.blocks_free;
    sv->f_bavail = s.blocks_avail;
    sv->f_files = s.files;
    sv->f_ffree = s.files_free;
    sv->f_namemax = 255;
    return 0;
}

static int t_setxattr(const char *path, const char *name, const char *value, size_t size, int flags, uint32_t position) {
    if (position != 0) return -EINVAL;
    int rc = tfs_setxattr(g_ctx, path, name, value, size, flags);
    if (g_trace) fprintf(stderr, "TRACE setxattr %s %s (%zu bytes, flags %d) -> %d\n", path, name, size, flags, rc);
    return rc;
}
static int t_getxattr(const char *path, const char *name, char *value, size_t size, uint32_t position) {
    if (position != 0) return -EINVAL;
    int64_t n = tfs_getxattr(g_ctx, path, name, value, size);
    if (g_trace) fprintf(stderr, "TRACE getxattr %s %s (size %zu) -> %lld\n", path, name, size, (long long)n);
    return n < 0 ? (int)n : (int)n;
}
static int t_listxattr(const char *path, char *list, size_t size) {
    int64_t n = tfs_listxattr(g_ctx, path, list, size);
    if (g_trace) fprintf(stderr, "TRACE listxattr %s (size %zu) -> %lld\n", path, size, (long long)n);
    return n < 0 ? (int)n : (int)n;
}
static int t_removexattr(const char *path, const char *name) { return tfs_removexattr(g_ctx, path, name); }

static struct fuse_operations ops = {
    .getattr = t_getattr, .fgetattr = t_fgetattr, .readlink = t_readlink, .readdir = t_readdir,
    .open = t_open, .create = t_create, .read = t_read, .write = t_write, .flush = t_flush,
    .fsync = t_fsync, .release = t_release, .ftruncate = t_ftruncate, .truncate = t_truncate,
    .mkdir = t_mkdir, .rmdir = t_rmdir, .unlink = t_unlink, .rename = t_rename, .symlink = t_symlink,
    .chmod = t_chmod, .chown = t_chown, .utimens = t_utimens, .statfs = t_statfs,
    .setxattr = t_setxattr, .getxattr = t_getxattr, .listxattr = t_listxattr, .removexattr = t_removexattr,
};

struct opts {
    char *origin, *prefix, *ledger, *keyfile, *devices, *control;
    int maint, wait_ms, background, notify, scan, cache_mb;
};

#define OPT(t, f) {t, offsetof(struct opts, f), 0}
static struct fuse_opt specs[] = {
    OPT("origin=%s", origin), OPT("prefix=%s", prefix), OPT("ledger=%s", ledger), OPT("keyfile=%s", keyfile),
    OPT("devices=%s", devices), OPT("control=%s", control), OPT("maint=%d", maint), OPT("waitms=%d", wait_ms),
    OPT("background=%d", background), OPT("notify=%d", notify), OPT("scan=%d", scan), OPT("cachemb=%d", cache_mb),
    FUSE_OPT_END};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct opts o = {0};
    o.maint = 60; o.background = 1; o.notify = 1; o.scan = 1; o.cache_mb = 64; o.wait_ms = 30000;
    if (fuse_opt_parse(&args, &o, specs, NULL) == -1) return 2;
    if (!o.origin || !o.prefix || !o.ledger || !o.keyfile) {
        fprintf(stderr, "usage: %s -o origin=DIR,prefix=/logical/,ledger=DIR,keyfile=FILE[,devices=host:port+host:port] MOUNTPOINT\n", argv[0]);
        return 2;
    }
    g_trace = getenv("TIERFS_TRACE") != NULL;
    fuse_opt_add_arg(&args, "-f"); /* the daemon owns threads: never fork after they exist */
    tfs_options t = {0};
    t.ledger = o.ledger; t.origin = o.origin; t.prefix = o.prefix; t.keyfile = o.keyfile; t.devices = o.devices;
    t.control = o.control; t.maint_seconds = o.maint; t.write_wait_ms = o.wait_ms; t.background = o.background;
    t.notify = o.notify; t.scan_at_start = o.scan; t.cache_mb = o.cache_mb;
    char err[512] = {0};
    g_ctx = tfs_open(&t, err, sizeof err);
    if (!g_ctx) {
        fprintf(stderr, "tierfsd: %s\n", err);
        return 1;
    }
    char notes[4096];
    if (tfs_startup_notes(g_ctx, notes, sizeof notes) > 0) fprintf(stderr, "tierfsd: start-up:\n%s", notes);
    int rc = fuse_main(args.argc, args.argv, &ops, NULL);
    tfs_close(g_ctx);
    return rc;
}
