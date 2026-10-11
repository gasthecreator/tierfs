/*
 * tierfs driver, Phase 1: read-only mount of a remote tree.
 *
 *   ./build/tierfs -f -o host=127.0.0.1,port=9099 <mountpoint>
 *
 * Every FUSE callback is a thin translation to the client library. Callbacks
 * return 0 / a byte count on success, or -errno.
 *
 * NOTE for later phases: right now getattr goes to the network on every call.
 * Phase 2 adds a local metadata cache so Finder never waits on the network.
 */
#define FUSE_USE_VERSION 26
#include <fuse.h>

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../core/tierclient.h"

static tc_client *g_client;

static void fill_stat(struct stat *st, const tc_attr *a) {
    memset(st, 0, sizeof(*st));
    st->st_uid = getuid(); /* show files as owned by you, not root */
    st->st_gid = getgid();
    st->st_mtime = (time_t)a->mtime;
    st->st_atime = st->st_ctime = st->st_mtime;
    if (a->is_dir) {
        st->st_mode = S_IFDIR | 0555; /* read-only in Phase 1 */
        st->st_nlink = 2;
    } else {
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = (off_t)a->size;
    }
}

static int t_getattr(const char *path, struct stat *st) {
    tc_attr a;
    int rc = tc_getattr(g_client, path, &a);
    if (rc) return rc;
    fill_stat(st, &a);
    return 0;
}

struct dir_ctx {
    void *buf;
    fuse_fill_dir_t fill;
};

static int dir_cb(void *ctx, const char *name, const tc_attr *a) {
    struct dir_ctx *d = ctx;
    struct stat st;
    fill_stat(&st, a);
    return d->fill(d->buf, name, &st, 0) != 0; /* nonzero = buffer full, stop */
}

static int t_readdir(const char *path, void *buf, fuse_fill_dir_t fill, off_t off,
                     struct fuse_file_info *fi) {
    (void)off;
    (void)fi;
    struct dir_ctx d = {buf, fill};
    fill(buf, ".", NULL, 0);
    fill(buf, "..", NULL, 0);
    return tc_readdir(g_client, path, dir_cb, &d);
}

static int t_open(const char *path, struct fuse_file_info *fi) {
    if ((fi->flags & O_ACCMODE) != O_RDONLY) return -EROFS;
    tc_attr a;
    int rc = tc_getattr(g_client, path, &a);
    if (rc) return rc;
    return a.is_dir ? -EISDIR : 0;
}

#define CHUNK (1u << 20)

/* The kernel may ask for more than one protocol read can return; loop until we
 * have everything or hit EOF / a short read. */
static int t_read(const char *path, char *buf, size_t size, off_t off,
                  struct fuse_file_info *fi) {
    (void)fi;
    size_t done = 0;
    while (done < size) {
        uint32_t want = (size - done) > CHUNK ? CHUNK : (uint32_t)(size - done);
        int64_t n = tc_read(g_client, path, (uint64_t)off + done, want, buf + done);
        if (n < 0) return done ? (int)done : (int)n;
        if (n == 0) break;
        done += (size_t)n;
        if ((uint32_t)n < want) break;
    }
    return (int)done;
}

static struct fuse_operations ops = {
    .getattr = t_getattr,
    .readdir = t_readdir,
    .open = t_open,
    .read = t_read,
};

struct opts {
    char *host;
    int port;
    int timeout_ms;
};

#define OPT(t, f) {t, offsetof(struct opts, f), 0}
static struct fuse_opt specs[] = {OPT("host=%s", host), OPT("port=%d", port),
                                  OPT("timeout=%d", timeout_ms), FUSE_OPT_END};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct opts o = {NULL, 9099, 3000};
    if (fuse_opt_parse(&args, &o, specs, NULL) == -1) return 2;
    g_client = tc_create(o.host ? o.host : "127.0.0.1", (uint16_t)o.port, o.timeout_ms);
    int rc = fuse_main(args.argc, args.argv, &ops, NULL);
    tc_destroy(g_client);
    return rc;
}
