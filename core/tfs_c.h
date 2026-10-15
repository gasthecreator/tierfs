/* A C interface to the daemon, for the FUSE driver (mount/tierfsd.c). Every function returns 0 / a byte count on success and
 * -errno on failure, like the FUSE callbacks it serves. Thread-safe. Nothing here throws. */
#ifndef TIERFS_TFS_C_H
#define TIERFS_TFS_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tfs_ctx tfs_ctx;

typedef struct tfs_options {
    const char *ledger;      /* directory of the ledger (and the control socket) */
    const char *origin;      /* the real folder with the local bytes */
    const char *prefix;      /* logical path prefix, e.g. "/Users/me/Projects/" */
    const char *keyfile;     /* 64 hex characters (development form of the key) */
    const char *devices;     /* host:port entries separated by '+' */
    const char *control;     /* control socket path; NULL = <ledger>/control.sock; "none" = no socket */
    int maint_seconds;       /* maintenance period (0 = none) */
    int write_wait_ms;       /* how long a writer waits for a drop/hydration of its file */
    int background;          /* the maintenance thread copies cold files to the devices */
    int notify;              /* macOS notifications when space runs short */
    int scan_at_start;
    int cache_mb;            /* verified remote chunks kept in memory */
    int readahead;           /* chunks fetched ahead for a sequential reader of an offloaded file (0 = off; negative = the default, 4) */
    int gc;                  /* the maintenance thread forgets old versions on the devices and has them free the space (0 = only on request) */
    int gc_keep_versions;    /* newest committed versions of a live file to keep (0 = default 3) */
    int gc_retention_days;   /* how long a deleted file can be undeleted before its data goes (0 = default 30) */
} tfs_options;

typedef struct tfs_stat {
    int kind;                /* 0 directory, 1 file, 2 symlink, 3 other */
    uint64_t size;
    int64_t mtime;           /* seconds */
    int64_t mtime_nsec;      /* the sub-second part */
    uint32_t mode;           /* permission bits */
    int remote;              /* the bytes are on the devices, not in the origin */
    uint32_t nlink;          /* names the file has (1 for a file that is only on the devices) */
} tfs_stat;

typedef struct tfs_fsstat {
    uint64_t block_size, blocks, blocks_free, blocks_avail, files, files_free;
} tfs_fsstat;

typedef int (*tfs_dir_cb)(void *ctx, const char *name, int kind, int remote);

/* Creates the daemon and starts it (recovery, scan, threads). NULL with a message in err on failure. */
tfs_ctx *tfs_open(const tfs_options *o, char *err, size_t errlen);
void tfs_close(tfs_ctx *c);
/* What start-up recovery and the first scan did, one line each. */
size_t tfs_startup_notes(tfs_ctx *c, char *buf, size_t size);

int tfs_getattr(tfs_ctx *c, const char *path, tfs_stat *st);
int tfs_readdir(tfs_ctx *c, const char *path, tfs_dir_cb cb, void *cbctx);
int tfs_readlink(tfs_ctx *c, const char *path, char *buf, size_t size);
int tfs_open_file(tfs_ctx *c, const char *path, int flags, uint64_t *fh);
int tfs_create(tfs_ctx *c, const char *path, uint32_t mode, int flags, uint64_t *fh);
int64_t tfs_read(tfs_ctx *c, uint64_t fh, uint64_t offset, size_t size, void *buf);
int64_t tfs_write(tfs_ctx *c, uint64_t fh, uint64_t offset, const void *buf, size_t size);
int tfs_ftruncate(tfs_ctx *c, uint64_t fh, uint64_t size);
int tfs_fsync(tfs_ctx *c, uint64_t fh);
int tfs_release(tfs_ctx *c, uint64_t fh);
int tfs_truncate(tfs_ctx *c, const char *path, uint64_t size);
int tfs_mkdir(tfs_ctx *c, const char *path, uint32_t mode);
int tfs_rmdir(tfs_ctx *c, const char *path);
int tfs_unlink(tfs_ctx *c, const char *path);
int tfs_rename(tfs_ctx *c, const char *from, const char *to);
int tfs_symlink(tfs_ctx *c, const char *target, const char *linkpath);
int tfs_link(tfs_ctx *c, const char *from, const char *to);
/* Advisory locks (ADR-0011). type: 0 shared/read, 1 exclusive/write, 2 unlock. len 0 = to the end of the file. All of them only TRY: -EAGAIN means "would
 * block", and the caller polls if it wants to wait. getlk fills the blocking lock (type 2 = nothing in the way). */
int tfs_getlk(tfs_ctx *c, uint64_t fh, uint64_t owner, int *type, uint64_t *start, uint64_t *len, uint64_t *blocker);
int tfs_setlk(tfs_ctx *c, uint64_t fh, uint64_t owner, int type, uint64_t start, uint64_t len);
int tfs_flock(tfs_ctx *c, uint64_t fh, uint64_t owner, int type);
int tfs_unlock_owner(tfs_ctx *c, uint64_t fh, uint64_t owner);
int tfs_chmod(tfs_ctx *c, const char *path, uint32_t mode);
int tfs_chown(tfs_ctx *c, const char *path, int64_t uid, int64_t gid);
int tfs_utimens(tfs_ctx *c, const char *path, int has_mtime, int64_t mtime);
int tfs_statfs(tfs_ctx *c, tfs_fsstat *out);
int64_t tfs_getxattr(tfs_ctx *c, const char *path, const char *name, void *buf, size_t size);
int64_t tfs_listxattr(tfs_ctx *c, const char *path, char *buf, size_t size);
int tfs_setxattr(tfs_ctx *c, const char *path, const char *name, const void *value, size_t size, int flags);
int tfs_removexattr(tfs_ctx *c, const char *path, const char *name);

#ifdef __cplusplus
}
#endif
#endif
