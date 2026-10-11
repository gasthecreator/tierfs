/*
 * Phase 0 spike: smallest possible read-only FUSE filesystem.
 *
 * Concepts you are learning here:
 *  - FUSE turns kernel VFS calls (stat, readdir, open, read) into callbacks
 *    in THIS process. Each callback must return 0/bytes on success or
 *    -errno on failure (e.g. -ENOENT = "no such file").
 *  - getattr is called constantly (Finder calls it for everything), so it
 *    must be fast and must never touch the network. That is why Phase 1+
 *    keeps metadata in a local database.
 */
#define FUSE_USE_VERSION 26
#include <fuse.h>

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

static const char *HELLO_PATH = "/hello.txt";
static const char *HELLO_DATA = "hello from tierfs phase 0\n";

static int hello_getattr(const char *path, struct stat *st) {
    memset(st, 0, sizeof(*st));
    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
    } else if (strcmp(path, HELLO_PATH) == 0) {
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = (off_t)strlen(HELLO_DATA);
    } else {
        return -ENOENT;
    }
    return 0;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t fill,
                         off_t off, struct fuse_file_info *fi) {
    (void)off; (void)fi;
    if (strcmp(path, "/") != 0) return -ENOENT;
    fill(buf, ".", NULL, 0);
    fill(buf, "..", NULL, 0);
    fill(buf, HELLO_PATH + 1, NULL, 0);
    return 0;
}

static int hello_open(const char *path, struct fuse_file_info *fi) {
    if (strcmp(path, HELLO_PATH) != 0) return -ENOENT;
    if ((fi->flags & O_ACCMODE) != O_RDONLY) return -EACCES;
    return 0;
}

/* Partial reads: the kernel asks for [offset, offset+size). Phase 1 will
 * fetch exactly this range from the remote backend. */
static int hello_read(const char *path, char *buf, size_t size, off_t off,
                      struct fuse_file_info *fi) {
    (void)fi;
    if (strcmp(path, HELLO_PATH) != 0) return -ENOENT;
    size_t len = strlen(HELLO_DATA);
    if ((size_t)off >= len) return 0;
    if (off + size > len) size = len - (size_t)off;
    memcpy(buf, HELLO_DATA + off, size);
    return (int)size;
}

static struct fuse_operations ops = {
    .getattr = hello_getattr,
    .readdir = hello_readdir,
    .open    = hello_open,
    .read    = hello_read,
};

int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &ops, NULL);
}
