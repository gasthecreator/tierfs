/* C interface to the tierfs client, so the C FUSE driver can use the C++
 * implementation. All functions return 0 / byte counts on success and a
 * negative errno on failure, exactly what FUSE callbacks want to return. */
#ifndef TIERCLIENT_H
#define TIERCLIENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tc_client tc_client;

typedef struct {
    uint8_t is_dir;
    uint64_t size;
    int64_t mtime; /* unix seconds */
    uint32_t mode; /* permission bits only */
} tc_attr;

/* Does not connect yet; the first call connects lazily and every call
 * reconnects if the previous connection died. cache_dir holds the persistent
 * metadata cache (created if missing); NULL or "" keeps it in memory only. */
tc_client *tc_create(const char *host, uint16_t port, int timeout_ms,
                     const char *cache_dir);
void tc_destroy(tc_client *c);

int tc_getattr(tc_client *c, const char *path, tc_attr *out);

/* Return nonzero from the callback to stop early. */
typedef int (*tc_dir_cb)(void *ctx, const char *name, const tc_attr *attr);
int tc_readdir(tc_client *c, const char *path, tc_dir_cb cb, void *ctx);

/* Returns bytes read (0 at EOF, possibly fewer than len) or -errno. */
int64_t tc_read(tc_client *c, const char *path, uint64_t off, uint32_t len,
                void *buf);

#ifdef __cplusplus
}
#endif
#endif
