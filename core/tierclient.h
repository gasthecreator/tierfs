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

typedef struct {
    const char *host;
    uint16_t port;
    int timeout_ms;      /* <= 0: 3000 */
    const char *cache_dir; /* NULL or "": ~/Library/Caches/tierfs/<host>_<port> */
    uint64_t cache_bytes;  /* chunk cache budget; 0: 512 MiB */
    int readahead;       /* chunks prefetched on sequential reads; <0: 4; 0: off */
} tc_config;

/* Does not connect yet; the first call connects lazily and every call
 * reconnects if the previous connection died. */
tc_client *tc_create(const tc_config *cfg);
void tc_destroy(tc_client *c);

int tc_getattr(tc_client *c, const char *path, tc_attr *out);

/* Return nonzero from the callback to stop early. */
typedef int (*tc_dir_cb)(void *ctx, const char *name, const tc_attr *attr);
int tc_readdir(tc_client *c, const char *path, tc_dir_cb cb, void *ctx);

/* Returns bytes read (0 at EOF) or -errno. Never a short count caused by an
 * error: the kernel would mistake it for end-of-file. May return fewer than
 * len only at EOF. */
int64_t tc_read(tc_client *c, const char *path, uint64_t off, uint32_t len,
                void *buf);

/* While a file is open its cached chunks are not evicted. Calls must balance. */
void tc_pin(tc_client *c, const char *path);
void tc_unpin(tc_client *c, const char *path);

typedef struct {
    uint64_t chunk_hits, chunk_misses, chunk_corrupt, chunk_evicted;
    uint64_t fetches;          /* READ requests sent for foreground reads */
    uint64_t prefetch_fetches; /* READ requests sent by the readahead thread */
    uint64_t prefetch_used;    /* prefetched chunks later consumed by a read */
    uint64_t bytes_fetched;
    uint64_t cache_bytes_used;
} tc_stats;
void tc_get_stats(tc_client *c, tc_stats *out);

#ifdef __cplusplus
}
#endif
#endif
