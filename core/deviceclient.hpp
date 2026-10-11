// Client for the device protocol (v3): how the Mac talks to a storage device.
// Blocking, thread-safe (one request at a time per client), every request has a whole-request
// deadline. All device operations are idempotent, so one transparent retry on a stale
// connection is safe. See proto/PROTOCOL.md.
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "devicestore.hpp"  // DevInfo, ManifestEntry, AuditItem, AuditOut (shared vocabulary)

namespace tierfs {

struct DevRes {
    int err = 0;           // 0 ok, otherwise an errno-style code
    std::string msg;
    bool ok() const { return err == 0; }
};

struct PutChunkReply {
    bool existed = false;
    std::string sha256_hex;  // hash of the blob the device now holds (the original, if it existed)
};
struct PutManifestReply {
    bool existed = false;
    uint64_t seq = 0;
    std::string sha256_hex;
};
struct ListReply {
    uint64_t epoch = 0, seq = 0;
    std::vector<ManifestEntry> entries;
};

class DeviceClient {
public:
    DeviceClient(std::string host, uint16_t port, int timeout_ms = 3000);
    ~DeviceClient();
    DeviceClient(const DeviceClient&) = delete;
    DeviceClient& operator=(const DeviceClient&) = delete;

    DevRes info(DevInfo& out);
    DevRes bind(const std::string& volume_id);
    DevRes has_chunks(const std::vector<std::string>& ids, std::vector<bool>& out);
    // Computes the blob's SHA-256 itself and sends it, so the device can reject damage in transit.
    DevRes put_chunk(const std::string& chunk_id, const std::vector<uint8_t>& blob, PutChunkReply& out);
    DevRes get_chunk(const std::string& chunk_id, std::vector<uint8_t>& out);
    DevRes put_manifest(const std::string& file_id, int64_t version, const std::vector<uint8_t>& blob,
                        const std::vector<std::string>& chunk_ids, PutManifestReply& out);
    DevRes get_manifest(const std::string& file_id, int64_t version, std::vector<uint8_t>& out);
    DevRes list_manifests(uint64_t since_seq, uint32_t max, ListReply& out);
    DevRes audit(const std::vector<AuditItem>& items, std::vector<AuditOut>& out);

    // Test hook: drop the connection so the next call has to reconnect.
    void disconnect();

private:
    struct Frame_;
    DevRes call(uint8_t type, const std::vector<uint8_t>& payload, std::vector<uint8_t>& reply, uint64_t expect_bytes);
    bool ensure_connected(DevRes* why);

    std::string host_, port_;
    int timeout_ms_;
    int fd_ = -1;
    uint32_t next_id_ = 1;
    std::mutex mu_;
};

}  // namespace tierfs
