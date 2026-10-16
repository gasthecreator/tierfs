// Client for the device protocol (v3): how the Mac talks to a storage device.
// Blocking, thread-safe (one request at a time per client), every request has a whole-request
// deadline. All device operations are idempotent, so one transparent retry on a stale
// connection is safe. See proto/PROTOCOL.md.
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "securechannel.hpp"
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
    // `pairing_secret` (32 bytes) makes every connection use the authenticated, encrypted channel (protocol v4); empty means the open
    // plaintext protocol (v3), which only a device that has not been paired will speak.
    DeviceClient(std::string host, uint16_t port, int timeout_ms = 3000, crypto::Bytes pairing_secret = {});
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

    // Garbage collection (ADR-0010). EPERM from a device that does not accept deletions; ENOSYS from one that predates them.
    // `deleted[i]` is 1 if item i was removed now, 0 if it was not there; `seq` is the device's commit sequence afterwards.
    DevRes delete_manifests(const std::vector<std::pair<std::string, int64_t>>& items, std::vector<uint8_t>& deleted, uint64_t* seq = nullptr);
    DevRes gc_status(GcStatus& out);
    DevRes sweep(uint64_t min_age_s, uint32_t max_chunks, bool dry_run, SweepOut& out);

    // Test hook: drop the connection so the next call has to reconnect.
    void disconnect();

    // Where to connect from the next new connection on (a device found again by name at another address). Never blocks on a request in progress and
    // never touches a connection that is up: the change takes effect when the connection is next made.
    void set_endpoint(const std::string& host, uint16_t port);
    std::string endpoint();  // "host:port" the next connection will use

private:
    struct Frame_;
    DevRes call(uint8_t type, const std::vector<uint8_t>& payload, std::vector<uint8_t>& reply, uint64_t expect_bytes);
    bool ensure_connected(DevRes* why);
    void drop_connection();
    bool tx(uint8_t type, uint32_t id, const std::vector<uint8_t>& payload, int64_t deadline);
    int rx(Frame& f, int64_t deadline);

    std::string host_, port_;
    std::mutex ep_mu_;  // guards pending_host_/pending_port_ (and nothing else, so it is never held across I/O)
    std::string pending_host_, pending_port_;
    int timeout_ms_;
    crypto::Bytes psk_;
    std::unique_ptr<chan::Channel> ch_;  // set when psk_ is
    int fd_ = -1;
    uint32_t next_id_ = 1;
    std::mutex mu_;
};

}  // namespace tierfs
