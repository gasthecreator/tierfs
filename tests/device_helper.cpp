// Helper process for the device store crash-injection tests (spawned fresh, with
// TIERFS_CRASH_AT set, so it dies at the named point like a power cut).
//   device_helper put_chunk    <dir> <chunk_id> <blob_file>
//   device_helper put_manifest <dir> <file_id> <version> <blob_file> [chunk_id ...]
//   device_helper delete_manifest <dir> <file_id> <version>
//   device_helper sweep <dir> <min_age_s>        (both of these run with deletions allowed and no age floor)
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>

#include "../core/crypto.hpp"
#include "../core/devicestore.hpp"

using namespace tierfs;

static std::vector<uint8_t> slurp(const char* p) {
    std::ifstream f(p, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

int main(int argc, char** argv) {
    if (argc < 4) return 2;
    std::string cmd = argv[1], err;
    auto d = DeviceStore::open(argv[2], &err);
    if (!d) { fprintf(stderr, "helper: %s\n", err.c_str()); return 3; }
    if (cmd == "put_chunk" && argc >= 5) {
        auto blob = slurp(argv[4]);
        auto r = d->put_chunk(argv[3], blob, crypto::sha256_hex(blob.data(), blob.size()));
        fprintf(stderr, "helper: put_chunk -> %d %s\n", r.err, r.msg.c_str());
        return r.err ? 5 : 0;
    }
    if (cmd == "put_manifest" && argc >= 6) {
        auto blob = slurp(argv[5]);
        std::vector<std::string> ids(argv + 6, argv + argc);
        auto r = d->put_manifest(argv[3], atoll(argv[4]), blob, crypto::sha256_hex(blob.data(), blob.size()), ids);
        fprintf(stderr, "helper: put_manifest -> %d %s seq=%llu\n", r.err, r.msg.c_str(), (unsigned long long)r.seq);
        return r.err ? 5 : 0;
    }
    if (cmd == "delete_manifest" && argc >= 5) {
        d->set_deletions_allowed(true);
        auto r = d->delete_manifests({{argv[3], atoll(argv[4])}});
        fprintf(stderr, "helper: delete_manifest -> %d %s\n", r.err, r.msg.c_str());
        return r.err ? 5 : 0;
    }
    if (cmd == "sweep") {
        d->set_deletions_allowed(true);
        d->set_min_sweep_age(0);
        auto r = d->sweep(strtoull(argv[3], nullptr, 10), 1000, false);
        fprintf(stderr, "helper: sweep -> %d %s deleted=%llu\n", r.err, r.msg.c_str(), (unsigned long long)r.chunks_deleted);
        return r.err ? 5 : 0;
    }
    return 2;
}
