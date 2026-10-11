// Helper process for the replicator crash-injection tests: runs ONE replicate against a device and
// dies at the crash point named by TIERFS_CRASH_AT, like a power cut.
//   repl_helper <ledger_dir> <device_port> <device_id> <file_id> <local_path>
// The master key comes from TIERFS_TEST_MASTER (hex): test-only, a real client uses the Keychain.
#include <cstdio>
#include <cstdlib>

#include "../core/replicator.hpp"

using namespace tierfs;

int main(int argc, char** argv) {
    if (argc < 6) return 2;
    const char* mh = getenv("TIERFS_TEST_MASTER");
    auto mk = mh ? crypto::from_hex(mh) : std::nullopt;
    if (!mk || mk->size() != 32) return 2;
    crypto::SecretKey master(mk->data());
    crypto::Keys keys(master);
    std::string err;
    auto ledger = Ledger::open(argv[1], &err);
    if (!ledger) { fprintf(stderr, "helper: %s\n", err.c_str()); return 3; }
    Replicator rep(*ledger, keys, ledger->volume_id());
    DeviceClient dev("127.0.0.1", static_cast<uint16_t>(atoi(argv[2])), 3000);
    ReplicateOutcome o = rep.replicate(dev, argv[3], argv[4], argv[5]);
    fprintf(stderr, "helper: replicate -> %s %s\n", o.ok ? "ok" : "failed", o.why.c_str());
    return o.ok ? 0 : 5;
}
