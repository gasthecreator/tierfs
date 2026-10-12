// Helper process for the overlay's crash-injection tests: runs ONE hydration and dies at the crash point named by
// TIERFS_CRASH_AT, like a power cut.
//   overlay_helper hydrate <ledger_dir> <origin_dir> <portA> <idA> <portB> <idB> <mount_path>
// The master key comes from TIERFS_TEST_MASTER (hex): test-only.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../core/overlay.hpp"

using namespace tierfs;

int main(int argc, char** argv) {
    if (argc < 9) return 2;
    const char* mh = getenv("TIERFS_TEST_MASTER");
    auto mk = mh ? crypto::from_hex(mh) : std::nullopt;
    if (!mk || mk->size() != 32) return 2;
    crypto::SecretKey master(mk->data());
    crypto::Keys keys(master);
    std::string err;
    auto ledger = Ledger::open(argv[2], &err);
    if (!ledger) { fprintf(stderr, "helper: %s\n", err.c_str()); return 3; }
    DeviceClient da("127.0.0.1", static_cast<uint16_t>(atoi(argv[4])), 3000), db("127.0.0.1", static_cast<uint16_t>(atoi(argv[6])), 3000);
    DeviceMap devs{{argv[5], &da}, {argv[7], &db}};
    OverlayConfig cfg;
    cfg.origin_dir = argv[3];
    cfg.logical_prefix = "/Users/me/proj/";
    Overlay ov(*ledger, keys, devs, cfg);
    if (strcmp(argv[1], "hydrate") == 0) {
        int r = ov.hydrate(argv[8]);
        fprintf(stderr, "helper: hydrate -> %d\n", r);
        return r == 0 ? 0 : 5;
    }
    return 2;
}
