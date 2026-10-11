// Helper process for the drop-engine crash-injection tests: runs ONE drop, purge or restore against two
// devices and dies at the crash point named by TIERFS_CRASH_AT, like a power cut.
//   drop_helper drop    <ledger_dir> <files_dir> <qroot> <portA> <idA> <portB> <idB> <consent> <file_id>
//   drop_helper purge   <ledger_dir> <files_dir> <qroot> <portA> <idA> <portB> <idB> <intent_id>
//   drop_helper restore <ledger_dir> <files_dir> <qroot> <portA> <idA> <portB> <idB> <intent_id>
// The master key comes from TIERFS_TEST_MASTER (hex): test-only. TIERFS_FAKE_NOW sets the clock.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../core/dropengine.hpp"

using namespace tierfs;

int main(int argc, char** argv) {
    if (argc < 10) return 2;
    const char* mh = getenv("TIERFS_TEST_MASTER");
    auto mk = mh ? crypto::from_hex(mh) : std::nullopt;
    if (!mk || mk->size() != 32) return 2;
    crypto::SecretKey master(mk->data());
    crypto::Keys keys(master);
    std::string err;
    auto ledger = Ledger::open(argv[2], &err);
    if (!ledger) { fprintf(stderr, "helper: %s\n", err.c_str()); return 3; }
    if (const char* t = getenv("TIERFS_FAKE_NOW")) {
        int64_t now = atoll(t);
        ledger->set_clock([now] { return now; });
    }
    std::string files = argv[3];
    Replicator rep(*ledger, keys, ledger->volume_id());
    DropEngine eng(*ledger, rep, keys, ledger->volume_id(), DropPolicy{}, argv[4],
                   [files](const FileRec& f) { return files + "/" + f.path.substr(f.path.rfind('/') + 1); });
    DeviceClient da("127.0.0.1", static_cast<uint16_t>(atoi(argv[5])), 3000), db("127.0.0.1", static_cast<uint16_t>(atoi(argv[7])), 3000);
    DeviceMap devs{{argv[6], &da}, {argv[8], &db}};
    std::string cmd = argv[1];
    if (cmd == "drop") {
        DropOutcome o = eng.drop(argv[10], argv[9], devs);
        fprintf(stderr, "helper: drop -> %s %s\n", o.ok ? "ok" : "failed", o.why.c_str());
        return o.ok ? 0 : 5;
    }
    if (cmd == "purge") {
        PurgeOutcome o = eng.purge(argv[9], devs, true);
        fprintf(stderr, "helper: purge -> %s %s\n", o.ok ? "ok" : "failed", o.why.c_str());
        return o.ok ? 0 : 5;
    }
    if (cmd == "restore") {
        RestoreOutcome o = eng.restore(argv[9], "test");
        fprintf(stderr, "helper: restore -> %s %s\n", o.ok ? "ok" : "failed", o.why.c_str());
        return o.ok ? 0 : 5;
    }
    return 2;
}
