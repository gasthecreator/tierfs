// Helper process for the ledger crash-injection tests. It is spawned fresh (no
// fork-without-exec, which is unsafe on macOS once system libraries are loaded)
// with TIERFS_CRASH_AT set, so it dies at the named crash point exactly like a
// power cut or `kill -9` would. Exit 0 means the crash point never fired.
//
//   ledger_helper drop     <dir> <file_id> <consent_id>
//   ledger_helper complete <dir> <intent_id>
// TIERFS_FAKE_NOW=<unix seconds> makes it use the test's clock.
#include <cstdio>
#include <cstdlib>
#include <string>

#include "../core/ledger.hpp"

using namespace tierfs;

int main(int argc, char** argv) {
    if (argc < 4) return 2;
    std::string cmd = argv[1], err;
    auto L = Ledger::open(argv[2], &err);
    if (!L) { fprintf(stderr, "helper: %s\n", err.c_str()); return 3; }
    if (const char* t = getenv("TIERFS_FAKE_NOW")) {
        int64_t now = atoll(t);
        L->set_clock([now] { return now; });
    }
    if (cmd == "drop" && argc >= 5) {
        auto f = L->get_file(argv[3]);
        if (!f) return 4;
        Res r = L->begin_drop(argv[3], f->current_version, f->generation, argv[4], 2.0, 600);
        fprintf(stderr, "helper: begin_drop -> %s %s\n", r.ok ? "ok" : "refused", r.why.c_str());
        return r.ok ? 0 : 5;
    }
    if (cmd == "complete") {
        Res r = L->complete_drop(argv[3]);
        fprintf(stderr, "helper: complete_drop -> %s %s\n", r.ok ? "ok" : "refused", r.why.c_str());
        return r.ok ? 0 : 5;
    }
    return 2;
}
