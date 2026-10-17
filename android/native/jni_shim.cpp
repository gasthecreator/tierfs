// The Android agent's native side: the SAME device server as backend/device_server.cpp (the store, the wire protocol, the secure channel, the pairing
// files), compiled into a shared library and started from Java. Nothing about the protocol is re-implemented here.
//
// `main` is renamed and included so the code that is tested on the Mac (tests/deviceauth_test.cpp, devicenet_test.cpp, gc_test.cpp) is the code that
// runs on the phone. The server never returns on its own; the service that hosts it runs in its own process (":device") and stops it by ending the
// process, which the store is built to survive (docs/DURABLE_STORE.md).
#include <android/log.h>
#include <jni.h>

#define main tierfs_device_main
#include "../../backend/device_server.cpp"
#undef main

namespace {

// stderr goes nowhere in an Android app; the server's start-up line and warnings are most useful in logcat.
void forward_stderr_to_logcat() {
    int fds[2];
    if (pipe(fds) != 0) return;
    dup2(fds[1], 2);
    close(fds[1]);
    int rd = fds[0];
    std::thread([rd] {
        std::string line;
        char ch;
        while (read(rd, &ch, 1) == 1) {
            if (ch == '\n') {
                __android_log_print(ANDROID_LOG_INFO, "tierfs-device", "%s", line.c_str());
                line.clear();
            } else if (line.size() < 1000) {
                line += ch;
            }
        }
    }).detach();
}

std::string to_std(JNIEnv* env, jstring s) {
    if (!s) return "";
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out = c ? c : "";
    if (c) env->ReleaseStringUTFChars(s, c);
    return out;
}

}  // namespace

extern "C" {

// Runs the server until the process ends. Returns only if it could not start (a message is in logcat); the value is its exit code.
JNIEXPORT jint JNICALL Java_dev_tierfs_agent_Native_serve(JNIEnv* env, jclass, jstring dir, jint port, jstring bind, jstring lock_dir) {
    forward_stderr_to_logcat();
    std::string d = to_std(env, dir), p = std::to_string(port), b = to_std(env, bind);
    std::string lk = to_std(env, lock_dir), lock_arg = "--lock-dir=" + lk;
    std::vector<char*> av = {const_cast<char*>("tierfs-device"), const_cast<char*>(d.c_str()), const_cast<char*>(p.c_str()),
                             const_cast<char*>(b.c_str())};
    if (!lk.empty()) av.push_back(const_cast<char*>(lock_arg.c_str()));   // the lock lives where files can be locked (internal storage)
    av.push_back(nullptr);
    return tierfs_device_main(static_cast<int>(av.size()) - 1, av.data());
}

// The original pairing secret of the store in `dir`: created if there is none (or replaced when `renew`). Returns "CODE\nKEYID", or "ERR: reason".
JNIEXPORT jstring JNICALL Java_dev_tierfs_agent_Native_pairing(JNIEnv* env, jclass, jstring dir, jboolean renew) {
    std::string d = to_std(env, dir), err;
    std::vector<std::string> problems;
    std::optional<pairing::Entry> primary;
    for (auto& e : pairing::list(d, &problems))
        if (e.primary) primary = e;
    if (!problems.empty()) return env->NewStringUTF(("ERR: " + problems[0]).c_str());
    if (renew || !primary) {
        primary = pairing::set_primary(d, renew, &err);
        if (!primary) return env->NewStringUTF(("ERR: " + err).c_str());
    }
    crypto::SecretKey k(primary->secret.data());
    return env->NewStringUTF((crypto::encode_recovery(k) + "\n" + primary->key_id).c_str());
}

// A new pairing for another Mac: "CODE\nKEYID", or "ERR: reason".
JNIEXPORT jstring JNICALL Java_dev_tierfs_agent_Native_addPairing(JNIEnv* env, jclass, jstring dir, jstring label, jboolean allowDelete) {
    std::string err;
    auto e = pairing::add(to_std(env, dir), to_std(env, label), allowDelete, &err);
    if (!e) return env->NewStringUTF(("ERR: " + err).c_str());
    crypto::SecretKey k(e->secret.data());
    return env->NewStringUTF((crypto::encode_recovery(k) + "\n" + e->key_id).c_str());
}

// One line per pairing: "KEYID\tLABEL\tdelete|nodelete" (a line "PROBLEM\t..." for a file that is not acceptable).
JNIEXPORT jstring JNICALL Java_dev_tierfs_agent_Native_listPairings(JNIEnv* env, jclass, jstring dir) {
    std::vector<std::string> problems;
    std::string out;
    for (auto& e : pairing::list(to_std(env, dir), &problems))
        out += e.key_id + "\t" + e.label + "\t" + (e.allow_delete ? "delete" : "nodelete") + "\n";
    for (auto& p : problems) out += "PROBLEM\t" + p + "\n";
    return env->NewStringUTF(out.c_str());
}

// Revokes a pairing: "" on success, otherwise the reason.
JNIEXPORT jstring JNICALL Java_dev_tierfs_agent_Native_revokePairing(JNIEnv* env, jclass, jstring dir, jstring keyId) {
    std::string err;
    return env->NewStringUTF(pairing::revoke(to_std(env, dir), to_std(env, keyId), &err) ? "" : err.c_str());
}

// The key ids of every pairing (the first is the original), one per line; "" if the store is not paired yet. (Public: they are announced on the
// network.)
JNIEXPORT jstring JNICALL Java_dev_tierfs_agent_Native_keyId(JNIEnv* env, jclass, jstring dir) {
    std::string out;
    for (auto& e : pairing::list(to_std(env, dir))) out += (out.empty() ? "" : "\n") + e.key_id;
    return env->NewStringUTF(out.c_str());
}

}  // extern "C"
