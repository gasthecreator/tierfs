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
JNIEXPORT jint JNICALL Java_dev_tierfs_agent_Native_serve(JNIEnv* env, jclass, jstring dir, jint port, jstring bind) {
    forward_stderr_to_logcat();
    std::string d = to_std(env, dir), p = std::to_string(port), b = to_std(env, bind);
    std::vector<char*> av = {const_cast<char*>("tierfs-device"), const_cast<char*>(d.c_str()), const_cast<char*>(p.c_str()),
                             const_cast<char*>(b.c_str()), nullptr};
    return tierfs_device_main(4, av.data());
}

// The pairing secret of the store in `dir`: created if there is none (or replaced when `renew`). Returns "CODE\nKEYID", or "ERR: reason".
JNIEXPORT jstring JNICALL Java_dev_tierfs_agent_Native_pairing(JNIEnv* env, jclass, jstring dir, jboolean renew) {
    std::string d = to_std(env, dir), err;
    mkdir(d.c_str(), 0700);
    auto existing = load_pairing(d, &err);
    if (!err.empty()) return env->NewStringUTF(("ERR: " + err).c_str());
    if (renew || !existing) {
        Bytes secret = crypto::random_bytes(chan::PSK_LEN);
        if (secret.size() != chan::PSK_LEN) return env->NewStringUTF("ERR: the system random generator failed");
        if (!write_pairing(d, secret, renew, &err)) return env->NewStringUTF(("ERR: " + err).c_str());
        existing = secret;
    }
    crypto::SecretKey k(existing->data());
    return env->NewStringUTF((crypto::encode_recovery(k) + "\n" + chan::key_id_hex(*existing)).c_str());
}

// The key id of the store's pairing secret, or "" if it is not paired yet. (Public: it is announced on the network.)
JNIEXPORT jstring JNICALL Java_dev_tierfs_agent_Native_keyId(JNIEnv* env, jclass, jstring dir) {
    std::string err;
    auto existing = load_pairing(to_std(env, dir), &err);
    return env->NewStringUTF(existing ? chan::key_id_hex(*existing).c_str() : "");
}

}  // extern "C"
