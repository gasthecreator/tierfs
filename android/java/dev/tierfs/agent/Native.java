package dev.tierfs.agent;

/** The device server and its pairing files: the same C++ code that runs on the Mac (backend/device_server.cpp), loaded as a library. */
final class Native {
    static { System.loadLibrary("tierfsdevice"); }

    private Native() {}

    /** Runs the server until the process ends. Returns only if it could not start. */
    static native int serve(String dir, int port, String bind);

    /** The pairing secret of the store in {@code dir} (created if there is none, replaced when {@code renew}): "CODE\nKEYID", or "ERR: reason". */
    static native String pairing(String dir, boolean renew);

    /** The key id of the store's pairing secret, or "" if it has none yet. */
    static native String keyId(String dir);
}
