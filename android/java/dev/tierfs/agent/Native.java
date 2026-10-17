package dev.tierfs.agent;

/** The device server and its pairing files: the same C++ code that runs on the Mac (backend/device_server.cpp), loaded as a library. */
final class Native {
    static { System.loadLibrary("tierfsdevice"); }

    private Native() {}

    /** Runs the server until the process ends. Returns only if it could not start. */
    static native int serve(String dir, int port, String bind);

    /** The pairing secret of the store in {@code dir} (created if there is none, replaced when {@code renew}): "CODE\nKEYID", or "ERR: reason". */
    static native String pairing(String dir, boolean renew);

    /** The key ids of every pairing in the store (the original first), one per line; "" if there is none yet. */
    static native String keyId(String dir);

    /** A new pairing for another Mac: "CODE\nKEYID", or "ERR: reason". */
    static native String addPairing(String dir, String label, boolean allowDelete);

    /** One line per pairing: "KEYID\tLABEL\tdelete|nodelete"; a line "PROBLEM\t..." for a pairing file that is not acceptable. */
    static native String listPairings(String dir);

    /** Revokes a pairing: "" on success, otherwise the reason. A revoked Mac is refused at once. */
    static native String revokePairing(String dir, String keyId);
}
