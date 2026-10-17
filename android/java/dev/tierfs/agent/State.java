package dev.tierfs.agent;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * What the person has chosen, in a small file in the app's private storage. Both processes (the screen and the ":device" service) read it, and the
 * service reads it again when the system restarts it, so it is written atomically and never held in memory across calls.
 */
final class State {
    static final int DEFAULT_PORT = 9100;
    boolean on; // the person switched the storage server on (and has not switched it off)
    boolean boot; // start it again when the phone starts
    boolean external; // keep the store in the app's folder on shared storage (a memory card, if there is one) instead of internal storage
    int port = DEFAULT_PORT;

    private final File file;

    private State(File file) { this.file = file; }

    static State load(Context c) {
        State s = new State(new File(c.getFilesDir(), "state.properties"));
        Properties p = new Properties();
        try (FileInputStream in = new FileInputStream(s.file)) {
            p.load(in);
        } catch (IOException ignored) {
            return s; // no file yet: everything off
        }
        s.on = "1".equals(p.getProperty("on"));
        s.boot = "1".equals(p.getProperty("boot"));
        s.external = "1".equals(p.getProperty("external"));
        try {
            int port = Integer.parseInt(p.getProperty("port", String.valueOf(DEFAULT_PORT)));
            s.port = port >= 1024 && port <= 65535 ? port : DEFAULT_PORT;
        } catch (NumberFormatException e) {
            s.port = DEFAULT_PORT;
        }
        return s;
    }

    void save() {
        Properties p = new Properties();
        p.setProperty("on", on ? "1" : "0");
        p.setProperty("boot", boot ? "1" : "0");
        p.setProperty("external", external ? "1" : "0");
        p.setProperty("port", String.valueOf(port));
        File tmp = new File(file.getPath() + ".new");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            p.store(out, null);
            out.getFD().sync();
        } catch (IOException e) {
            return;
        }
        // noinspection ResultOfMethodCallIgnored
        tmp.renameTo(file); // atomic on the same filesystem
    }

    /** Where the store lives. */
    String storeDir(Context c) {
        File base = external ? c.getExternalFilesDir(null) : null;
        return new File(base != null ? base : c.getFilesDir(), "tierfs-store").getAbsolutePath();
    }

    /** Where the store's lock file lives: always internal storage, because shared storage cannot lock files. */
    String lockDir(Context c) { return new File(c.getFilesDir(), "tierfs-lock").getAbsolutePath(); }
}
