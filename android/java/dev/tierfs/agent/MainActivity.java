package dev.tierfs.agent;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.Socket;

/** One screen: switch the storage server on or off, see the key id and the addresses, show the pairing code (only here, never in a screenshot). */
public final class MainActivity extends Activity {
    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView status, details, code;
    private Button toggle, show, renew, addMac, macs;
    private EditText portField;
    private String dir;
    private volatile boolean running;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        // The pairing code lets whoever has it act as the Mac towards this device: no screenshots, no recent-apps thumbnail.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        // Internal storage: it can lock files (the store needs flock; the emulated "external" storage cannot) and shares the phone's free space
        // anyway.
        dir = new File(getFilesDir(), "tierfs-store").getAbsolutePath();

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        col.setPadding(pad, pad * 2, pad, pad);
        status = text(col, 22);
        details = text(col, 14);
        portField = new EditText(this);
        portField.setInputType(InputType.TYPE_CLASS_NUMBER);
        portField.setText("9100");
        portField.setHint("port");
        col.addView(portField);
        toggle = button(col, "Switch on", v -> toggle());
        show = button(col, "Show pairing code", v -> showCode());
        addMac = button(col, "Add another Mac", v -> addAnotherMac());
        macs = button(col, "Paired Macs", v -> showMacs());
        renew = button(col, "Make a new original pairing code", v -> confirmRenew());
        code = text(col, 16);
        code.setTextIsSelectable(false);
        code.setTypeface(android.graphics.Typeface.MONOSPACE);
        ScrollView sv = new ScrollView(this);
        sv.addView(col);
        setContentView(sv);
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[] {Manifest.permission.POST_NOTIFICATIONS}, 1);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    @Override
    protected void onPause() {
        super.onPause();
        code.setText(""); // the code is shown only while the screen is in front
    }

    private TextView text(LinearLayout parent, int sp) {
        TextView t = new TextView(this);
        t.setTextSize(sp);
        t.setPadding(0, 8, 0, 8);
        parent.addView(t);
        return t;
    }

    private Button button(LinearLayout parent, String label, View.OnClickListener l) {
        Button x = new Button(this);
        x.setText(label);
        x.setOnClickListener(l);
        x.setGravity(Gravity.CENTER);
        parent.addView(x);
        return x;
    }

    private int port() {
        try {
            int p = Integer.parseInt(portField.getText().toString().trim());
            return p >= 1024 && p <= 65535 ? p : 9100;
        } catch (NumberFormatException e) {
            return 9100;
        }
    }

    /** Is something listening on the server port? (The service lives in another process, so ask the network, not a flag.) */
    private void probe(Runnable then) {
        final int p = port();
        new Thread(() -> {
            boolean up;
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", p), 400);
                up = true;
            } catch (Exception e) {
                up = false;
            }
            running = up;
            ui.post(then);
        }).start();
    }

    private void refresh() {
        probe(() -> {
            String kids = Native.keyId(dir);
            int count = kids.isEmpty() ? 0 : kids.split("\n").length;
            String kid = count == 0 ? "" : kids.split("\n")[0];
            status.setText(running ? "Storage is ON" : "Storage is off");
            toggle.setText(running ? "Switch off" : "Switch on");
            portField.setEnabled(!running);
            StringBuilder d = new StringBuilder();
            d.append(kid.isEmpty() ? "Not paired yet: switching on creates the pairing code.\n"
                                   : count + " Mac pairing(s); the original's key id: " + kid + "\n");
            d.append("Stores encrypted chunks in:\n").append(dir).append("\n");
            d.append("Free: ").append(new File(dir).getParentFile().getUsableSpace() / (1024 * 1024)).append(" MiB\n");
            String addr = addresses();
            d.append(addr.isEmpty() ? "No network address (connect to Wi-Fi)." : "On this network: " + addr);
            d.append("\nOn the Mac: tierctl pair <address>:").append(port()).append(" --store keychain");
            details.setText(d.toString());
        });
    }

    private String addresses() {
        StringBuilder sb = new StringBuilder();
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        Network n = cm.getActiveNetwork();
        LinkProperties lp = n == null ? null : cm.getLinkProperties(n);
        if (lp != null)
            for (LinkAddress la : lp.getLinkAddresses())
                if (la.getAddress() instanceof Inet4Address) sb.append(sb.length() > 0 ? ", " : "").append(la.getAddress().getHostAddress());
        return sb.toString();
    }

    private void toggle() {
        if (running) {
            stopService(new Intent(this, DeviceService.class));
            ui.postDelayed(this::refresh, 600);
            return;
        }
        String r = Native.pairing(dir, false); // creates the pairing secret on first use
        if (r.startsWith("ERR")) {
            status.setText(r);
            return;
        }
        Intent i = new Intent(this, DeviceService.class).putExtra(DeviceService.EXTRA_DIR, dir).putExtra(DeviceService.EXTRA_PORT, port());
        startForegroundService(i);
        ui.postDelayed(this::refresh, 1200);
    }

    private void showCode() {
        String r = Native.pairing(dir, false);
        if (r.startsWith("ERR")) {
            code.setText(r);
            return;
        }
        String[] parts = r.split("\n");
        code.setText("Type this on the Mac:\n\n" + parts[0] + "\n\nKey id: " + parts[1]
            + "\n\nAnyone who has this code can act as the Mac towards this device.");
        refresh();
    }

    /** A pairing of its own for another Mac: it can be revoked alone, and may be allowed (or not) to delete when that Mac cleans up old versions. */
    private void addAnotherMac() {
        final EditText name = new EditText(this);
        name.setHint("Name of the Mac (for you)");
        final android.widget.CheckBox del = new android.widget.CheckBox(this);
        del.setText("May delete (lets that Mac run garbage collection here)");
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(48, 16, 48, 0);
        box.addView(name);
        box.addView(del);
        new AlertDialog.Builder(this)
            .setTitle("Add another Mac")
            .setView(box)
            .setPositiveButton("Make a pairing code",
                (d, w) -> {
                    String r = Native.addPairing(dir, name.getText().toString().trim(), del.isChecked());
                    if (r.startsWith("ERR")) {
                        code.setText(r);
                        return;
                    }
                    String[] parts = r.split("\n");
                    code.setText("Type this on the Mac called " + name.getText().toString().trim() + ":\n\n" + parts[0] + "\n\nKey id: " + parts[1]
                        + ("\n\nAnyone who has this code can act as that Mac towards this device. If the server is on, switch it off and on once so "
                            + "the Mac can find it by name."));
                    refresh();
                })
            .setNegativeButton("Cancel", null)
            .show();
    }

    /** Every pairing, and a way to revoke one: the Mac is refused at once, the others carry on. */
    private void showMacs() {
        final String[] lines = Native.listPairings(dir).trim().isEmpty() ? new String[0] : Native.listPairings(dir).trim().split("\n");
        if (lines.length == 0) {
            code.setText("No Mac is paired yet.");
            return;
        }
        final String[] items = new String[lines.length];
        final String[] ids = new String[lines.length];
        for (int i = 0; i < lines.length; i++) {
            String[] f = lines[i].split("\t");
            ids[i] = f[0];
            items[i] = f[0].equals("PROBLEM") ? "Problem: " + (f.length > 1 ? f[1] : "")
                                              : f[1] + (f.length > 2 && f[2].equals("delete") ? " (may delete)" : "") + "\n" + f[0];
        }
        new AlertDialog.Builder(this)
            .setTitle("Paired Macs (tap one to revoke it)")
            .setItems(items,
                (d, which) -> {
                    if (ids[which].equals("PROBLEM")) return;
                    new AlertDialog.Builder(this)
                        .setTitle("Revoke this Mac?")
                        .setMessage(
                            items[which] + "\n\nIt can no longer reach this phone. Its files are not touched; it can pair again with a new code.")
                        .setPositiveButton("Revoke",
                            (d2, w2) -> {
                                String err = Native.revokePairing(dir, ids[which]);
                                code.setText(err.isEmpty() ? "Revoked." : "Could not revoke: " + err);
                                refresh();
                            })
                        .setNegativeButton("Cancel", null)
                        .show();
                })
            .setNegativeButton("Close", null)
            .show();
    }

    private void confirmRenew() {
        new AlertDialog.Builder(this)
            .setTitle("Make a new pairing code?")
            .setMessage("Every Mac paired with this phone will have to pair again. Do this only if the code may have leaked.")
            .setPositiveButton("Make a new code",
                (d, w) -> {
                    if (running) stopService(new Intent(this, DeviceService.class));
                    code.setText(
                        Native.pairing(dir, true).startsWith("ERR") ? "Could not make a new code." : "A new code was made. Switch on, then show it.");
                    ui.postDelayed(this::refresh, 600);
                })
            .setNegativeButton("Cancel", null)
            .show();
    }
}
