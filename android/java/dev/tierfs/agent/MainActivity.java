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
    private Button toggle, show, renew, addMac, macs, battery;
    private EditText portField;
    private android.widget.CheckBox bootBox, externalBox;
    private State state;
    private String dir;
    private volatile boolean running;
    private boolean loading; // (the boxes are being set from the saved choices: not a click)

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        // The pairing code lets whoever has it act as the Mac towards this device: no screenshots, no recent-apps thumbnail.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        state = State.load(this);
        dir = state.storeDir(this);

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        col.setPadding(pad, pad * 2, pad, pad);
        status = text(col, 22);
        details = text(col, 14);
        portField = new EditText(this);
        portField.setInputType(InputType.TYPE_CLASS_NUMBER);
        portField.setText(String.valueOf(state.port));
        portField.setHint("port");
        col.addView(portField);
        toggle = button(col, "Switch on", v -> toggle());
        bootBox = new android.widget.CheckBox(this);
        bootBox.setText("Switch on again when the phone starts");
        bootBox.setOnCheckedChangeListener((v, checked) -> {
            if (loading) return;
            state.boot = checked;
            state.save();
        });
        col.addView(bootBox);
        externalBox = new android.widget.CheckBox(this);
        externalBox.setText("Keep the store on shared storage (memory card)");
        externalBox.setOnCheckedChangeListener((v, checked) -> {
            if (!loading) confirmStorageChange(checked);
        });
        col.addView(externalBox);
        battery = button(col, "Allow it to run in the background", v -> askBatteryExemption());
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
        state = State.load(this);
        dir = state.storeDir(this);
        loading = true;
        bootBox.setChecked(state.boot);
        externalBox.setChecked(state.external);
        portField.setText(String.valueOf(state.port));
        loading = false;
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
            return p >= 1024 && p <= 65535 ? p : State.DEFAULT_PORT;
        } catch (NumberFormatException e) {
            return State.DEFAULT_PORT;
        }
    }

    /** Moving the store means a new, empty store: no pairing, no data. Say so, and only do it while the server is off. */
    private void confirmStorageChange(boolean external) {
        if (running || state.on) {
            loading = true;
            externalBox.setChecked(state.external);
            loading = false;
            code.setText("Switch the storage off before changing where it is kept.");
            return;
        }
        new AlertDialog.Builder(this)
            .setTitle("Keep the store somewhere else?")
            .setMessage("This starts a new, empty store at the new place: Macs have to pair with it again, and what is stored in the old place stays "
                + "there (and is not served). "
                + "Shared storage is shared with other apps and can be removed or cleaned by the system.")
            .setPositiveButton("Change",
                (d, w) -> {
                    state.external = external;
                    state.save();
                    dir = state.storeDir(this);
                    refresh();
                })
            .setNegativeButton("Cancel",
                (d, w) -> {
                    loading = true;
                    externalBox.setChecked(state.external);
                    loading = false;
                })
            .show();
    }

    /** Android may stop a background service to save battery; this asks the system to leave this app alone (the person decides). */
    @android.annotation.SuppressLint("BatteryLife")
    private void askBatteryExemption() {
        android.os.PowerManager pm = getSystemService(android.os.PowerManager.class);
        if (pm.isIgnoringBatteryOptimizations(getPackageName())) {
            code.setText("Battery optimisation is already off for this app.");
            return;
        }
        startActivity(
            new Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, android.net.Uri.parse("package:" + getPackageName())));
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
            status.setText(running ? "Storage is ON" : state.on ? "Storage should be on (starting)" : "Storage is off");
            toggle.setText(running || state.on ? "Switch off" : "Switch on");
            portField.setEnabled(!running && !state.on);
            externalBox.setEnabled(!running && !state.on);
            android.os.PowerManager pm = getSystemService(android.os.PowerManager.class);
            battery.setText(
                pm.isIgnoringBatteryOptimizations(getPackageName()) ? "Allowed to run in the background" : "Allow it to run in the background");
            StringBuilder d = new StringBuilder();
            d.append(kid.isEmpty() ? "Not paired yet: switching on creates the pairing code.\n"
                                   : count + " Mac pairing(s); the original's key id: " + kid + "\n");
            d.append("Stores encrypted chunks in:\n").append(dir).append("\n");
            File parent = new File(dir).getParentFile();
            d.append("Free: ").append(parent == null ? 0 : parent.getUsableSpace() / (1024 * 1024)).append(" MiB\n");
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
        if (running || state.on) {
            state.on = false; // the choice is saved first: if the system restarts the service meanwhile, it stays off
            state.save();
            stopService(new Intent(this, DeviceService.class));
            ui.postDelayed(this::refresh, 600);
            return;
        }
        String r = Native.pairing(dir, false); // creates the pairing secret on first use
        if (r.startsWith("ERR")) {
            status.setText(r);
            return;
        }
        state.port = port();
        state.on = true;
        state.save();
        startForegroundService(new Intent(this, DeviceService.class));
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
