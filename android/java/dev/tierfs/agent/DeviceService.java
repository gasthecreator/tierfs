package dev.tierfs.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

/**
 * Keeps the device server running while the person has it switched on. Runs in the ":device" process: the native server never returns, so stopping
 * means ending that process. A paired device is required (the server itself refuses to listen on the network otherwise).
 */
public final class DeviceService extends Service {
    private static final String TAG = "tierfs-agent", CHANNEL = "device", SERVICE_TYPE = "_tierfs._tcp.";
    private PowerManager.WakeLock wake;
    private NsdManager nsd;
    private final java.util.List<NsdManager.RegistrationListener> registrations = new java.util.ArrayList<>();
    private Thread server;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (server != null) return START_STICKY;
        // What to do comes from the person's saved choices, not from the intent: the system also calls this with no intent when it restarts the service
        // after killing it, and then the server must come back exactly as it was (or stay off, if the person has switched it off since).
        State state = State.load(this);
        if (!state.on) {
            stopSelf();
            return START_NOT_STICKY;
        }
        final String dir = state.storeDir(this), lockDir = state.external ? state.lockDir(this) : "";
        final int port = state.port;
        String keyIds = Native.keyId(dir);
        if (keyIds.isEmpty()) { // never serve an unpaired store on the network
            Log.e(TAG, "refusing to start: the store is not paired");
            stopSelf();
            return START_NOT_STICKY;
        }
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Storage server", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, CHANNEL)
                             .setContentTitle("tierfs storage is on")
                             .setContentText("Serving on port " + port + " for the Macs paired with this phone")
                             .setSmallIcon(android.R.drawable.stat_sys_upload)
                             .setContentIntent(open)
                             .setOngoing(true)
                             .build();
        startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        PowerManager pm = getSystemService(PowerManager.class);
        wake = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "tierfs:device");
        wake.acquire();
        server = new Thread(() -> {
            int rc = Native.serve(dir, port, "0.0.0.0", lockDir); // only returns if it could not start
            Log.e(TAG, "the device server stopped (exit code " + rc + ")");
            stopSelf();
        }, "tierfs-device");
        server.start();
        announce(port, dir);
        return START_STICKY; // if the system kills the process, it starts the service again
    }

    /**
     * Announces the device on the local network, once per pairing (each with its own key id, so each Mac finds the device by the key id it holds).
     * Only a locator: a Mac still has to prove it holds the pairing secret (ADR-0013). A pairing added while the server runs is announced after the
     * next start.
     */
    private void announce(int port, String dir) {
        nsd = (NsdManager) getSystemService(Context.NSD_SERVICE);
        boolean first = true;
        for (String line : Native.listPairings(dir).split("\n")) {
            String[] f = line.split("\t");
            if (f.length < 3 || f[0].equals("PROBLEM")) continue;
            String base = ("tierfs-" + android.os.Build.MODEL).replaceAll("[^A-Za-z0-9._ -]", "-");
            String name = first ? base : base + " (" + f[1].replaceAll("[^A-Za-z0-9._ -]", "-") + ")";
            first = false;
            NsdServiceInfo info = new NsdServiceInfo();
            info.setServiceName(name.length() > 63 ? name.substring(0, 63) : name);
            info.setServiceType(SERVICE_TYPE);
            info.setPort(port);
            info.setAttribute("v", "1"); // the record format of core/discovery.hpp
            info.setAttribute("auth", "1"); // this device only speaks the authenticated channel
            info.setAttribute("kid", f[0]);
            NsdManager.RegistrationListener l = new NsdManager.RegistrationListener() {
                @Override
                public void onServiceRegistered(NsdServiceInfo i) {
                    Log.i(TAG, "announced as " + i.getServiceName());
                }
                @Override
                public void onRegistrationFailed(NsdServiceInfo i, int code) {
                    Log.w(TAG, "could not announce on the network (" + code + "); Macs need the address");
                }
                @Override
                public void onServiceUnregistered(NsdServiceInfo i) {}
                @Override
                public void onUnregistrationFailed(NsdServiceInfo i, int code) {}
            };
            try {
                nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, l);
                registrations.add(l);
            } catch (RuntimeException e) {
                Log.w(TAG, "could not announce on the network: " + e);
            }
        }
    }

    @Override
    public void onDestroy() {
        try {
            if (nsd != null)
                for (NsdManager.RegistrationListener l : registrations) nsd.unregisterService(l);
        } catch (RuntimeException ignored) {
        }
        if (wake != null && wake.isHeld()) wake.release();
        // The native server cannot be asked to return: end the process. Every acknowledgement it gave was already durable.
        android.os.Process.killProcess(android.os.Process.myPid());
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
