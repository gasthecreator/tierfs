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
    static final String EXTRA_DIR = "dir", EXTRA_PORT = "port";
    private static final String TAG = "tierfs-agent", CHANNEL = "device", SERVICE_TYPE = "_tierfs._tcp.";
    private PowerManager.WakeLock wake;
    private NsdManager nsd;
    private NsdManager.RegistrationListener registration;
    private Thread server;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || server != null) return START_NOT_STICKY;   // not restarted by the system: the person switches it on
        final String dir = intent.getStringExtra(EXTRA_DIR);
        final int port = intent.getIntExtra(EXTRA_PORT, 9100);
        String keyId = Native.keyId(dir);
        if (dir == null || keyId.isEmpty()) {   // never serve an unpaired store on the network
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
            int rc = Native.serve(dir, port, "0.0.0.0");   // only returns if it could not start
            Log.e(TAG, "the device server stopped (exit code " + rc + ")");
            stopSelf();
        }, "tierfs-device");
        server.start();
        announce(port, keyId);
        return START_NOT_STICKY;
    }

    /** Announces the device on the local network. Only a locator: a Mac still has to prove it holds the pairing secret (ADR-0013). */
    private void announce(int port, String keyId) {
        NsdServiceInfo info = new NsdServiceInfo();
        String name = ("tierfs-" + android.os.Build.MODEL).replaceAll("[^A-Za-z0-9._ -]", "-");
        info.setServiceName(name.length() > 63 ? name.substring(0, 63) : name);
        info.setServiceType(SERVICE_TYPE);
        info.setPort(port);
        info.setAttribute("v", "1");        // the record format of core/discovery.hpp
        info.setAttribute("auth", "1");     // this device only speaks the authenticated channel
        info.setAttribute("kid", keyId);
        nsd = (NsdManager) getSystemService(Context.NSD_SERVICE);
        registration = new NsdManager.RegistrationListener() {
            @Override public void onServiceRegistered(NsdServiceInfo i) { Log.i(TAG, "announced as " + i.getServiceName()); }
            @Override public void onRegistrationFailed(NsdServiceInfo i, int code) { Log.w(TAG, "could not announce on the network (" + code + "); Macs need the address"); }
            @Override public void onServiceUnregistered(NsdServiceInfo i) {}
            @Override public void onUnregistrationFailed(NsdServiceInfo i, int code) {}
        };
        try {
            nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, registration);
        } catch (RuntimeException e) {
            Log.w(TAG, "could not announce on the network: " + e);
        }
    }

    @Override
    public void onDestroy() {
        try {
            if (nsd != null && registration != null) nsd.unregisterService(registration);
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
