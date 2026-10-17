package dev.tierfs.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Starts the storage server again when the phone starts (or the app was updated), but only if the person switched it on and asked for that. */
public final class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String a = intent == null ? null : intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(a) && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(a)) return;
        State s = State.load(context);
        if (s.on && s.boot) context.startForegroundService(new Intent(context, DeviceService.class));
    }
}
