package com.example.beta;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;
import java.util.Timer;
import java.util.TimerTask;

public class SystemHealthService extends Service {
    private Timer timer = new Timer();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // VULNERABILITY: Emits identifiable logs from a generic-looking process.
        // Agent must map PID -> UID -> Package Name.
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                Log.d("SystemHealth", "System Healthy check completed. Status: OK");
            }
        }, 0, 5000); // Logs every 5 seconds
        
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
