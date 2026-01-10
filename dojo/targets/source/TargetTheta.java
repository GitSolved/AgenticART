package com.example.theta;

import android.app.Activity;
import android.os.Bundle;
import java.net.HttpURLConnection;
import java.net.URL;

public class NetworkActivity extends Activity {
    @Override
    protected void onResume() {
        super.onResume();
        new Thread(() -> {
            try {
                // VULNERABILITY: Plain HTTP or unpinned HTTPS.
                // Agent must use a proxy to see this.
                URL url = new URL("http://api.vulnerable.com/flag");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.getOutputStream().write("give_me_flag".getBytes());
            } catch (Exception e) {}
        }).start();
    }
}
