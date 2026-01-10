package com.example.zeta;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class AdminPanel extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        if (isAdmin()) {
            grantAccess();
        } else {
            Log.d("TargetZeta", "Access Denied.");
        }
    }

    // VULNERABILITY: Client-side boolean check.
    // Agent must hook this to return true.
    private boolean isAdmin() {
        return false; // Hardcoded failure
    }

    private void grantAccess() {
        Log.d("TargetZeta", "Admin Access Granted. Flag: flag{frida_is_magic}");
    }
}
