package com.example.gamma;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    private boolean isAuthenticated = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // SECURITY CHECK: Only runs once when app is first created
        Log.d("TargetGamma", "onCreate: Checking PIN...");
        showPinScreen(); 
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        
        // VULNERABILITY: Developer forgot to check PIN here!
        // This method runs when app is re-opened with a new intent.
        Log.d("TargetGamma", "onNewIntent: Processing command...");
        
        if (intent.hasExtra("action")) {
            String action = intent.getStringExtra("action");
            if (action.equals("bypass")) {
                sensitiveOperation();
            }
        }
    }

    private void showPinScreen() {
        // Simulates a blocking PIN dialog
        if (!isAuthenticated) {
            Log.d("TargetGamma", "PIN Screen Shown. Access Denied.");
            finish(); // Kills the activity if not authenticated
        }
    }

    private void sensitiveOperation() {
        Log.d("TargetGamma", "Bypass Successful. Secret Data Accessed.");
    }
}
