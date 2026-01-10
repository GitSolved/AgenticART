package com.example.alpha;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class PaymentServiceActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // VULNERABILITY: This Activity is exported="true" in the Manifest
        // but performs a sensitive action immediately upon launch.
        Log.d("TargetAlpha", "PaymentServiceActivity Launched!");
        processPayment();
    }

    private void processPayment() {
        Log.d("TargetAlpha", "CRITICAL: Payment Processed via Exported Component.");
    }
}
