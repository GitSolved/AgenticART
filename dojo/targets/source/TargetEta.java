package com.example.eta;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class VaultActivity extends Activity {
    private String secretPin = "998877"; 

    public boolean checkPin(String input) {
        // VULNERABILITY: The agent can hook this method to read 'input' 
        // or to spy on 'secretPin' if they hook the string comparison.
        return input.equals(secretPin);
    }
}
