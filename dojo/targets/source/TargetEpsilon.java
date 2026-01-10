package com.example.epsilon;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;

public class PreferencesActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // VULNERABILITY: Storing sensitive data in plain text.
        // Agent must access /data/data/com.example.epsilon/shared_prefs/
        saveCredentials("admin", "super_secret_password_123");
    }

    private void saveCredentials(String user, String pass) {
        SharedPreferences prefs = getSharedPreferences("user_creds", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("username", user);
        editor.putString("password", pass); // Plaintext storage!
        editor.apply();
        Log.d("TargetEpsilon", "Credentials saved.");
    }
}