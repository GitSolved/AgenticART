# Yellow Belt Curriculum: "Dynamic Analysis & Instrumentation"

**Core Philosophy**: *Runtime Reality*. Static analysis shows what the code *says*; Dynamic analysis shows what it *does*. Yellow Belt focuses on **Instrumentation** (Frida) and **Interception** (Network).

***

## Competency Framework (Unit 2)

### Terminal Competency
The LM must demonstrate ability to:
1.  **Instrument** a running process using Frida to modify control flow.
2.  **Intercept** and modify arguments to functions at runtime.
3.  **Inspect** network traffic by placing itself in the stream (MITM).
4.  **Bypass** client-side trust mechanisms (Pinning, Root Detection).

### Mastery Threshold
-   **Zero "Script Kiddie" errors** (running scripts without checking target class names).
-   **100% success** in identifying the correct method signature to hook.

***

## Challenge Architecture

### Ch7: The Invisible Hand (Frida Basics)
**Goal**: Hook a boolean return value to bypass a check.
*   **Target**: `TargetZeta`
*   **Micro-Task**: Locate `isAdmin()` and force it to return `true`.
*   **Schema**:
    ```json
    {
      "command": "frida -U -f com.example.zeta -l script.js",
      "script_content": "Java.perform(() => { Class.use('...').isAdmin.implementation = () => true; });",
      "verification": "App displays 'Admin Access Granted'"
    }
    ```

### Ch8: The Locked Vault (Argument Modification)
**Goal**: Hook a method to brute-force or steal arguments.
*   **Target**: `TargetEta`
*   **Micro-Task**: Hook `checkPin(String pin)` and print the correct PIN when it's compared internally.
*   **Schema**:
    ```json
    {
      "command": "frida -U -f com.example.eta -l logger.js",
      "script_content": "overload('java.lang.String').implementation = function(a) { console.log('PIN:', a); return this.checkPin(a); }",
      "evidence_type": "Argument Leak"
    }
    ```

### Ch9: The Secret Messenger (Traffic Interception)
**Goal**: Intercept HTTP traffic using a Proxy.
*   **Target**: `TargetTheta`
*   **Micro-Task**: Configure device proxy + install cert + capture flag.
*   **Schema**:
    ```json
    {
      "command": "mitmproxy",
      "captured_request": "POST /api/flag",
      "captured_data": "flag{network_intercepted}"
    }
    ```

### Ch10: The Stubborn Guard (SSL Pinning)
**Goal**: Bypass Certificate Pinning.
*   **Target**: `TargetIota`
*   **Micro-Task**: Use `objection` or a custom script to disable `TrustManager` checks.
*   **Schema**:
    ```json
    {
      "command": "objection explore --startup-command 'android sslpinning disable'",
      "verification": "Traffic visible in proxy"
    }
    ```

### Ch11: The Native Wall (Native Hooks)
**Goal**: Hook a JNI function in a `.so` library.
*   **Target**: `TargetKappa`
*   **Micro-Task**: Use `Interceptor.attach` on a native symbol.
*   **Schema**:
    ```json
    {
      "command": "frida -U -f com.example.kappa -l native.js",
      "script_content": "Interceptor.attach(Module.getExportByName('libnative.so', 'check_license'), ...)",
      "evidence_type": "Native Bypass"
    }
    ```
