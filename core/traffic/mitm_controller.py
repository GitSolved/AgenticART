"""
MITM Controller for Android Traffic Interception

Manages mitmproxy for intercepting Android application traffic.
Supports:
- Proxy server management (start/stop/status)
- Device proxy configuration via ADB
- CA certificate installation (user/system)
- Certificate pinning bypass via Frida/objection
- Traffic capture and flow logging

Reference: agent/prompts/mitm_setup.md
"""

import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MitmStatus(Enum):
    """Proxy server status."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ERROR = "error"


@dataclass
class MitmConfig:
    """mitmproxy configuration."""
    # Proxy settings
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    web_port: int = 8081  # mitmweb interface

    # Device settings
    device_ip: str = "192.168.56.101"
    adb_port: int = 5555

    # Certificate settings
    cert_path: str = "~/.mitmproxy/mitmproxy-ca-cert.pem"
    install_as_system: bool = False  # Requires root

    # Capture settings
    save_flows: bool = True
    flow_file: str = "output/traffic/flows.mitm"

    # Pinning bypass
    use_frida: bool = False
    frida_script: Optional[str] = None
    target_package: Optional[str] = None

    def __post_init__(self):
        self.cert_path = os.path.expanduser(self.cert_path)


@dataclass
class CapturedFlow:
    """Represents a captured HTTP(S) flow."""
    timestamp: str
    method: str
    url: str
    status_code: int
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    request_body: Optional[str] = None
    response_body: Optional[str] = None


class MitmController:
    """
    Controller for mitmproxy traffic interception.

    Usage:
        controller = MitmController(config)
        controller.start()
        controller.configure_device_proxy()
        controller.install_ca_certificate()
        # ... capture traffic ...
        controller.stop()
    """

    def __init__(self, config: Optional[MitmConfig] = None):
        self.config = config or MitmConfig()
        self.status = MitmStatus.STOPPED
        self._process: Optional[subprocess.Popen] = None
        self._frida_process: Optional[subprocess.Popen] = None
        self._flows: list[CapturedFlow] = []

        # Ensure output directory exists
        flow_dir = Path(self.config.flow_file).parent
        flow_dir.mkdir(parents=True, exist_ok=True)

    @property
    def device_serial(self) -> str:
        """Get ADB device serial."""
        return f"{self.config.device_ip}:{self.config.adb_port}"

    def _run_adb(self, cmd: str, use_root: bool = False) -> tuple[bool, str]:
        """Execute ADB command on device."""
        shell_cmd = f"su -c '{cmd}'" if use_root else cmd
        full_cmd = ["adb", "-s", self.device_serial, "shell", shell_cmd]

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout.strip() or result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def check_prerequisites(self) -> dict:
        """Check if all prerequisites are met."""
        checks = {
            "mitmproxy_installed": False,
            "adb_connected": False,
            "ca_cert_exists": False,
            "frida_available": False,
            "objection_available": False,
        }

        # Check mitmproxy
        try:
            result = subprocess.run(
                ["mitmproxy", "--version"],
                capture_output=True,
                text=True
            )
            checks["mitmproxy_installed"] = result.returncode == 0
        except FileNotFoundError:
            pass

        # Check ADB connection
        success, output = self._run_adb("echo connected")
        checks["adb_connected"] = success and "connected" in output

        # Check CA certificate
        checks["ca_cert_exists"] = os.path.exists(self.config.cert_path)

        # Check Frida
        try:
            result = subprocess.run(
                ["frida", "--version"],
                capture_output=True,
                text=True
            )
            checks["frida_available"] = result.returncode == 0
        except FileNotFoundError:
            pass

        # Check objection
        try:
            result = subprocess.run(
                ["objection", "version"],
                capture_output=True,
                text=True
            )
            checks["objection_available"] = result.returncode == 0
        except FileNotFoundError:
            pass

        return checks

    def start(self, mode: str = "mitmdump") -> bool:
        """
        Start mitmproxy server.

        Args:
            mode: "mitmdump" (CLI), "mitmproxy" (TUI), or "mitmweb" (Web UI)

        Returns:
            True if started successfully
        """
        if self.status == MitmStatus.RUNNING:
            logger.warning("Proxy already running")
            return True

        self.status = MitmStatus.STARTING

        # Build command
        cmd = [mode, "-p", str(self.config.listen_port)]

        if mode == "mitmweb":
            cmd.extend(["--web-port", str(self.config.web_port)])

        if self.config.save_flows:
            cmd.extend(["-w", self.config.flow_file])

        # Add upstream mode for transparent proxying if needed
        cmd.extend(["--listen-host", self.config.listen_host])

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait a moment and check if it started
            time.sleep(2)

            if self._process.poll() is None:
                self.status = MitmStatus.RUNNING
                logger.info(f"mitmproxy started on port {self.config.listen_port}")
                return True
            else:
                stderr = self._process.stderr.read().decode() if self._process.stderr else ""
                self.status = MitmStatus.ERROR
                logger.error(f"mitmproxy failed to start: {stderr}")
                return False

        except Exception as e:
            self.status = MitmStatus.ERROR
            logger.error(f"Failed to start mitmproxy: {e}")
            return False

    def stop(self) -> bool:
        """Stop mitmproxy server."""
        if self._process:
            try:
                self._process.send_signal(signal.SIGTERM)
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

        if self._frida_process:
            try:
                self._frida_process.send_signal(signal.SIGTERM)
                self._frida_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._frida_process.kill()
            self._frida_process = None

        self.status = MitmStatus.STOPPED
        logger.info("mitmproxy stopped")
        return True

    def configure_device_proxy(self) -> tuple[bool, str]:
        """Configure Android device to use proxy."""
        # Get host IP that device can reach
        host_ip = self._get_host_ip()

        commands = [
            f"settings put global http_proxy {host_ip}:{self.config.listen_port}",
        ]

        results = []
        for cmd in commands:
            success, output = self._run_adb(cmd)
            results.append(f"{cmd}: {'OK' if success else output}")

        # Verify proxy is set
        success, proxy = self._run_adb("settings get global http_proxy")

        if success and str(self.config.listen_port) in proxy:
            return True, f"Proxy configured: {proxy}"
        else:
            return False, f"Proxy configuration failed: {proxy}"

    def clear_device_proxy(self) -> tuple[bool, str]:
        """Remove proxy configuration from device."""
        success, output = self._run_adb("settings put global http_proxy :0")

        if success:
            return True, "Proxy cleared"
        else:
            return False, f"Failed to clear proxy: {output}"

    def install_ca_certificate(self, as_system: bool = False) -> tuple[bool, str]:
        """
        Install mitmproxy CA certificate on device.

        Args:
            as_system: Install as system cert (requires root, survives app checks)
        """
        if not os.path.exists(self.config.cert_path):
            return False, f"CA cert not found: {self.config.cert_path}"

        # Push cert to device
        push_cmd = [
            "adb", "-s", self.device_serial,
            "push", self.config.cert_path, "/data/local/tmp/mitmproxy-ca.pem"
        ]

        try:
            result = subprocess.run(push_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, f"Failed to push cert: {result.stderr}"
        except Exception as e:
            return False, str(e)

        if as_system:
            # Install as system certificate (requires root)
            # Convert to correct format and install
            commands = [
                # Get cert hash for filename
                "HASH=$(openssl x509 -inform PEM -subject_hash_old -in /data/local/tmp/mitmproxy-ca.pem | head -1)",
                # Remount system
                "mount -o rw,remount /system",
                # Copy with correct name
                "cp /data/local/tmp/mitmproxy-ca.pem /system/etc/security/cacerts/$HASH.0",
                "chmod 644 /system/etc/security/cacerts/$HASH.0",
                # Remount read-only
                "mount -o ro,remount /system",
            ]

            for cmd in commands:
                success, output = self._run_adb(cmd, use_root=True)
                if not success:
                    return False, f"System cert install failed: {output}"

            return True, "CA cert installed as system certificate (reboot may be required)"
        else:
            # User certificate - guide user through manual install
            return True, (
                "CA cert pushed to /data/local/tmp/mitmproxy-ca.pem\n"
                "To install: Settings > Security > Install from storage\n"
                "Or use: adb shell am start -a android.settings.SECURITY_SETTINGS"
            )

    def start_pinning_bypass(self, package: str, method: str = "objection") -> tuple[bool, str]:
        """
        Start certificate pinning bypass for target app.

        Args:
            package: Target app package name
            method: "objection" or "frida"
        """
        if method == "objection":
            cmd = [
                "objection", "-g", package,
                "explore", "--startup-command",
                "android sslpinning disable"
            ]
        else:
            # Use Frida with universal pinning bypass script
            script = self.config.frida_script or self._get_default_frida_script()
            cmd = ["frida", "-U", "-f", package, "-l", script, "--no-pause"]

        try:
            self._frida_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            time.sleep(3)

            if self._frida_process.poll() is None:
                return True, f"Pinning bypass active for {package}"
            else:
                stderr = self._frida_process.stderr.read().decode() if self._frida_process.stderr else ""
                return False, f"Pinning bypass failed: {stderr}"

        except FileNotFoundError:
            return False, f"{method} not found. Install with: pip install {method}"
        except Exception as e:
            return False, str(e)

    def stop_pinning_bypass(self) -> bool:
        """Stop certificate pinning bypass."""
        if self._frida_process:
            try:
                self._frida_process.send_signal(signal.SIGTERM)
                self._frida_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._frida_process.kill()
            self._frida_process = None
            return True
        return False

    def get_captured_flows(self, limit: int = 50) -> list[dict]:
        """
        Get recently captured HTTP flows.

        Note: This reads from the flow file if available.
        For real-time streaming, use mitmproxy's API.
        """
        flows = []

        if os.path.exists(self.config.flow_file):
            try:
                # Use mitmdump to read flows
                cmd = [
                    "mitmdump", "-n", "-r", self.config.flow_file,
                    "--set", "flow_detail=1"
                ]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                # Parse output (simplified)
                for line in result.stdout.split('\n')[-limit:]:
                    if line.strip():
                        flows.append({"raw": line})

            except Exception as e:
                logger.error(f"Error reading flows: {e}")

        return flows

    def _get_host_ip(self) -> str:
        """Get host IP address that device can reach."""
        # For Genymotion, host is typically at 10.0.3.2 or via vboxnet
        # Try to detect automatically
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.config.device_ip, 1))
            host_ip = s.getsockname()[0]
            s.close()
            return host_ip
        except Exception:
            # Fallback to common Genymotion host IP
            return "10.0.3.2"

    def _get_default_frida_script(self) -> str:
        """Get path to default SSL pinning bypass script."""
        script_path = Path(__file__).parent / "scripts" / "ssl_pinning_bypass.js"

        if not script_path.exists():
            # Create default script
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text(DEFAULT_FRIDA_SCRIPT)

        return str(script_path)

    def get_status_info(self) -> dict:
        """Get current controller status."""
        return {
            "status": self.status.value,
            "proxy_port": self.config.listen_port,
            "device": self.device_serial,
            "flows_captured": len(self._flows),
            "flow_file": self.config.flow_file,
            "pinning_bypass_active": self._frida_process is not None,
        }


# Default Frida SSL pinning bypass script
DEFAULT_FRIDA_SCRIPT = '''
/*
 * Universal SSL Pinning Bypass for Android
 * Disables certificate validation in common frameworks
 */

Java.perform(function() {
    console.log("[*] Starting SSL Pinning Bypass");

    // TrustManager bypass
    try {
        var TrustManager = Java.registerClass({
            name: 'com.mitm.TrustManager',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        );

        SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
            console.log("[+] Bypassing TrustManager");
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
    } catch(e) {
        console.log("[-] TrustManager bypass failed: " + e);
    }

    // OkHttp CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp pinning bypassed for: " + hostname);
            return;
        };
    } catch(e) {
        console.log("[-] OkHttp bypass not applicable");
    }

    console.log("[*] SSL Pinning Bypass Active");
});
'''
