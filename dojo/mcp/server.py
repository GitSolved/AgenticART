#!/usr/bin/env python3
"""
MCP Server for Android Security Tooling.
Provides a hybrid interface: High-level structured tools + raw ADB shell.
"""

import logging
import subprocess
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("android-mcp")

mcp = FastMCP("android-security")

@mcp.tool()
def get_package_info(package_name: str) -> str:
    """
    Returns parsed permissions, activities, and services for a specific Android package.
    Use this for initial reconnaissance of a target application.
    """
    logger.info(f"Getting info for package: {package_name}")
    try:
        # We use dumpsys package to get detailed information
        result = subprocess.run(
            ["adb", "shell", "dumpsys", "package", package_name],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return f"Error: {result.stderr}"

        # Simple extraction logic to keep output manageable
        lines = result.stdout.splitlines()
        extracted = []
        capture = False
        target_sections = [
            "requested permissions:",
            "install permissions:",
            "runtime permissions:",
            "Activities:",
            "Services:",
            "Receivers:",
            "ContentProviders:"
        ]

        for line in lines:
            line_strip = line.strip()
            if any(section in line for section in target_sections):
                capture = True
                extracted.append(line)
                continue
            if capture:
                # Sections end when indentation returns to base level
                if line.startswith("    ") or line.startswith("\t") or not line_strip:
                    if line_strip:
                        extracted.append(line)
                else:
                    capture = False

        return "\n".join(extracted) if extracted else "Package found but no detailed info extracted. Try adb_shell for raw dump."
    except Exception as e:
        return f"Exception occurred: {str(e)}"

@mcp.tool()
def pull_file(remote_path: str, local_path: str) -> str:
    """
    Safely extracts artifacts (e.g., databases, preferences, APKs) from the Android device.
    Ensure you have appropriate permissions on the device first.
    """
    logger.info(f"Pulling file from {remote_path} to {local_path}")
    try:
        result = subprocess.run(
            ["adb", "pull", remote_path, local_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return f"Error: {result.stderr}"
        return f"Successfully pulled {remote_path} to {local_path}"
    except Exception as e:
        return f"Exception occurred: {str(e)}"

@mcp.tool()
def install_apk(apk_path: str) -> str:
    """
    Installs an APK file onto the connected Android device.
    """
    logger.info(f"Installing APK: {apk_path}")
    try:
        result = subprocess.run(
            ["adb", "install", "-r", apk_path],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            return f"Error: {result.stderr}"
        return f"Successfully installed {apk_path}"
    except Exception as e:
        return f"Exception occurred: {str(e)}"

@mcp.tool()
def scan_logcat(log_filter: str, count: int = 100) -> str:
    """
    Returns recent matching logs from logcat using a specific filter or tag.
    Default count is 100 lines.
    """
    logger.info(f"Scanning logcat with filter: {log_filter}")
    try:
        result = subprocess.run(
            ["adb", "logcat", "-d", "-t", str(count), log_filter],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return f"Error: {result.stderr}"
        return result.stdout
    except Exception as e:
        return f"Exception occurred: {str(e)}"

@mcp.tool()
def adb_shell(command: str) -> Dict[str, Any]:
    """
    The 'Escape Hatch': Executes raw shell commands on the Android device.
    Returns a JSON object with exit_code, stdout, and stderr.
    Use this for creative exploitation or when high-level tools are insufficient.
    """
    logger.info(f"Executing raw shell command: {command}")
    try:
        result = subprocess.run(
            ["adb", "shell", command],
            capture_output=True, text=True, timeout=60
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Exception occurred: {str(e)}"
        }

if __name__ == "__main__":
    mcp.run()
