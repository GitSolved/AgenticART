#!/usr/bin/env python3
"""
Quick Scan Script

Run a vulnerability scan against a connected Android device.
Usage: python scripts/run-scan.py [--ip IP] [--port PORT] [--output FILE]
"""

import argparse
import json
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.reconnaissance import ADBConnection, DeviceEnumerator, ServiceDiscovery
from core.scanning import CVEMatcher, VulnerabilityScanner


def main():
    parser = argparse.ArgumentParser(description="Run Android vulnerability scan")
    parser.add_argument("--ip", default="192.168.56.101", help="Device IP address")
    parser.add_argument("--port", default="5555", help="ADB port")
    parser.add_argument("--output", help="Output file for JSON report")
    parser.add_argument("--quick", action="store_true", help="Quick scan (skip app analysis)")
    args = parser.parse_args()

    device_id = f"{args.ip}:{args.port}"
    print(f"\n{'='*60}")
    print("LLM-AndroidPentest Quick Scan")
    print(f"Target: {device_id}")
    print(f"{'='*60}\n")

    # Connect
    print("[*] Connecting to device...")
    adb = ADBConnection(device_id=device_id)

    if not adb.is_connected():
        print(f"[!] Failed to connect to {device_id}")
        print("[*] Attempting to connect...")
        os.system(f"adb connect {device_id}")

        if not adb.is_connected():
            print("[✗] Could not connect to device")
            sys.exit(1)

    print(f"[✓] Connected to {device_id}\n")

    # Device enumeration
    print("[*] Enumerating device...")
    enumerator = DeviceEnumerator(adb)
    device_info = enumerator.enumerate()

    print(f"    Model: {device_info.model}")
    print(f"    Android: {device_info.android_version} (API {device_info.api_level})")
    print(f"    Security Patch: {device_info.security_patch}")
    print(f"    SELinux: {device_info.selinux_status}")
    print(f"    Rooted: {'Yes' if device_info.is_rooted else 'No'}")
    print()

    # Service discovery
    print("[*] Discovering services...")
    service_discovery = ServiceDiscovery(adb)
    services = service_discovery.discover_network_services()

    critical_services = [s for s in services if s.risk.value == "critical"]
    if critical_services:
        print(f"    [!] Found {len(critical_services)} critical exposures:")
        for svc in critical_services:
            print(f"        - Port {svc.port}: {svc.description}")
    else:
        print("    [✓] No critical network exposures")
    print()

    # CVE matching
    print("[*] Matching CVEs...")
    cve_matcher = CVEMatcher()
    cves = cve_matcher.match_device(
        android_version=device_info.android_version,
        api_level=device_info.api_level,
        security_patch=device_info.security_patch,
    )

    if cves:
        print(f"    [!] Found {len(cves)} potential CVEs:")
        for cve in cves[:5]:
            exploit_status = "EXPLOIT" if cve.exploit_availability.value == "public_exploit" else ""
            print(f"        - {cve.cve_id} ({cve.severity}) {exploit_status}")
        if len(cves) > 5:
            print(f"        ... and {len(cves) - 5} more")
    else:
        print("    [✓] No known CVEs match this configuration")
    print()

    # Vulnerability scan
    print("[*] Running vulnerability scan...")
    scanner = VulnerabilityScanner(adb)
    scan_result = scanner.scan(include_apps=not args.quick)

    print(f"\n{scanner.generate_report(scan_result)}")

    # Output to file
    if args.output:
        report_data = {
            "device": {
                "model": device_info.model,
                "android_version": device_info.android_version,
                "api_level": device_info.api_level,
                "security_patch": device_info.security_patch,
                "rooted": device_info.is_rooted,
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "category": v.category.value,
                    "description": v.description,
                }
                for v in scan_result.vulnerabilities
            ],
            "cves": [
                {
                    "id": c.cve_id,
                    "severity": c.severity,
                    "cvss": c.cvss_score,
                    "exploit_available": c.exploit_availability.value == "public_exploit",
                }
                for c in cves
            ],
        }

        with open(args.output, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"\n[✓] Report saved to {args.output}")

    print("\n[✓] Scan complete\n")


if __name__ == "__main__":
    main()
