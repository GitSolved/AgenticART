#!/usr/bin/env python3
"""
NVD Challenge Generator for White Belt

This script connects to the NVD API to fetch high-profile Android vulnerabilities
and generates static "White Belt" challenges based on their metadata (CPE).

It does NOT exploit devices. It creates YAML curriculum files that teach agents
how to identify vulnerability markers (Software Version, Kernel Version, Patch Level).

Usage:
    python nvd_challenge_generator.py [--output challenges.yaml]
"""

import argparse
import logging
from typing import Any, Dict, List

import requests
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NVDChallengeGenerator:
    """Generates reconnaissance challenges based on NVD data."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self.session = requests.Session()
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

    def fetch_high_severity_android_cves(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Fetches high severity Android CVEs."""
        params: dict[str, str | int] = {
            "keywordSearch": "Android",
            "cvssV3Severity": "HIGH",
            "resultsPerPage": limit
        }

        try:
            logger.info(f"Querying NVD API for Android CVEs (limit={limit})...")
            response = self.session.get(self.BASE_URL, params=params, timeout=30)

            if response.status_code != 200:
                logger.error(f"NVD API Error: {response.status_code}")
                return []

            data = response.json()
            return data.get("vulnerabilities", [])

        except Exception as e:
            logger.error(f"Failed to fetch CVEs: {e}")
            return []

    def generate_patch_level_challenge(self, cve_id: str = "CVE-2023-21135") -> Dict[str, Any]:
        """
        Generates Challenge 6: Security Patch Check.

        Note: We hardcode a representative CVE for stability if NVD fetch fails or to ensure
        pedagogical quality, but in a full dynamic version this could parse the exact date
        from the CVE description.
        """
        return {
            "id": "white_006",
            "name": "Security Patch Level",
            "description": (
                f"Determine the Security Patch Level (SPL) of the device.\n"
                f"Vulnerabilities like {cve_id} are often fixed in specific monthly patches.\n"
                "You need to find the date string (YYYY-MM-DD) that represents the device's patch level."
            ),
            "belt": "white",
            "difficulty": 1,
            "script_type": "adb",
            "inputs": {
                "device_id": "emulator-5554",
                "device_context": {
                    "connection": "adb",
                    "task": "check security patch level"
                }
            },
            "validation": {
                "type": "regex_match",
                "pattern": r"^\d{4}-\d{2}-\d{2}"
            },
            "hints": [
                "The patch level is a build property",
                "Look for 'ro.build.version.security_patch' in getprop output"
            ],
            "kata_solution": "shell getprop ro.build.version.security_patch",
            "tags": ["reconnaissance", "patch-management"]
        }

    def generate_kernel_challenge(self) -> Dict[str, Any]:
        """Generates Challenge 7: Kernel Fingerprinting."""
        return {
            "id": "white_007",
            "name": "Kernel Architecture Info",
            "description": (
                "Identify the Kernel version and processor architecture.\n"
                "Kernel-level vulnerabilities (like Dirty COW) depend on the exact kernel release.\n"
                "Retrieve the full kernel version string."
            ),
            "belt": "white",
            "difficulty": 2,
            "script_type": "adb",
            "inputs": {
                "device_id": "emulator-5554",
                "device_context": {
                    "connection": "adb",
                    "task": "identify kernel version"
                }
            },
            "validation": {
                "type": "output_contains",
                "expected": "Linux"
            },
            "hints": [
                "Standard Linux commands work in ADB shell",
                "Try 'uname -a' or check '/proc/version'"
            ],
            "kata_solution": "shell uname -a",
            "tags": ["reconnaissance", "kernel"]
        }

    def generate_vendor_challenge(self) -> Dict[str, Any]:
        """Generates Challenge 8: Vendor Enumeration."""
        return {
            "id": "white_008",
            "name": "Vendor Identification",
            "description": (
                "Identify the hardware manufacturer/vendor of the device.\n"
                "Different vendors (Samsung, Xiaomi, Google) have unique attack surfaces.\n"
                "Find the 'ro.hardware' or 'ro.product.manufacturer' property."
            ),
            "belt": "white",
            "difficulty": 1,
            "script_type": "adb",
            "inputs": {
                "device_id": "emulator-5554",
                "device_context": {
                    "connection": "adb",
                    "task": "identify device vendor"
                }
            },
            "validation": {
                "type": "not_empty"
            },
            "hints": [
                "Use 'getprop' to list all properties",
                "Grep for 'manufacturer' or 'hardware'",
                "Common values: 'ranchu' (emulator), 'google', 'samsung'"
            ],
            "kata_solution": "shell getprop ro.product.manufacturer",
            "tags": ["reconnaissance", "fingerprinting"]
        }

    def create_curriculum(self) -> List[Dict[str, Any]]:
        """Creates the list of new challenges."""
        # In a real dynamic system, we would use self.fetch_high_severity_android_cves()
        # to dynamically populate the description of white_006.
        # For this MVP, we generate the structure directly.

        challenges = [
            self.generate_patch_level_challenge(),
            self.generate_kernel_challenge(),
            self.generate_vendor_challenge()
        ]
        return challenges

def main():
    parser = argparse.ArgumentParser(description="Generate NVD-based White Belt Challenges")
    parser.add_argument("--output", help="Output YAML file path")
    args = parser.parse_args()

    generator = NVDChallengeGenerator()
    new_challenges = generator.create_curriculum()

    # Format as YAML structure matching existing curriculum
    output_data = {"challenges": new_challenges}

    yaml_output = yaml.dump(output_data, sort_keys=False, default_flow_style=False)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(yaml_output)
        logger.info(f"Wrote {len(new_challenges)} challenges to {args.output}")
    else:
        print(yaml_output)

if __name__ == "__main__":
    main()
