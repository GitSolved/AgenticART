"""
NVD Challenge Generator - Automates Dojo challenge creation from real-world CVEs.

Usage:
    generator = NVDChallengeGenerator(api_key="your_nvd_api_key")
    challenges = generator.generate_challenges(android_version="14", belt=Belt.ORANGE)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml

from dojo.models import (
    Belt,
)

logger = logging.getLogger(__name__)


@dataclass
class LiveCVE:
    """CVE from live NVD API query."""

    cve_id: str
    published: str
    cvss_score: float
    severity: str
    description: str
    attack_vector: str = "NETWORK"
    exploit_maturity: str = "UNPROVEN"
    references: List[Dict[str, Any]] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)


class NVDChallengeGenerator:
    """Fetches CVEs from NVD and generates Dojo challenge templates."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.session = requests.Session()
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
        else:
            logger.warning("No NVD API key - rate limits will be strict")

    def fetch_recent_android_cves(self, android_version: str, limit: int = 10) -> List[LiveCVE]:
        """Fetch recent CVEs for a specific Android version."""
        query = f"Android {android_version}"
        params = {"keywordSearch": query, "resultsPerPage": str(limit)}

        try:
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            if response.status_code != 200:
                logger.error(f"NVD API error: {response.status_code}")
                return []

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            cves = []
            for v in vulnerabilities:
                cve = self._parse_cve(v)
                if cve:
                    cves.append(cve)
            return cves
        except Exception as e:
            logger.error(f"Failed to fetch from NVD: {e}")
            return []

    def _parse_cve(self, v_data: dict) -> Optional[LiveCVE]:
        """Parse NVD 2.0 API JSON into LiveCVE object."""
        try:
            cve_item = v_data.get("cve", {})
            cve_id = cve_item.get("id")
            published = cve_item.get("published")

            # Description
            desc_list = cve_item.get("descriptions", [])
            description = ""
            for d in desc_list:
                if d.get("lang") == "en":
                    description = d.get("value")
                    break

            # Metrics (CVSS 3.1 preferred)
            metrics = cve_item.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            attack_vector = "NETWORK"

            cvss_31 = metrics.get("cvssMetricV31", [])
            if cvss_31:
                data = cvss_31[0].get("cvssData", {})
                cvss_score = data.get("baseScore", 0.0)
                severity = data.get("baseSeverity", "UNKNOWN")
                attack_vector = data.get("attackVector", "NETWORK")

            # CWEs
            cwes = []
            for w in cve_item.get("weaknesses", []):
                for d in w.get("description", []):
                    if d.get("value").startswith("CWE-"):
                        cwes.append(d.get("value"))

            return LiveCVE(
                cve_id=cve_id,
                published=published,
                cvss_score=cvss_score,
                severity=severity,
                description=description,
                attack_vector=attack_vector,
                cwe_ids=cwes,
            )
        except Exception:
            return None

    def classify_belt(self, cve: LiveCVE) -> Belt:
        """Semantic classification based on vulnerability type and complexity."""
        desc = cve.description.lower()

        # 1. Critical Kernel/Driver Path (Black/Brown)
        if any(
            kw in desc for kw in ["kernel", "use-after-free", "race condition", "uaf", "binder"]
        ):
            return Belt.BLACK if cve.attack_vector == "NETWORK" else Belt.BROWN

        # 2. Native Code / Memory Path (Blue)
        if any(
            kw in desc
            for kw in [
                "buffer overflow",
                "integer overflow",
                "out-of-bounds",
                "memory corruption",
            ]
        ):
            return Belt.BLUE

        # 3. IPC / App Logic Path (Orange)
        if any(
            kw in desc
            for kw in [
                "intent",
                "content provider",
                "permission bypass",
                "exported",
                "broadcast",
            ]
        ):
            return Belt.ORANGE

        # 4. Information / Recon Path (Yellow)
        if any(kw in desc for kw in ["information disclosure", "leak", "logcat", "sensitive"]):
            return Belt.YELLOW

        # Fallback to CVSS score
        if cve.cvss_score >= 9.0:
            return Belt.BROWN
        elif cve.cvss_score >= 7.0:
            return Belt.BLUE
        elif cve.cvss_score >= 4.0:
            return Belt.ORANGE
        else:
            return Belt.YELLOW

    def create_challenge_template(self, cve: LiveCVE) -> Dict[str, Any]:
        """Generate a YAML-compatible challenge dictionary."""
        belt = self.classify_belt(cve)

        # Determine script type based on description keywords
        script_type = "adb"
        if "kernel" in cve.description.lower():
            script_type = "c_exploit"
        elif any(kw in cve.description.lower() for kw in ["hook", "intercept", "instrument"]):
            script_type = "frida"

        template = {
            "id": f"{belt.value}_{cve.cve_id.replace('-', '_').lower()}",
            "name": f"CVE Analysis: {cve.cve_id}",
            "description": f"Target: {cve.cve_id}\n\n{cve.description}\n\nGoal: Probe the device to determine if it is vulnerable to this specific issue.",
            "belt": belt.value,
            "difficulty": 3,
            "script_type": script_type,
            "inputs": {
                "cve_id": cve.cve_id,
                "device_context": {
                    "connection": "adb",
                    "task": "vulnerability_probing",
                    "severity": cve.severity,
                },
            },
            "expected_output": {"must_contain": [cve.cve_id], "expected_patterns": []},
            "scoring": {
                "syntax_correct": 25,
                "api_valid": 25,
                "executes_successfully": 30,
                "achieves_objective": 20,
            },
            "tags": ["nvd-generated", cve.cve_id.lower()] + [c.lower() for c in cve.cwe_ids],
        }

        return template

    def export_to_curriculum(
        self, template: Dict[str, Any], curriculum_dir: Path = Path("dojo/curriculum")
    ):
        """Append the generated challenge to the appropriate belt's challenges.yaml."""
        belt_name = template["belt"]
        yaml_path = curriculum_dir / f"{belt_name}_belt" / "challenges.yaml"

        if not yaml_path.exists():
            data: Dict[str, Any] = {"challenges": []}
        else:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f) or {"challenges": []}

        # Check for duplicates
        if any(c["id"] == template["id"] for c in data["challenges"]):
            logger.info(f"Challenge {template['id']} already exists. Skipping.")
            return

        data["challenges"].append(template)

        with open(yaml_path, "w") as f:
            yaml.dump(data, f, sort_keys=False, default_flow_style=False)

        logger.info(f"Exported {template['id']} to {yaml_path}")


if __name__ == "__main__":
    # Quick Test
    gen = NVDChallengeGenerator()
    print("Fetching recent Android 14 CVEs...")
    cves = gen.fetch_recent_android_cves(android_version="14", limit=2)

    for cve in cves:
        print(f"\nProcessing {cve.cve_id} (CVSS: {cve.cvss_score})")
        template = gen.create_challenge_template(cve)
        print(f"Assigned Belt: {template['belt'].upper()}")
        print(f"Generated ID: {template['id']}")
        # gen.export_to_curriculum(template) # Uncomment to actually save
