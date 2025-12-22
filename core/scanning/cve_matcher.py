"""
CVE Matcher

Matches device and application versions against known Android CVEs.
Uses local CVE database and optional NVD API queries.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ExploitAvailability(Enum):
    PUBLIC_EXPLOIT = "public_exploit"
    POC_AVAILABLE = "poc_available"
    NO_KNOWN_EXPLOIT = "no_known_exploit"


@dataclass
class CVEEntry:
    """Represents a CVE entry."""
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    affected_versions: list[str]
    min_api_level: Optional[int]
    max_api_level: Optional[int]
    patch_date: Optional[str]
    exploit_availability: ExploitAvailability
    references: list[str] = field(default_factory=list)
    exploit_url: Optional[str] = None


# Known exploits with verified PoC URLs (loaded from known_exploits.json)
# Primary CVE data comes from NVD API
KNOWN_EXPLOITS_FILE = os.path.join(os.path.dirname(__file__), "known_exploits.json")

# Curated Android kernel CVEs that don't appear in NVD "Android" keyword search
# These are Linux kernel CVEs that are exploitable on Android
CURATED_ANDROID_KERNEL_CVES: list[dict] = [
    {
        "cve_id": "CVE-2016-5195",
        "description": "Dirty COW - Race condition in mm/gup.c allows local privilege escalation via copy-on-write",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "affected_versions": ["4.4", "5.0", "5.1", "6.0", "7.0"],
        "min_api_level": 19,
        "max_api_level": 24,
        "patch_date": "2016-11-01",
        "exploit_availability": "public_exploit",
        "exploit_url": "https://github.com/dirtycow/dirtycow.github.io",
    },
    {
        "cve_id": "CVE-2019-2215",
        "description": "Binder UAF - Use-after-free in binder driver allows local privilege escalation",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "affected_versions": ["8.0", "8.1", "9", "10"],
        "min_api_level": 26,
        "max_api_level": 29,
        "patch_date": "2019-10-01",
        "exploit_availability": "public_exploit",
        "exploit_url": "https://github.com/grant-h/qu1ckr00t",
    },
    {
        "cve_id": "CVE-2020-0069",
        "description": "MediaTek-SU - Command queue driver vulnerability allows privilege escalation on MediaTek SoCs",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected_versions": ["7.0", "7.1", "8.0", "8.1", "9", "10"],
        "min_api_level": 24,
        "max_api_level": 29,
        "patch_date": "2020-03-01",
        "exploit_availability": "public_exploit",
        "exploit_url": "https://github.com/topjohnwu/Magisk",
    },
    {
        "cve_id": "CVE-2022-0847",
        "description": "Dirty Pipe - Arbitrary file overwrite via pipe page cache allows privilege escalation",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "affected_versions": ["12", "12L"],
        "min_api_level": 31,
        "max_api_level": 32,
        "patch_date": "2022-03-01",
        "exploit_availability": "public_exploit",
        "exploit_url": "https://dirtypipe.cm4all.com/",
    },
    {
        "cve_id": "CVE-2021-0920",
        "description": "Unix GC UAF - Use-after-free in Unix garbage collector allows privilege escalation",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "affected_versions": ["10", "11", "12"],
        "min_api_level": 29,
        "max_api_level": 31,
        "patch_date": "2021-11-01",
        "exploit_availability": "poc_available",
    },
]


class CVEMatcher:
    """
    Matches device configuration against known Android CVEs.

    Usage:
        matcher = CVEMatcher()
        matches = matcher.match_device(
            android_version="13",
            api_level=33,
            security_patch="2023-06-01"
        )
        for cve in matches:
            print(f"{cve.cve_id}: {cve.description}")
    """

    def __init__(self, database_path: Optional[str] = None, auto_fetch: bool = True):
        self.cve_database: list[CVEEntry] = []
        self.known_exploits: dict[str, dict] = {}
        self._load_known_exploits()
        self._load_database(database_path, auto_fetch)

    def _load_known_exploits(self):
        """Load curated exploit URLs from known_exploits.json."""
        if os.path.exists(KNOWN_EXPLOITS_FILE):
            try:
                with open(KNOWN_EXPLOITS_FILE) as f:
                    data = json.load(f)
                    for exploit in data.get("exploits", []):
                        self.known_exploits[exploit["cve_id"]] = exploit
                logger.info(f"Loaded {len(self.known_exploits)} known exploits")
            except Exception as e:
                logger.warning(f"Failed to load known exploits: {e}")

    def _enrich_with_known_exploits(self, cve: CVEEntry) -> CVEEntry:
        """Enrich CVE with known exploit data if available."""
        if cve.cve_id in self.known_exploits:
            exploit_info = self.known_exploits[cve.cve_id]
            cve.exploit_url = exploit_info.get("exploit_url")
            cve.exploit_availability = ExploitAvailability.PUBLIC_EXPLOIT
            logger.debug(f"Enriched {cve.cve_id} with known exploit: {exploit_info.get('name')}")
        return cve

    def _load_database(self, database_path: Optional[str], auto_fetch: bool):
        """Load CVE database from file, cache, or NVD API."""
        # Always load curated kernel CVEs first (these don't show up in NVD "Android" search)
        for entry in CURATED_ANDROID_KERNEL_CVES:
            cve = self._dict_to_cve(entry)
            self.cve_database.append(cve)
        logger.info(f"Loaded {len(CURATED_ANDROID_KERNEL_CVES)} curated kernel CVEs")

        # Option 1: Load from specified path
        if database_path and os.path.exists(database_path):
            try:
                with open(database_path) as f:
                    data = json.load(f)
                    for entry in data:
                        if not any(c.cve_id == entry["cve_id"] for c in self.cve_database):
                            cve = self._dict_to_cve(entry)
                            cve = self._enrich_with_known_exploits(cve)
                            self.cve_database.append(cve)
                logger.info(f"Total CVEs: {len(self.cve_database)} (from {database_path})")
                return
            except Exception as e:
                logger.warning(f"Failed to load CVE database: {e}")

        # Option 2: Load from NVD cache
        cache_file = os.path.join(os.path.dirname(__file__), "..", "..", "output", "nvd_cache.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                    for entry in data:
                        if not any(c.cve_id == entry["cve_id"] for c in self.cve_database):
                            cve = self._dict_to_cve(entry)
                            cve = self._enrich_with_known_exploits(cve)
                            self.cve_database.append(cve)
                logger.info(f"Total CVEs: {len(self.cve_database)} (from NVD cache)")
                return
            except Exception as e:
                logger.warning(f"Failed to load NVD cache: {e}")

        # Option 3: Auto-fetch from NVD (if enabled and no cache)
        if auto_fetch:
            logger.info("No CVE cache found. Fetching from NVD API...")
            self.update_from_nvd(max_results=200, use_cache=True)
        else:
            logger.info(f"Using {len(self.cve_database)} curated CVEs only. Call update_from_nvd() for more.")

    def _dict_to_cve(self, d: dict) -> CVEEntry:
        """Convert dictionary to CVEEntry."""
        return CVEEntry(
            cve_id=d["cve_id"],
            description=d["description"],
            severity=d["severity"],
            cvss_score=d["cvss_score"],
            affected_versions=d["affected_versions"],
            min_api_level=d.get("min_api_level"),
            max_api_level=d.get("max_api_level"),
            patch_date=d.get("patch_date"),
            exploit_availability=ExploitAvailability(d.get("exploit_availability", "no_known_exploit")),
            references=d.get("references", []),
            exploit_url=d.get("exploit_url"),
        )

    def match_device(
        self,
        android_version: str,
        api_level: int,
        security_patch: Optional[str] = None,
        kernel_version: Optional[str] = None,
    ) -> list[CVEEntry]:
        """
        Find CVEs that affect the given device configuration.

        Args:
            android_version: Android version string (e.g., "13", "12L")
            api_level: Android API level
            security_patch: Security patch date (YYYY-MM-DD)
            kernel_version: Linux kernel version

        Returns:
            List of matching CVEEntry objects
        """
        matches = []

        # Parse security patch date
        patch_datetime = None
        if security_patch:
            try:
                patch_datetime = datetime.strptime(security_patch, "%Y-%m-%d")
            except ValueError:
                pass

        for cve in self.cve_database:
            # Check version match
            version_match = False
            for affected_ver in cve.affected_versions:
                if android_version.startswith(affected_ver) or affected_ver == android_version:
                    version_match = True
                    break

            if not version_match:
                continue

            # Check API level range
            if cve.min_api_level and api_level < cve.min_api_level:
                continue
            if cve.max_api_level and api_level > cve.max_api_level:
                continue

            # Check if patched
            if patch_datetime and cve.patch_date:
                try:
                    cve_patch_date = datetime.strptime(cve.patch_date, "%Y-%m-%d")
                    if patch_datetime >= cve_patch_date:
                        # Device has patch, skip this CVE
                        continue
                except ValueError:
                    pass

            matches.append(cve)

        # Sort by CVSS score (highest first)
        matches.sort(key=lambda c: c.cvss_score, reverse=True)

        return matches

    def match_app(
        self,
        package_name: str,
        version_code: int,
        version_name: str,
    ) -> list[CVEEntry]:
        """
        Find CVEs that affect a specific application.

        Note: This is a placeholder. A real implementation would need
        an app-specific CVE database.
        """
        # Would query app-specific CVE database
        return []

    def get_exploitable_cves(
        self,
        android_version: str,
        api_level: int,
        security_patch: Optional[str] = None,
    ) -> list[CVEEntry]:
        """
        Get only CVEs with known public exploits.
        """
        all_matches = self.match_device(android_version, api_level, security_patch)
        return [
            cve for cve in all_matches
            if cve.exploit_availability == ExploitAvailability.PUBLIC_EXPLOIT
        ]

    def export_database(self, output_path: str):
        """Export CVE database to JSON file."""
        data = []
        for cve in self.cve_database:
            data.append({
                "cve_id": cve.cve_id,
                "description": cve.description,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "affected_versions": cve.affected_versions,
                "min_api_level": cve.min_api_level,
                "max_api_level": cve.max_api_level,
                "patch_date": cve.patch_date,
                "exploit_availability": cve.exploit_availability.value,
                "references": cve.references,
                "exploit_url": cve.exploit_url,
            })

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported {len(data)} CVEs to {output_path}")

    def update_from_nvd(
        self,
        api_key: Optional[str] = None,
        max_results: int = 500,
        use_cache: bool = True,
        cache_hours: int = 24,
    ):
        """
        Update CVE database from NVD API with pagination, caching, and rate limiting.

        Args:
            api_key: NVD API key (get free at https://nvd.nist.gov/developers/request-an-api-key)
            max_results: Maximum CVEs to fetch (default 500)
            use_cache: Whether to use cached results (default True)
            cache_hours: Hours before cache expires (default 24)

        Rate limits:
            - Without API key: 5 requests per 30 seconds
            - With API key: 50 requests per 30 seconds
        """
        import time

        import requests

        # Check for cached data
        cache_file = os.path.join(os.path.dirname(__file__), "..", "..", "output", "nvd_cache.json")
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)

        if use_cache and os.path.exists(cache_file):
            try:
                cache_age = time.time() - os.path.getmtime(cache_file)
                if cache_age < cache_hours * 3600:
                    with open(cache_file) as f:
                        cached_data = json.load(f)
                    logger.info(f"Loading {len(cached_data)} CVEs from cache (age: {cache_age/3600:.1f}h)")
                    for entry in cached_data:
                        if not any(c.cve_id == entry["cve_id"] for c in self.cve_database):
                            self.cve_database.append(self._dict_to_cve(entry))
                    return
            except Exception as e:
                logger.warning(f"Cache read failed: {e}")

        # API configuration
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": api_key} if api_key else {}
        rate_limit_delay = 0.6 if api_key else 6.0  # Respect NVD rate limits

        # Fetch with pagination
        all_cves = []
        start_index = 0
        results_per_page = 100

        logger.info(f"Fetching Android CVEs from NVD (max {max_results})...")

        while start_index < max_results:
            params: dict[str, str] = {
                "keywordSearch": "Android",
                "resultsPerPage": str(min(results_per_page, max_results - start_index)),
                "startIndex": str(start_index),
            }

            try:
                response = requests.get(base_url, params=params, headers=headers, timeout=60)

                if response.status_code == 403:
                    logger.warning("Rate limited by NVD. Waiting 30 seconds...")
                    time.sleep(30)
                    continue

                response.raise_for_status()
                data = response.json()

                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                total_results = data.get("totalResults", 0)
                logger.info(f"Fetched {start_index + len(vulns)}/{min(total_results, max_results)} CVEs")

                for vuln in vulns:
                    cve_entry = self._parse_nvd_cve(vuln)
                    if cve_entry:
                        cve_entry = self._enrich_with_known_exploits(cve_entry)
                        all_cves.append(cve_entry)

                start_index += len(vulns)

                if start_index >= total_results:
                    break

                # Rate limiting
                time.sleep(rate_limit_delay)

            except requests.exceptions.RequestException as e:
                logger.error(f"NVD API request failed: {e}")
                break

        # Cache results
        if all_cves:
            try:
                cache_data = []
                for cve in all_cves:
                    cache_data.append({
                        "cve_id": cve.cve_id,
                        "description": cve.description,
                        "severity": cve.severity,
                        "cvss_score": cve.cvss_score,
                        "affected_versions": cve.affected_versions,
                        "min_api_level": cve.min_api_level,
                        "max_api_level": cve.max_api_level,
                        "patch_date": cve.patch_date,
                        "exploit_availability": cve.exploit_availability.value,
                        "references": cve.references,
                        "exploit_url": cve.exploit_url,
                    })
                with open(cache_file, "w") as f:
                    json.dump(cache_data, f, indent=2)
                logger.info(f"Cached {len(cache_data)} CVEs to {cache_file}")
            except Exception as e:
                logger.warning(f"Cache write failed: {e}")

        # Add to database
        new_cves = 0
        for cve in all_cves:
            if not any(c.cve_id == cve.cve_id for c in self.cve_database):
                self.cve_database.append(cve)
                new_cves += 1

        logger.info(f"Added {new_cves} new CVEs from NVD (total: {len(self.cve_database)})")

    def _parse_nvd_cve(self, vuln: dict) -> Optional[CVEEntry]:
        """Parse a single CVE from NVD API response."""

        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id:
            return None

        # Extract description
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Skip non-Android CVEs that slipped through keyword search
        desc_lower = description.lower()
        if "android" not in desc_lower and "google" not in desc_lower:
            return None

        # Get CVSS score
        cvss_score = 0.0
        metrics = cve_data.get("metrics", {})
        for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_type in metrics and metrics[metric_type]:
                cvss_data = metrics[metric_type][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                break

        # Severity mapping
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Parse Android versions from description
        affected_versions = self._extract_android_versions(description)

        # Parse API levels
        min_api, max_api = self._extract_api_levels(description, affected_versions)

        # Check for exploit availability (basic heuristic)
        exploit_availability = ExploitAvailability.NO_KNOWN_EXPLOIT
        exploit_url = None

        references = []
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            references.append(url)

            # Check for known exploit sources
            if any(src in url.lower() for src in ["exploit-db", "github.com/poc", "github.com/exploit", "packetstorm"]):
                exploit_availability = ExploitAvailability.POC_AVAILABLE
                exploit_url = url

        # Check description for exploit indicators
        if any(term in desc_lower for term in ["proof of concept", "poc available", "exploit available", "actively exploited"]):
            exploit_availability = ExploitAvailability.POC_AVAILABLE

        # Extract patch date from published date
        patch_date = None
        published = cve_data.get("published", "")
        if published:
            patch_date = published[:10]  # YYYY-MM-DD

        return CVEEntry(
            cve_id=cve_id,
            description=description[:500],
            severity=severity,
            cvss_score=cvss_score,
            affected_versions=affected_versions,
            min_api_level=min_api,
            max_api_level=max_api,
            patch_date=patch_date,
            exploit_availability=exploit_availability,
            references=references[:5],  # Limit to 5 references
            exploit_url=exploit_url,
        )

    def _extract_android_versions(self, description: str) -> list[str]:
        """Extract Android version numbers from CVE description."""
        import re

        versions = set()

        # Pattern: "Android X", "Android X.Y", "Android X.Y.Z"
        pattern = r"Android\s+(\d+(?:\.\d+)?(?:\.\d+)?)"
        matches = re.findall(pattern, description, re.IGNORECASE)
        versions.update(matches)

        # Pattern: "Android versions X through Y"
        range_pattern = r"Android\s+(?:versions?\s+)?(\d+(?:\.\d+)?)\s+(?:through|to|-)\s+(\d+(?:\.\d+)?)"
        range_matches = re.findall(range_pattern, description, re.IGNORECASE)
        for start, end in range_matches:
            try:
                start_major = int(start.split('.')[0])
                end_major = int(end.split('.')[0])
                for v in range(start_major, end_major + 1):
                    versions.add(str(v))
            except ValueError:
                pass

        # Pattern: "Android 10, 11, 12, and 13"
        list_pattern = r"Android\s+((?:\d+(?:\.\d+)?(?:,\s*|\s+and\s+)?)+)"
        list_matches = re.findall(list_pattern, description, re.IGNORECASE)
        for match in list_matches:
            nums = re.findall(r"\d+(?:\.\d+)?", match)
            versions.update(nums)

        return sorted(list(versions), key=lambda x: float(x.split('.')[0]))

    def _extract_api_levels(self, description: str, versions: list[str]) -> tuple[Optional[int], Optional[int]]:
        """Extract or infer API levels from description and versions."""
        import re

        # Direct API level mentions
        api_pattern = r"API\s+(?:level\s+)?(\d+)"
        api_matches = re.findall(api_pattern, description, re.IGNORECASE)
        if api_matches:
            levels = [int(x) for x in api_matches]
            return min(levels), max(levels)

        # Infer from Android versions
        version_to_api = {
            "4.4": 19, "5.0": 21, "5.1": 22, "6.0": 23, "7.0": 24, "7.1": 25,
            "8.0": 26, "8.1": 27, "9": 28, "9.0": 28, "10": 29, "11": 30,
            "12": 31, "12L": 32, "13": 33, "14": 34, "15": 35,
        }

        if versions:
            api_levels = []
            for v in versions:
                if v in version_to_api:
                    api_levels.append(version_to_api[v])
                elif v.split('.')[0] in version_to_api:
                    api_levels.append(version_to_api[v.split('.')[0]])
            if api_levels:
                return min(api_levels), max(api_levels)

        return None, None
