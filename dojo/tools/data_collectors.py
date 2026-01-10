#!/usr/bin/env python3
"""
Data Collectors for V2 Curriculum Generation

Collects vulnerability data from:
- NVD (National Vulnerability Database)
- AOSP Git (Android Open Source Project patches)
- CWE Database (Weakness taxonomy)
- GitHub Security Advisories

This data feeds the V2 challenge generator to create reasoning-based
training challenges for vulnerability discovery.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, cast

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class CVERecord:
    """Structured CVE data."""

    cve_id: str
    description: str
    cwe_ids: list[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    severity: str
    published_date: str
    affected_products: list[str]
    patch_urls: list[str]
    references: list[dict]
    raw_data: dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cwe_ids": self.cwe_ids,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "published_date": self.published_date,
            "affected_products": self.affected_products,
            "patch_urls": self.patch_urls,
            "references": self.references,
        }


@dataclass
class PatchRecord:
    """Extracted patch data."""

    source: str  # "aosp", "github", "other"
    commit_url: str
    commit_hash: str
    commit_message: str
    author: str
    date: str
    files_changed: list[str]
    before_code: dict[str, str]  # filename -> content before
    after_code: dict[str, str]  # filename -> content after
    diff: str
    cve_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "commit_url": self.commit_url,
            "commit_hash": self.commit_hash,
            "commit_message": self.commit_message,
            "author": self.author,
            "date": self.date,
            "files_changed": self.files_changed,
            "before_code": self.before_code,
            "after_code": self.after_code,
            "diff": self.diff,
            "cve_id": self.cve_id,
        }


@dataclass
class CWERecord:
    """CWE weakness record."""

    cwe_id: str
    name: str
    description: str
    extended_description: str
    parent_ids: list[str]
    child_ids: list[str]
    related_ids: list[str]
    detection_methods: list[str]
    mitigations: list[str]
    examples: list[str]
    owasp_mappings: list[str]

    def to_dict(self) -> dict:
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "extended_description": self.extended_description,
            "parent_ids": self.parent_ids,
            "child_ids": self.child_ids,
            "related_ids": self.related_ids,
            "detection_methods": self.detection_methods,
            "mitigations": self.mitigations,
            "examples": self.examples,
            "owasp_mappings": self.owasp_mappings,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# NVD COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════


class NVDCollector:
    """
    Collect CVE data from the National Vulnerability Database.

    Features:
    - Fetch Android-specific CVEs
    - Filter by severity, CWE, date range
    - Extract patch URLs from references
    - Rate limiting compliance
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 6.0  # seconds between requests (no API key)
    RATE_LIMIT_DELAY_WITH_KEY = 0.6  # seconds with API key

    # Patterns to identify patch URLs in references
    PATCH_URL_PATTERNS = [
        r"android\.googlesource\.com",
        r"github\.com/.+/commit/",
        r"github\.com/.+/pull/",
        r"source\.android\.com",
        r"git\..+\.org",
    ]

    def __init__(self, api_key: Optional[str] = None, cache_dir: Optional[Path] = None):
        """
        Initialize NVD collector.

        Args:
            api_key: NVD API key for higher rate limits
            cache_dir: Directory to cache responses
        """
        self.api_key = api_key
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.session = requests.Session()

        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
            self.rate_limit = self.RATE_LIMIT_DELAY_WITH_KEY
        else:
            self.rate_limit = self.RATE_LIMIT_DELAY

        self._last_request_time = 0.0

    def _rate_limit_wait(self) -> None:
        """Ensure we don't exceed rate limits."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    def _extract_patch_urls(self, references: list[dict]) -> list[str]:
        """Extract URLs that look like patches from references."""
        patch_urls = []
        for ref in references:
            url = ref.get("url", "")
            for pattern in self.PATCH_URL_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    patch_urls.append(url)
                    break
        return patch_urls

    def _parse_cve(self, vuln_data: dict) -> CVERecord:
        """Parse NVD vulnerability data into CVERecord."""
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id", "")

        # Get description (English)
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Get CWE IDs
        cwe_ids = []
        weaknesses = cve.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_ids.append(cwe_id)

        # Get CVSS v3.1 metrics
        cvss_score = None
        cvss_vector = None
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")

        # Get affected products
        affected_products = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if "android" in criteria.lower():
                        affected_products.append(criteria)

        # Get references and extract patch URLs
        references = cve.get("references", [])
        patch_urls = self._extract_patch_urls(references)

        # Get published date
        published_date = cve.get("published", "")

        return CVERecord(
            cve_id=cve_id,
            description=description,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            published_date=published_date,
            affected_products=affected_products,
            patch_urls=patch_urls,
            references=[{"url": r.get("url"), "tags": r.get("tags", [])} for r in references],
            raw_data=vuln_data,
        )

    def fetch_android_cves(
        self,
        min_severity: str = "HIGH",
        cwe_filter: Optional[list[str]] = None,
        has_patch: bool = False,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100,
    ) -> list[CVERecord]:
        """
        Fetch Android CVEs with filtering.

        Args:
            min_severity: Minimum CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)
            cwe_filter: Only return CVEs with these CWE IDs
            has_patch: Only return CVEs that have identifiable patch URLs
            start_date: Start date (YYYY-MM-DD)
            end_date: End date (YYYY-MM-DD)
            limit: Maximum number of CVEs to return

        Returns:
            List of CVERecord objects
        """
        params: dict[str, str | int] = {
            "keywordSearch": "Android",
            "resultsPerPage": min(limit, 100),
        }

        if min_severity in ("HIGH", "CRITICAL"):
            params["cvssV3Severity"] = min_severity

        if start_date:
            params["pubStartDate"] = f"{start_date}T00:00:00.000"
        if end_date:
            params["pubEndDate"] = f"{end_date}T23:59:59.999"

        all_cves: list[CVERecord] = []
        start_index = 0

        while len(all_cves) < limit:
            params["startIndex"] = start_index

            logger.info(f"Fetching CVEs (offset={start_index}, have={len(all_cves)}/{limit})...")
            self._rate_limit_wait()

            try:
                # cast params to satisfy mypy's strict checking of requests.get
                request_params = cast(Any, params)
                response = self.session.get(self.BASE_URL, params=request_params, timeout=30)  # type: ignore
                response.raise_for_status()
                data = response.json()
            except requests.RequestException as e:
                logger.error(f"NVD API request failed: {e}")
                break

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                if len(all_cves) >= limit:
                    break

                cve = self._parse_cve(vuln)

                # Apply filters
                if cwe_filter and not any(cwe in cve.cwe_ids for cwe in cwe_filter):
                    continue

                if has_patch and not cve.patch_urls:
                    continue

                all_cves.append(cve)

            total_results = data.get("totalResults", 0)
            start_index += len(vulnerabilities)

            if start_index >= total_results:
                break

        logger.info(f"Fetched {len(all_cves)} Android CVEs")
        return all_cves

    def fetch_cve_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """Fetch a specific CVE by ID."""
        params = {"cveId": cve_id}

        self._rate_limit_wait()

        try:
            # cast params to satisfy mypy's strict checking of requests.get
            request_params = cast(Any, params)
            response = self.session.get(self.BASE_URL, params=request_params, timeout=30)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch {cve_id}: {e}")
            return None

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        return self._parse_cve(vulnerabilities[0])


# ═══════════════════════════════════════════════════════════════════════════════
# AOSP PATCH COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════


class AOSPPatchCollector:
    """
    Collect patches from Android Open Source Project git repositories.

    Can extract:
    - Commit diffs
    - Before/after code
    - Commit messages
    - Security-related commits
    """

    # AOSP Gitiles base URLs
    AOSP_BASE = "https://android.googlesource.com"

    # Common repositories with security-relevant code
    SECURITY_REPOS = [
        "platform/frameworks/base",
        "platform/packages/apps/Settings",
        "platform/system/core",
        "platform/system/sepolicy",
        "platform/system/security",
        "platform/packages/providers/ContactsProvider",
        "platform/packages/providers/DownloadProvider",
    ]

    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize AOSP patch collector."""
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.session = requests.Session()

    def _parse_gitiles_commit(self, repo: str, commit_data: dict) -> PatchRecord:
        """Parse Gitiles commit JSON into PatchRecord."""
        commit_hash = commit_data.get("commit", "")
        message = commit_data.get("message", "")
        author = commit_data.get("author", {}).get("name", "")
        date = commit_data.get("author", {}).get("time", "")

        # Get diff (tree_diff contains file changes)
        files_changed = []
        before_code: dict[str, str] = {}
        after_code: dict[str, str] = {}

        tree_diff = commit_data.get("tree_diff", [])
        for diff_entry in tree_diff:
            old_path = diff_entry.get("old_path", "")
            new_path = diff_entry.get("new_path", "")
            path = new_path or old_path
            if path:
                files_changed.append(path)

        commit_url = f"{self.AOSP_BASE}/{repo}/+/{commit_hash}"

        return PatchRecord(
            source="aosp",
            commit_url=commit_url,
            commit_hash=commit_hash,
            commit_message=message,
            author=author,
            date=date,
            files_changed=files_changed,
            before_code=before_code,
            after_code=after_code,
            diff="",  # Would need separate fetch for full diff
        )

    def fetch_commit(self, repo: str, commit_hash: str) -> Optional[PatchRecord]:
        """
        Fetch a specific commit from AOSP.

        Args:
            repo: Repository path (e.g., "platform/frameworks/base")
            commit_hash: Full or abbreviated commit hash

        Returns:
            PatchRecord or None if not found
        """
        # Gitiles JSON API
        url = f"{self.AOSP_BASE}/{repo}/+/{commit_hash}?format=JSON"

        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 404:
                return None
            response.raise_for_status()

            # Gitiles returns JSON with )]}' prefix
            text = response.text
            if text.startswith(")]}'"):
                text = text[4:]

            data = json.loads(text)
            return self._parse_gitiles_commit(repo, data)

        except (requests.RequestException, json.JSONDecodeError) as e:
            logger.error(f"Failed to fetch commit {commit_hash}: {e}")
            return None

    def fetch_file_at_commit(
        self, repo: str, commit_hash: str, file_path: str
    ) -> Optional[str]:
        """
        Fetch file content at a specific commit.

        Args:
            repo: Repository path
            commit_hash: Commit hash
            file_path: Path to file in repo

        Returns:
            File content as string or None
        """
        # Gitiles raw file API
        url = f"{self.AOSP_BASE}/{repo}/+/{commit_hash}/{file_path}?format=TEXT"

        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 404:
                return None
            response.raise_for_status()

            # Content is base64 encoded
            import base64

            return base64.b64decode(response.text).decode("utf-8", errors="replace")

        except requests.RequestException as e:
            logger.error(f"Failed to fetch file {file_path}: {e}")
            return None

    def search_security_commits(
        self,
        repo: str,
        search_terms: Optional[list[str]] = None,
        limit: int = 50,
    ) -> list[str]:
        """
        Search for security-related commits in a repository.

        Args:
            repo: Repository to search
            search_terms: Terms to search for (default: CVE, security, vulnerability)
            limit: Maximum commits to return

        Returns:
            List of commit hashes
        """
        if search_terms is None:
            search_terms = ["CVE-", "security", "vulnerability", "fix crash"]

        # Gitiles log API
        url = f"{self.AOSP_BASE}/{repo}/+log/?format=JSON&n={limit}"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            text = response.text
            if text.startswith(")]}'"):
                text = text[4:]

            data = json.loads(text)
            log_entries = data.get("log", [])

            matching_commits = []
            for entry in log_entries:
                message = entry.get("message", "").lower()
                if any(term.lower() in message for term in search_terms):
                    matching_commits.append(entry.get("commit", ""))

            return matching_commits

        except (requests.RequestException, json.JSONDecodeError) as e:
            logger.error(f"Failed to search commits in {repo}: {e}")
            return []

    def extract_patch_from_url(self, url: str) -> Optional[PatchRecord]:
        """
        Extract patch data from an AOSP URL.

        Supports:
        - android.googlesource.com/repo/+/hash
        - android.googlesource.com/repo/+/hash^!

        Args:
            url: AOSP git URL

        Returns:
            PatchRecord or None
        """
        # Parse AOSP URL
        pattern = r"android\.googlesource\.com/([^/]+(?:/[^/]+)*)/\+/([a-f0-9]+)"
        match = re.search(pattern, url)

        if not match:
            logger.warning(f"Could not parse AOSP URL: {url}")
            return None

        repo = match.group(1)
        commit_hash = match.group(2).rstrip("^!")

        return self.fetch_commit(repo, commit_hash)


# ═══════════════════════════════════════════════════════════════════════════════
# CWE TAXONOMY
# ═══════════════════════════════════════════════════════════════════════════════


class CWETaxonomy:
    """
    Load and query CWE weakness taxonomy.

    For full functionality, download CWE XML from:
    https://cwe.mitre.org/data/downloads.html
    """

    # Android-relevant CWEs (subset for quick reference)
    ANDROID_CWES = {
        "CWE-89": {
            "name": "SQL Injection",
            "parents": ["CWE-943"],
            "owasp": ["M7"],
        },
        "CWE-79": {
            "name": "Cross-site Scripting (XSS)",
            "parents": ["CWE-74"],
            "owasp": ["M7"],
        },
        "CWE-78": {
            "name": "OS Command Injection",
            "parents": ["CWE-77"],
            "owasp": ["M7"],
        },
        "CWE-22": {
            "name": "Path Traversal",
            "parents": ["CWE-706"],
            "owasp": ["M7"],
        },
        "CWE-200": {
            "name": "Information Exposure",
            "parents": ["CWE-668"],
            "owasp": ["M2"],
        },
        "CWE-312": {
            "name": "Cleartext Storage of Sensitive Information",
            "parents": ["CWE-922"],
            "owasp": ["M2", "M9"],
        },
        "CWE-327": {
            "name": "Use of Broken Crypto Algorithm",
            "parents": ["CWE-693"],
            "owasp": ["M5"],
        },
        "CWE-330": {
            "name": "Insufficient Randomness",
            "parents": ["CWE-693"],
            "owasp": ["M5"],
        },
        "CWE-352": {
            "name": "Cross-Site Request Forgery",
            "parents": ["CWE-345"],
            "owasp": ["M6"],
        },
        "CWE-601": {
            "name": "Open Redirect",
            "parents": ["CWE-610"],
            "owasp": ["M1"],
        },
        "CWE-749": {
            "name": "Exposed Dangerous Method",
            "parents": ["CWE-668"],
            "owasp": ["M1", "M7"],
        },
        "CWE-798": {
            "name": "Hardcoded Credentials",
            "parents": ["CWE-344"],
            "owasp": ["M9"],
        },
        "CWE-862": {
            "name": "Missing Authorization",
            "parents": ["CWE-285"],
            "owasp": ["M6"],
        },
        "CWE-926": {
            "name": "Improper Export of Android Components",
            "parents": ["CWE-285"],
            "owasp": ["M1"],
        },
        "CWE-939": {
            "name": "Improper Authorization in Handler",
            "parents": ["CWE-862"],
            "owasp": ["M6"],
        },
    }

    def __init__(self, cwe_xml_path: Optional[Path] = None):
        """
        Initialize CWE taxonomy.

        Args:
            cwe_xml_path: Path to CWE XML file for full data
        """
        self.cwe_xml_path = cwe_xml_path
        self._cache: dict[str, CWERecord] = {}

    def get_cwe(self, cwe_id: str) -> Optional[CWERecord]:
        """
        Get CWE record by ID.

        Args:
            cwe_id: CWE ID (e.g., "CWE-89")

        Returns:
            CWERecord or None
        """
        if cwe_id in self._cache:
            return self._cache[cwe_id]

        # Use embedded data for common Android CWEs
        if cwe_id in self.ANDROID_CWES:
            data = self.ANDROID_CWES[cwe_id]
            record = CWERecord(
                cwe_id=cwe_id,
                name=str(data["name"]),
                description="",
                extended_description="",
                parent_ids=list(data.get("parents", [])),
                child_ids=[],
                related_ids=[],
                detection_methods=[],
                mitigations=[],
                examples=[],
                owasp_mappings=list(data.get("owasp", [])),
            )
            self._cache[cwe_id] = record
            return record

        return None

    def get_parent_chain(self, cwe_id: str) -> list[str]:
        """
        Get full parent chain for a CWE.

        Args:
            cwe_id: Starting CWE ID

        Returns:
            List of CWE IDs from child to root
        """
        chain = [cwe_id]
        current = cwe_id

        while True:
            record = self.get_cwe(current)
            if not record or not record.parent_ids:
                break
            parent = record.parent_ids[0]
            chain.append(parent)
            current = parent

        return chain

    def get_android_relevant_cwes(self) -> list[str]:
        """Get list of Android-relevant CWE IDs."""
        return list(self.ANDROID_CWES.keys())

    def map_to_owasp(self, cwe_id: str) -> list[str]:
        """
        Map CWE to OWASP Mobile Top 10 categories.

        Args:
            cwe_id: CWE ID

        Returns:
            List of OWASP Mobile categories (M1-M10)
        """
        record = self.get_cwe(cwe_id)
        if record:
            return record.owasp_mappings
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# GITHUB SECURITY ADVISORY COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════


class GitHubAdvisoryCollector:
    """
    Collect security advisories from GitHub.

    Focuses on Android library vulnerabilities:
    - OkHttp, Retrofit, Gson
    - AndroidX libraries
    - Popular third-party SDKs
    """

    API_BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub collector.

        Args:
            token: GitHub personal access token for higher rate limits
        """
        self.session = requests.Session()
        if token:
            self.session.headers["Authorization"] = f"token {token}"
        self.session.headers["Accept"] = "application/vnd.github+json"

    def search_advisories(
        self,
        ecosystem: str = "maven",
        keywords: Optional[list[str]] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """
        Search GitHub Security Advisories.

        Args:
            ecosystem: Package ecosystem (maven for Android/Java)
            keywords: Search keywords
            severity: Filter by severity
            limit: Maximum results

        Returns:
            List of advisory dictionaries
        """
        # Build GraphQL query or use REST API
        url = f"{self.API_BASE}/advisories"
        params = {
            "ecosystem": ecosystem,
            "per_page": min(limit, 100),
        }

        if severity:
            params["severity"] = severity.lower()

        try:
            response = self.session.get(url, params=cast(Any, params), timeout=30)
            response.raise_for_status()
            advisories = response.json()

            # Filter by keywords if provided
            if keywords:
                advisories = [
                    a
                    for a in advisories
                    if any(kw.lower() in json.dumps(a).lower() for kw in keywords)
                ]

            return advisories[:limit]

        except requests.RequestException as e:
            logger.error(f"Failed to fetch GitHub advisories: {e}")
            return []


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATED COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════


class VulnerabilityDataCollector:
    """
    Integrated collector that coordinates all data sources.

    Provides unified interface for curriculum generation.
    """

    def __init__(
        self,
        nvd_api_key: Optional[str] = None,
        github_token: Optional[str] = None,
        cache_dir: Optional[Path] = None,
    ):
        """Initialize all collectors."""
        self.nvd = NVDCollector(api_key=nvd_api_key, cache_dir=cache_dir)
        self.aosp = AOSPPatchCollector(cache_dir=cache_dir)
        self.cwe = CWETaxonomy()
        self.github = GitHubAdvisoryCollector(token=github_token)
        self.cache_dir = Path(cache_dir) if cache_dir else None

    def collect_cve_with_patch(self, cve_id: str) -> dict[str, Any]:
        """
        Collect complete data for a CVE including patches.

        Returns:
            Dictionary with CVE data, patches, and CWE info
        """
        result: dict[str, Any] = {
            "cve": None,
            "patches": [],
            "cwe_info": [],
            "complete": False,
        }

        # Fetch CVE
        cve = self.nvd.fetch_cve_by_id(cve_id)
        if not cve:
            logger.warning(f"CVE not found: {cve_id}")
            return result

        result["cve"] = cve.to_dict()

        # Fetch patches from identified URLs
        for patch_url in cve.patch_urls:
            if "android.googlesource.com" in patch_url:
                patch = self.aosp.extract_patch_from_url(patch_url)
                if patch:
                    patch.cve_id = cve_id
                    result["patches"].append(patch.to_dict())

        # Get CWE info
        for cwe_id in cve.cwe_ids:
            cwe_record = self.cwe.get_cwe(cwe_id)
            if cwe_record:
                result["cwe_info"].append(cwe_record.to_dict())

        result["complete"] = bool(result["patches"])
        return result

    def collect_android_vulnerabilities(
        self,
        count: int = 100,
        min_severity: str = "HIGH",
        require_patch: bool = True,
    ) -> list[dict]:
        """
        Collect Android vulnerabilities with all associated data.

        Args:
            count: Target number of complete records
            min_severity: Minimum CVSS severity
            require_patch: Only return CVEs with identified patches

        Returns:
            List of complete vulnerability records
        """
        logger.info(f"Collecting {count} Android vulnerabilities...")

        # Fetch more than needed since not all will have patches
        cves = self.nvd.fetch_android_cves(
            min_severity=min_severity,
            has_patch=require_patch,
            limit=count * 2,
        )

        results: list[dict[str, Any]] = []
        for cve in cves:
            if len(results) >= count:
                break

            data = self.collect_cve_with_patch(cve.cve_id)
            if data["complete"] or not require_patch:
                results.append(data)
                logger.info(f"Collected: {cve.cve_id} ({len(results)}/{count})")

        return results

    def save_collection(self, data: list[dict], output_path: Path) -> None:
        """Save collected data to JSON file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"Saved {len(data)} records to {output_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Collect vulnerability data for curriculum generation")
    parser.add_argument("--nvd-key", help="NVD API key")
    parser.add_argument("--github-token", help="GitHub token")
    parser.add_argument("--output", "-o", default="vulnerability_data.json", help="Output file")
    parser.add_argument("--count", "-n", type=int, default=50, help="Number of CVEs to collect")
    parser.add_argument("--severity", default="HIGH", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    parser.add_argument("--cve", help="Fetch specific CVE by ID")

    args = parser.parse_args()

    collector = VulnerabilityDataCollector(
        nvd_api_key=args.nvd_key,
        github_token=args.github_token,
    )

    if args.cve:
        # Fetch single CVE
        data = collector.collect_cve_with_patch(args.cve)
        print(json.dumps(data, indent=2, default=str))
    else:
        # Collect multiple
        data = collector.collect_android_vulnerabilities(
            count=args.count,
            min_severity=args.severity,
        )
        collector.save_collection(data, Path(args.output))


if __name__ == "__main__":
    main()
