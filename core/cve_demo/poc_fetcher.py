"""
PoC Fetcher - Retrieves Proof-of-Concept Code from Public Sources

Sources:
- GitHub (search + known repos)
- ExploitDB
- Google Project Zero
- Android Security Bulletins

For authorized security testing only.
"""

import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)


class PoCSource(Enum):
    GITHUB = "github"
    EXPLOITDB = "exploitdb"
    PROJECT_ZERO = "project_zero"
    ANDROID_BULLETIN = "android_bulletin"
    CUSTOM = "custom"


@dataclass
class PoCEntry:
    """A proof-of-concept exploit entry."""
    cve_id: str
    source: PoCSource
    url: str
    title: str
    description: str
    code: Optional[str] = None
    language: str = "unknown"
    verified: bool = False
    platform: str = "android"
    author: Optional[str] = None
    date: Optional[str] = None
    local_path: Optional[str] = None


# Known PoC repositories for Android CVEs
KNOWN_POC_REPOS: dict[str, dict] = {
    "CVE-2016-5195": {
        "url": "https://github.com/dirtycow/dirtycow.github.io",
        "files": ["pokemon.c", "dirtyc0w.c"],
        "language": "c",
    },
    "CVE-2019-2215": {
        "url": "https://github.com/grant-h/qu1ckr00t",
        "files": ["poc.c", "exploit.c"],
        "language": "c",
    },
    "CVE-2020-0041": {
        "url": "https://github.com/bluefrostsecurity/CVE-2020-0041",
        "files": ["exploit.c"],
        "language": "c",
    },
    "CVE-2020-0069": {
        "url": "https://github.com/topjohnwu/Magisk",
        "files": ["mtk-su.c"],
        "language": "c",
        "notes": "MediaTek-SU integrated into Magisk",
    },
    "CVE-2021-0920": {
        "url": "https://github.com/pqlx/CVE-2021-0920",
        "files": ["exploit.c"],
        "language": "c",
    },
    "CVE-2022-0847": {
        "url": "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
        "files": ["exploit.c", "dirtypipe.c"],
        "language": "c",
    },
    "CVE-2022-20465": {
        "url": "https://github.com/kirliavc/CVE-2022-20465",
        "files": ["poc.py"],
        "language": "python",
        "notes": "SIM swap lock screen bypass",
    },
    "CVE-2023-21036": {
        "url": "https://github.com/nicholasaleks/CVE-2023-21036",
        "files": ["acropalypse.py"],
        "language": "python",
        "notes": "aCropalypse screenshot data recovery",
    },
}


class PoCFetcher:
    """
    Fetches PoC code from various sources.

    Usage:
        fetcher = PoCFetcher()
        pocs = fetcher.fetch_for_cve("CVE-2022-0847")
        for poc in pocs:
            print(poc.code)
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        github_token: Optional[str] = None,
    ):
        self.cache_dir = Path(cache_dir or "output/poc_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.session = requests.Session()

        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"

    def fetch_for_cve(self, cve_id: str) -> list[PoCEntry]:
        """
        Fetch all available PoCs for a CVE.

        Searches:
        1. Known repositories
        2. GitHub code search
        3. ExploitDB
        """
        pocs = []

        # Check known repos first
        if cve_id in KNOWN_POC_REPOS:
            poc = self._fetch_known_repo(cve_id)
            if poc:
                pocs.append(poc)

        # Search GitHub
        github_pocs = self._search_github(cve_id)
        pocs.extend(github_pocs)

        # Search ExploitDB
        edb_pocs = self._search_exploitdb(cve_id)
        pocs.extend(edb_pocs)

        # Deduplicate by URL
        seen_urls = set()
        unique_pocs = []
        for poc in pocs:
            if poc.url not in seen_urls:
                seen_urls.add(poc.url)
                unique_pocs.append(poc)

        return unique_pocs

    def _fetch_known_repo(self, cve_id: str) -> Optional[PoCEntry]:
        """Fetch from known repository."""
        info = KNOWN_POC_REPOS.get(cve_id)
        if not info:
            return None

        try:
            # Convert github.com URL to raw content URL
            repo_url = info["url"]
            parts = repo_url.replace("https://github.com/", "").split("/")
            owner, repo = parts[0], parts[1]

            # Try to fetch exploit files
            code_parts = []
            for filename in info.get("files", []):
                # Try common paths
                for path in [filename, f"src/{filename}", f"exploit/{filename}"]:
                    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
                    resp = self.session.get(raw_url, timeout=10)
                    if resp.status_code == 200:
                        code_parts.append(f"// File: {filename}\n{resp.text}")
                        break
                    # Try master branch
                    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{path}"
                    resp = self.session.get(raw_url, timeout=10)
                    if resp.status_code == 200:
                        code_parts.append(f"// File: {filename}\n{resp.text}")
                        break

            code = "\n\n".join(code_parts) if code_parts else None

            return PoCEntry(
                cve_id=cve_id,
                source=PoCSource.GITHUB,
                url=repo_url,
                title=f"{cve_id} PoC",
                description=info.get("notes", f"Proof of concept for {cve_id}"),
                code=code,
                language=info.get("language", "c"),
                verified=True,
            )

        except Exception as e:
            logger.warning(f"Failed to fetch known repo for {cve_id}: {e}")
            return None

    def _search_github(self, cve_id: str, max_results: int = 5) -> list[PoCEntry]:
        """Search GitHub for PoC repositories."""
        pocs = []

        try:
            # Search repositories
            query = quote(f"{cve_id} android exploit poc")
            url = f"https://api.github.com/search/repositories?q={query}&per_page={max_results}"

            resp = self.session.get(url, timeout=15)
            if resp.status_code != 200:
                logger.warning(f"GitHub search failed: {resp.status_code}")
                return pocs

            data = resp.json()
            for item in data.get("items", []):
                pocs.append(PoCEntry(
                    cve_id=cve_id,
                    source=PoCSource.GITHUB,
                    url=item["html_url"],
                    title=item["name"],
                    description=item.get("description", "")[:200] or f"GitHub: {item['name']}",
                    language=item.get("language", "unknown"),
                    author=item["owner"]["login"],
                    verified=False,
                ))

        except Exception as e:
            logger.warning(f"GitHub search error: {e}")

        return pocs

    def _search_exploitdb(self, cve_id: str) -> list[PoCEntry]:
        """Search ExploitDB for exploits."""
        pocs = []

        try:
            # ExploitDB search API (unofficial, may need adjustment)
            # Using the CVE search endpoint
            url = f"https://www.exploit-db.com/search?cve={cve_id}"

            # Note: ExploitDB may require scraping or API access
            # This is a simplified version
            resp = self.session.get(url, timeout=15, headers={
                "User-Agent": "Mozilla/5.0 (Security Research)"
            })

            if resp.status_code == 200:
                # Parse response - would need proper HTML parsing
                # For now, construct reference URL
                pocs.append(PoCEntry(
                    cve_id=cve_id,
                    source=PoCSource.EXPLOITDB,
                    url=f"https://www.exploit-db.com/search?cve={cve_id}",
                    title=f"ExploitDB: {cve_id}",
                    description=f"Search ExploitDB for {cve_id} exploits",
                    verified=False,
                ))

        except Exception as e:
            logger.debug(f"ExploitDB search error: {e}")

        return pocs

    def download_poc(self, poc: PoCEntry) -> Optional[str]:
        """Download PoC code and save locally."""
        if poc.code:
            return poc.code

        if poc.source == PoCSource.GITHUB and "github.com" in poc.url:
            try:
                # Try to get raw file content
                parts = poc.url.replace("https://github.com/", "").split("/")
                owner, repo = parts[0], parts[1]

                # Get repository files
                api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
                resp = self.session.get(api_url, timeout=15)

                if resp.status_code == 200:
                    files = resp.json()
                    code_files = [f for f in files if f["name"].endswith(
                        (".c", ".py", ".sh", ".java", ".smali")
                    )]

                    if code_files:
                        # Download first code file
                        raw_url = code_files[0]["download_url"]
                        code_resp = self.session.get(raw_url, timeout=15)
                        if code_resp.status_code == 200:
                            poc.code = code_resp.text
                            return poc.code

            except Exception as e:
                logger.warning(f"Failed to download PoC: {e}")

        return None

    def get_cached_poc(self, cve_id: str) -> Optional[str]:
        """Get cached PoC code if available."""
        cache_file = self.cache_dir / f"{cve_id}.txt"
        if cache_file.exists():
            return cache_file.read_text()
        return None

    def cache_poc(self, poc: PoCEntry):
        """Cache PoC code locally."""
        if poc.code:
            cache_file = self.cache_dir / f"{poc.cve_id}.txt"
            cache_file.write_text(poc.code)
            poc.local_path = str(cache_file)


# Quick access functions
def fetch_poc(cve_id: str) -> list[PoCEntry]:
    """Quick function to fetch PoCs for a CVE."""
    fetcher = PoCFetcher()
    return fetcher.fetch_for_cve(cve_id)


def get_poc_code(cve_id: str) -> Optional[str]:
    """Get PoC code for a CVE, downloading if necessary."""
    fetcher = PoCFetcher()

    # Check cache first
    cached = fetcher.get_cached_poc(cve_id)
    if cached:
        return cached

    # Fetch and download
    pocs = fetcher.fetch_for_cve(cve_id)
    for poc in pocs:
        if poc.verified or poc.source == PoCSource.GITHUB:
            code = fetcher.download_poc(poc)
            if code:
                fetcher.cache_poc(poc)
                return code

    return None
