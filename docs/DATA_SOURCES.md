# External Data Sources for Discovery Training

## The Core Problem

**V1 (current)**: Generates "retrieve patch level" challenges from CVE metadata
**V2 (needed)**: Needs actual vulnerable code, patches, and reasoning chains

To train a model to DISCOVER vulnerabilities, we need training data that shows:
1. What the vulnerable code looked like
2. What observations led to finding it
3. Why it was vulnerable (root cause)
4. How it was fixed (patch analysis)
5. What similar patterns exist

---

## Required Data Sources

### 1. NVD API + CVE Details
**What it provides**:
- CVE IDs with CWE mappings
- CVSS scores (severity calibration)
- Affected products/versions
- References to patches

**API Endpoint**: `https://services.nvd.nist.gov/rest/json/cves/2.0`

**Limitations**:
- No actual code
- No patch diffs
- Just metadata

**Use for**: Taxonomy training, severity assessment, CVE → CWE mapping

---

### 2. Android Security Bulletins
**What it provides**:
- Monthly Android CVEs
- Affected components
- Links to AOSP patches
- Severity ratings

**Source**: `https://source.android.com/security/bulletin`

**Critical for**:
- Android-specific vulnerability patterns
- Framework-level vulnerabilities
- Real severity context

---

### 3. AOSP Git (Android Open Source Project)
**What it provides**:
- ACTUAL PATCH DIFFS
- Before/after code
- Commit messages explaining fixes
- Related changes

**Source**: `https://android.googlesource.com/`

**Example**: For CVE-2023-21036 (acropalypse)
```
https://android.googlesource.com/platform/packages/apps/Markup/+/cc org/chromium/src/+/main/third_party/pdfium/core/fpdfapi/parser/cpdf_stream_acc.cpp
```

**Critical for**: Pillar 7 (Patch Analysis) - This is the GOLD STANDARD

---

### 4. GitHub Security Advisories (GHSA)
**What it provides**:
- Vulnerabilities in Android libraries
- OkHttp, Retrofit, Gson, etc.
- Links to fixing PRs

**API**: `https://api.github.com/advisories`

**Critical for**: Third-party library vulnerabilities in Android apps

---

### 5. CWE Database
**What it provides**:
- Complete weakness taxonomy
- Parent/child relationships
- Detection methods
- Related weaknesses

**Source**: `https://cwe.mitre.org/data/downloads.html` (XML/JSON exports)

**Critical for**: Pillar 6 (Taxonomy Understanding)

---

### 6. Exploit-DB / PacketStorm (Curated)
**What it provides**:
- Proof-of-concept exploits
- Exploitation techniques
- Real attack patterns

**Use carefully**: Educational context only, curated selection

---

### 7. Open Source Android Apps (GitHub)
**What it provides**:
- Real codebases with commit history
- Security-related commits
- Bug fix patterns

**Sources**:
- F-Droid catalog: `https://f-droid.org/api/v1/packages`
- GitHub search: `language:java topic:android`

---

## Data Collection Strategy

### Phase 1: CVE → Patch Mapping Pipeline

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  NVD API    │────▶│  CVE Metadata    │────▶│  Find Patch     │
│             │     │  - CWE           │     │  - AOSP git     │
│             │     │  - CVSS          │     │  - GitHub refs  │
└─────────────┘     │  - References    │     │  - ASB links    │
                    └──────────────────┘     └─────────────────┘
                                                     │
                                                     ▼
                    ┌──────────────────┐     ┌─────────────────┐
                    │  Challenge Gen   │◀────│  Extract Diff   │
                    │  - Before code   │     │  - git diff     │
                    │  - After code    │     │  - context      │
                    │  - Root cause    │     └─────────────────┘
                    └──────────────────┘
```

### Phase 2: Pattern Clustering

```
┌─────────────────────────────────────────────────────────────┐
│                    CWE-89 (SQL Injection)                   │
├─────────────────────────────────────────────────────────────┤
│  Instance 1: CVE-2021-XXXXX - ContentProvider               │
│  Instance 2: CVE-2020-XXXXX - Room Database                 │
│  Instance 3: CVE-2022-XXXXX - SQLiteOpenHelper              │
│  Instance 4: Synthetic - Custom query builder               │
│  Instance 5: Holdout - For transfer testing                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation: Data Collectors

### 1. NVD Collector (Enhanced)

```python
class NVDCollector:
    """Fetch CVE data with patch references."""

    def fetch_android_cves(self,
                           min_severity: str = "HIGH",
                           cwe_filter: list[str] = None,
                           has_patch: bool = True) -> list[CVERecord]:
        """
        Fetch Android CVEs with filtering.

        Returns CVERecord with:
        - cve_id, cwe_id, cvss_score
        - description
        - patch_urls (extracted from references)
        - affected_versions
        """
        pass
```

### 2. AOSP Patch Collector

```python
class AOSPPatchCollector:
    """Extract actual code diffs from AOSP."""

    def fetch_patch(self, commit_url: str) -> PatchRecord:
        """
        Fetch a specific patch.

        Returns PatchRecord with:
        - before_code: str
        - after_code: str
        - commit_message: str
        - files_changed: list[str]
        - diff: str
        """
        pass

    def search_security_commits(self,
                                 cve_id: str = None,
                                 component: str = None) -> list[str]:
        """Search for security-related commits."""
        pass
```

### 3. CWE Taxonomy Loader

```python
class CWETaxonomy:
    """Load and query CWE hierarchy."""

    def get_cwe(self, cwe_id: str) -> CWERecord:
        """Get CWE with full hierarchy."""
        pass

    def get_parent_chain(self, cwe_id: str) -> list[str]:
        """Get CWE-89 -> CWE-943 -> CWE-74 chain."""
        pass

    def get_related_weaknesses(self, cwe_id: str) -> list[str]:
        """Get siblings and related CWEs."""
        pass
```

### 4. Challenge Generator V2

```python
class ChallengeGeneratorV2:
    """Generate V2 challenges from collected data."""

    def generate_patch_analysis_challenge(self,
                                           patch: PatchRecord,
                                           cve: CVERecord) -> ChallengeV2:
        """
        Generate a patch analysis challenge.

        Artifacts:
        - before_code (decompiled_code type)
        - after_code (patch_diff type)
        - cve_description (cve_description type)

        Phases:
        - observe: What changed?
        - hypothesize: What vulnerability did it fix?
        - analyze: What was the root cause?
        """
        pass

    def generate_pattern_family(self,
                                 cwe_id: str,
                                 instances: list[PatchRecord]) -> list[ChallengeV2]:
        """
        Generate a pattern family with transfer holdout.

        Creates 4-5 challenges showing same vuln pattern,
        plus 1 holdout for transfer testing.
        """
        pass
```

---

## Data Volume Requirements

| Data Type | Minimum Needed | Ideal | Source |
|-----------|---------------|-------|--------|
| Android CVEs with patches | 100 | 300+ | NVD + AOSP |
| CWE entries (Android-relevant) | 50 | 100+ | CWE Database |
| Pattern families | 30 | 50+ | Clustered from CVEs |
| Negative examples (secure code) | 150 | 300+ | Reviewed open source |
| Real APKs for synthesis | 20 | 50+ | F-Droid, custom |

---

## Priority Order for Implementation

### Week 1-2: Core Infrastructure
1. ✅ Enhanced NVD collector with patch URL extraction
2. ✅ AOSP git scraper for patch diffs
3. ✅ CWE taxonomy loader

### Week 3-4: Data Collection
4. Collect 100 Android CVEs with patches
5. Extract code diffs for each
6. Map to CWE taxonomy

### Week 5-6: Challenge Generation
7. Generate patch analysis challenges
8. Create pattern families
9. Add negative examples

### Week 7-8: Validation
10. Expert review of generated challenges
11. Test with baseline model
12. Iterate on quality

---

## API Keys / Access Required

| Service | Free Tier | Rate Limits | Key Required |
|---------|-----------|-------------|--------------|
| NVD API | Yes | 5 req/30s (no key), 50 req/30s (with key) | Optional but recommended |
| GitHub API | Yes | 60 req/hr (no auth), 5000 req/hr (auth) | Recommended |
| AOSP Git | Yes | None | No |
| CWE | Yes (download) | N/A | No |

---

## Quick Start: Minimal Viable Data

For immediate curriculum development, we need AT MINIMUM:

1. **20 Android CVEs** with:
   - Actual vulnerable code snippets
   - The patch that fixed them
   - CWE classification
   - Root cause explanation

2. **10 Pattern Families** with:
   - 3-5 instances each
   - 1 holdout for transfer testing

3. **30 Negative Examples**:
   - Secure implementations of the same patterns
   - Explanation of why they're secure

This gives us ~150 core challenges to start V2 training.
