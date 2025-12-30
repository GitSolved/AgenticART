# CVE Version Targeting in AgenticART

## The Problem

Testing CVE-2014-0537 (Adobe Flash Player) on Android 11 is meaningless because:
1. Flash Player was removed from Android in ~2012
2. The vulnerability literally cannot exist on Android 11
3. A "pass" proves nothing about model capability

This breaks triangulated verification - the OS successfully runs the command, but we're not testing anything real.

## Solution: Version-Targeted Challenges

### Schema Addition

Every CVE challenge should specify version constraints:

```yaml
- id: yellow_cve_2014_0537
  name: "CVE Analysis: CVE-2014-0537"

  # NEW: Version targeting
  version_constraints:
    min_api: 14          # Android 4.0
    max_api: 18          # Android 4.3 (last Flash support)
    affected_packages:
      - com.adobe.flashplayer
      - com.adobe.air
    notes: "Flash Player removed from Android after 4.3"

  # Existing fields...
  inputs:
    cve_id: CVE-2014-0537
```

### Version Constraint Fields

| Field | Type | Description |
|-------|------|-------------|
| `min_api` | int | Minimum Android API level affected |
| `max_api` | int | Maximum Android API level affected |
| `affected_packages` | list | Packages that must be present for vulnerability |
| `affected_components` | list | System components (kernel, binder, etc.) |
| `kernel_versions` | list | Specific kernel versions affected |
| `notes` | string | Human-readable context |

### Example Mappings

| CVE | Affected Android | API Range | Required Package |
|-----|------------------|-----------|------------------|
| CVE-2014-0537 | 4.0-4.3 | 14-18 | com.adobe.flashplayer |
| CVE-2019-2215 | 8.0-10 | 26-29 | (kernel binder) |
| CVE-2021-1024 | 12 | 31 | (system) |
| CVE-2022-20116 | 12-12L | 31-32 | com.android.systemui |
| CVE-2023-21445 | 11-13 | 30-33 | com.samsung.android.app.myfiles |

### Challenge Runner Logic

```python
def should_run_challenge(challenge: Challenge, device: Device) -> bool:
    """Determine if challenge is applicable to connected device."""

    constraints = challenge.get("version_constraints", {})

    # Check API level
    min_api = constraints.get("min_api", 1)
    max_api = constraints.get("max_api", 999)
    if not (min_api <= device.api_level <= max_api):
        return False

    # Check required packages
    affected_packages = constraints.get("affected_packages", [])
    for pkg in affected_packages:
        if pkg not in device.installed_packages:
            return False

    return True
```

### Categories by Android Version

#### Android 11 (API 30) Relevant CVEs
- CVE-2021-0314: Privilege escalation in Settings
- CVE-2021-0327: Bypass in AccountManager
- CVE-2021-0391: Info disclosure in Bluetooth
- CVE-2021-0397: RCE in System
- CVE-2021-1024: Intent redirection (Android 12 but backported patches)

#### Android 12+ (API 31+) Relevant CVEs
- CVE-2022-20116: SystemUI intent redirection
- CVE-2022-20007: Privilege escalation
- CVE-2023-21036: Pixel Markup screenshot vulnerability

#### Legacy (Testing Methodology Only)
- CVE-2014-* (Flash): Can't test on modern Android, teaches methodology only
- CVE-2016-* (Stagefright): Mostly patched, methodology focus

## Implementation Plan

### Phase 1: Tag Existing CVEs
Add `version_constraints` to all CVE challenges with:
- Accurate API ranges from NVD/Android Security Bulletins
- Required packages where applicable

### Phase 2: Update Challenge Runner
Modify `dojo/curriculum/executor.py` to:
1. Query device API level: `getprop ro.build.version.sdk`
2. Query installed packages: `pm list packages`
3. Filter challenges before execution

### Phase 3: Generate Version-Appropriate CVEs
Use NVD API to generate CVEs filtered by:
- Connected device's Android version
- Installed packages
- Known patch level (from `ro.build.version.security_patch`)

## Security Patch Level Awareness

Android devices report their security patch level:
```bash
adb shell getprop ro.build.version.security_patch
# Example: 2023-12-01
```

CVEs patched before this date should be marked as "likely patched" but still testable for methodology validation.

```yaml
version_constraints:
  min_api: 30
  max_api: 33
  patched_after: "2023-06-01"  # Challenge may not work if device patched after this
```

## Summary

| Without Versioning | With Versioning |
|--------------------|-----------------|
| Test Flash CVE on Android 11 | Skip incompatible challenges |
| "Pass" proves syntax only | "Pass" proves real capability |
| Meaningless success metrics | Accurate success metrics |
| Model learns bad patterns | Model learns version-aware probing |
