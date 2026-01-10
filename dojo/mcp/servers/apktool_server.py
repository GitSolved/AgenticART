#!/usr/bin/env python3
"""
Apktool MCP Server - APK Decoding and Rebuilding for Android Security Research.

Apktool decodes APKs to their original resource form and smali bytecode,
and can rebuild modified APKs. This is essential for:
- Analyzing AndroidManifest.xml (permissions, components, intent filters)
- Understanding smali bytecode for reverse engineering
- Modifying and repackaging APKs for testing
- Extracting resources (layouts, strings, drawables)

Tools provided:
    - decode: Decode APK to smali + resources
    - get_manifest: Parse and return AndroidManifest.xml
    - get_smali: Get smali code for a specific class
    - search_smali: Search smali bytecode for patterns
    - list_resources: List all decoded resources
    - get_resource: Get specific resource content
    - get_strings: Extract strings.xml for all locales
    - build: Rebuild APK from decoded sources

Prerequisites:
    - Apktool installed and available in PATH
    - Install via: brew install apktool (macOS) or apt install apktool (Linux)

Usage:
    # As standalone server
    python -m dojo.mcp.servers.apktool_server

    # Or import and create programmatically
    from dojo.mcp.servers.apktool_server import create_apktool_server
    mcp = create_apktool_server()
    mcp.run()
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("apktool-mcp")

# Default output directory
DEFAULT_OUTPUT_BASE = Path("/tmp/apktool_output")

# Android namespace for manifest parsing
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def create_apktool_server(
    output_base: Optional[Path] = None,
    apktool_path: str = "apktool",
) -> FastMCP:
    """
    Create an Apktool MCP server instance.

    Args:
        output_base: Base directory for decoded output (default: /tmp/apktool_output)
        apktool_path: Path to apktool binary (default: assumes in PATH)

    Returns:
        Configured FastMCP server instance
    """
    mcp = FastMCP("apktool-security")

    _output_base = output_base or DEFAULT_OUTPUT_BASE
    _output_base.mkdir(parents=True, exist_ok=True)

    def _get_apk_hash(apk_path: str) -> str:
        """Generate a hash for the APK to use as cache key."""
        with open(apk_path, "rb") as f:
            return hashlib.md5(f.read(1024 * 1024)).hexdigest()[:12]

    def _get_output_dir(apk_path: str) -> Path:
        """Get or create output directory for an APK."""
        apk_hash = _get_apk_hash(apk_path)
        apk_name = Path(apk_path).stem
        return _output_base / f"{apk_name}_{apk_hash}_apktool"

    @mcp.tool()
    def decode(
        apk_path: str,
        force: bool = False,
        decode_sources: bool = True,
        decode_resources: bool = True,
    ) -> dict[str, Any]:
        """
        Decode an APK file to smali bytecode and resources.

        This produces:
        - AndroidManifest.xml (decoded, readable XML)
        - smali/ directory with Dalvik bytecode
        - res/ directory with decoded resources
        - original/ directory with original files

        Args:
            apk_path: Path to the APK file to decode
            force: Force re-decoding even if cached
            decode_sources: Decode smali sources (set False for resources-only)
            decode_resources: Decode resources (set False for sources-only)

        Returns:
            Dict with:
                - output_dir: Path to decoded output
                - success: Whether decoding succeeded
                - manifest_path: Path to AndroidManifest.xml
                - stats: Directory structure info
        """
        logger.info(f"Decoding APK: {apk_path}")

        if not os.path.exists(apk_path):
            return {"success": False, "error": f"APK not found: {apk_path}"}

        output_dir = _get_output_dir(apk_path)

        # Check cache
        if output_dir.exists() and not force:
            logger.info(f"Using cached decode: {output_dir}")
            return _get_decode_stats(output_dir)

        # Clean existing output if forcing
        if output_dir.exists():
            shutil.rmtree(output_dir)

        # Build apktool command
        cmd = [
            apktool_path,
            "d",  # decode
            "-o", str(output_dir),
            "-f",  # force overwrite
        ]

        if not decode_sources:
            cmd.append("-s")  # no-src
        if not decode_resources:
            cmd.append("-r")  # no-res

        cmd.append(apk_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,  # 3 minute timeout
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Apktool failed: {result.stderr}",
                }

            return _get_decode_stats(output_dir)

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Decoding timed out (3 min limit)"}
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Apktool not found at '{apktool_path}'. Install with: brew install apktool",
            }
        except Exception as e:
            return {"success": False, "error": f"Exception: {str(e)}"}

    def _get_decode_stats(output_dir: Path) -> dict[str, Any]:
        """Get statistics about decoded output."""
        manifest_path = output_dir / "AndroidManifest.xml"
        smali_dir = output_dir / "smali"
        res_dir = output_dir / "res"

        smali_files = list(smali_dir.rglob("*.smali")) if smali_dir.exists() else []
        res_files = list(res_dir.rglob("*")) if res_dir.exists() else []
        res_files = [f for f in res_files if f.is_file()]

        return {
            "success": True,
            "output_dir": str(output_dir),
            "manifest_path": str(manifest_path) if manifest_path.exists() else None,
            "stats": {
                "smali_files": len(smali_files),
                "resource_files": len(res_files),
                "has_manifest": manifest_path.exists(),
                "has_smali": smali_dir.exists(),
                "has_resources": res_dir.exists(),
            },
        }

    @mcp.tool()
    def get_manifest(
        output_dir: str,
        parse_components: bool = True,
    ) -> dict[str, Any]:
        """
        Get the decoded AndroidManifest.xml with parsed security information.

        This extracts critical security-relevant information:
        - Package name and version
        - Permissions (requested and defined)
        - Exported components (activities, services, receivers, providers)
        - Intent filters (attack surface)
        - Backup and debug flags

        Args:
            output_dir: Path to decoded APK output
            parse_components: Whether to parse and categorize components

        Returns:
            Dict with:
                - raw_xml: Full manifest XML
                - package: Package name
                - permissions: Requested permissions
                - components: Parsed components with export status
                - security_flags: debuggable, allowBackup, etc.
        """
        logger.info(f"Parsing manifest from {output_dir}")

        manifest_path = Path(output_dir) / "AndroidManifest.xml"
        if not manifest_path.exists():
            return {"success": False, "error": f"Manifest not found: {manifest_path}"}

        try:
            raw_xml = manifest_path.read_text()
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # Basic info
            package = root.get("package", "unknown")
            version_code = root.get(f"{ANDROID_NS}versionCode", "unknown")
            version_name = root.get(f"{ANDROID_NS}versionName", "unknown")

            # Permissions
            uses_permissions = []
            for perm in root.findall("uses-permission"):
                name = perm.get(f"{ANDROID_NS}name", "")
                if name:
                    uses_permissions.append(name)

            # Custom permissions defined by app
            defined_permissions = []
            for perm in root.findall("permission"):
                defined_permissions.append({
                    "name": perm.get(f"{ANDROID_NS}name", ""),
                    "protection_level": perm.get(f"{ANDROID_NS}protectionLevel", "normal"),
                })

            # Application flags
            app_elem = root.find("application")
            security_flags = {}
            if app_elem is not None:
                security_flags = {
                    "debuggable": app_elem.get(f"{ANDROID_NS}debuggable", "false") == "true",
                    "allowBackup": app_elem.get(f"{ANDROID_NS}allowBackup", "true") == "true",
                    "usesCleartextTraffic": app_elem.get(f"{ANDROID_NS}usesCleartextTraffic", "false") == "true",
                    "networkSecurityConfig": app_elem.get(f"{ANDROID_NS}networkSecurityConfig"),
                }

            # Components
            components = {"activities": [], "services": [], "receivers": [], "providers": []}

            if parse_components and app_elem is not None:
                for comp_type in ["activity", "service", "receiver", "provider"]:
                    for comp in app_elem.findall(comp_type):
                        name = comp.get(f"{ANDROID_NS}name", "")
                        exported = comp.get(f"{ANDROID_NS}exported")

                        # Parse intent filters
                        intent_filters = []
                        for if_elem in comp.findall("intent-filter"):
                            actions = [a.get(f"{ANDROID_NS}name", "") for a in if_elem.findall("action")]
                            categories = [c.get(f"{ANDROID_NS}name", "") for c in if_elem.findall("category")]
                            data_elems = if_elem.findall("data")
                            data = []
                            for d in data_elems:
                                data.append({
                                    "scheme": d.get(f"{ANDROID_NS}scheme"),
                                    "host": d.get(f"{ANDROID_NS}host"),
                                    "path": d.get(f"{ANDROID_NS}path"),
                                    "pathPrefix": d.get(f"{ANDROID_NS}pathPrefix"),
                                    "mimeType": d.get(f"{ANDROID_NS}mimeType"),
                                })
                            intent_filters.append({
                                "actions": actions,
                                "categories": categories,
                                "data": [d for d in data if any(d.values())],
                            })

                        # Determine effective export status
                        # If exported is not set, it's true if there are intent filters
                        if exported is None:
                            effective_exported = len(intent_filters) > 0
                        else:
                            effective_exported = exported == "true"

                        # For providers, check authorities and permissions
                        extra = {}
                        if comp_type == "provider":
                            extra["authorities"] = comp.get(f"{ANDROID_NS}authorities", "")
                            extra["readPermission"] = comp.get(f"{ANDROID_NS}readPermission")
                            extra["writePermission"] = comp.get(f"{ANDROID_NS}writePermission")
                            extra["grantUriPermissions"] = comp.get(f"{ANDROID_NS}grantUriPermissions", "false") == "true"

                        components[f"{comp_type}s" if comp_type != "activity" else "activities"].append({
                            "name": name,
                            "exported": effective_exported,
                            "explicit_exported": exported,
                            "permission": comp.get(f"{ANDROID_NS}permission"),
                            "intent_filters": intent_filters,
                            **extra,
                        })

            # Count exported components (attack surface)
            exported_count = sum(
                1 for comp_list in components.values()
                for comp in comp_list
                if comp["exported"]
            )

            return {
                "success": True,
                "raw_xml": raw_xml,
                "package": package,
                "version": {"code": version_code, "name": version_name},
                "permissions": {
                    "uses": uses_permissions,
                    "defines": defined_permissions,
                },
                "security_flags": security_flags,
                "components": components,
                "attack_surface": {
                    "exported_components": exported_count,
                    "total_components": sum(len(c) for c in components.values()),
                },
            }

        except ET.ParseError as e:
            return {"success": False, "error": f"XML parse error: {e}", "raw_xml": raw_xml}
        except Exception as e:
            return {"success": False, "error": f"Exception: {str(e)}"}

    @mcp.tool()
    def get_smali(
        output_dir: str,
        class_name: str,
    ) -> dict[str, Any]:
        """
        Get the smali bytecode for a specific class.

        Smali is the human-readable form of Dalvik bytecode. Use this when
        JADX decompilation fails or you need to see the exact bytecode.

        Args:
            output_dir: Path to decoded APK output
            class_name: Fully qualified class name (e.g., "com.example.MainActivity")
                       or simple name (will search)

        Returns:
            Dict with:
                - smali: Full smali bytecode
                - file_path: Path to the smali file
                - methods: List of methods in the class
        """
        logger.info(f"Getting smali for class: {class_name}")

        smali_dir = Path(output_dir) / "smali"
        if not smali_dir.exists():
            return {"success": False, "error": f"Smali directory not found: {smali_dir}"}

        # Convert class name to smali path
        if "." in class_name:
            relative_path = class_name.replace(".", "/") + ".smali"
            target_file = smali_dir / relative_path

            if target_file.exists():
                return _read_smali_file(target_file, smali_dir)

        # Also check smali_classes2, smali_classes3, etc. for multidex
        for smali_subdir in Path(output_dir).glob("smali*"):
            if "." in class_name:
                target_file = smali_subdir / (class_name.replace(".", "/") + ".smali")
                if target_file.exists():
                    return _read_smali_file(target_file, smali_subdir)

        # Search by simple name
        simple_name = class_name.split(".")[-1]
        target_filename = f"{simple_name}.smali"

        candidates = []
        for smali_subdir in Path(output_dir).glob("smali*"):
            candidates.extend(smali_subdir.rglob(target_filename))

        if not candidates:
            return {"success": False, "error": f"Smali class not found: {class_name}"}

        if len(candidates) == 1:
            return _read_smali_file(candidates[0], candidates[0].parent)

        return {
            "success": False,
            "error": "Multiple smali files found with that name",
            "candidates": [str(c) for c in candidates],
        }

    def _read_smali_file(file_path: Path, base_dir: Path) -> dict[str, Any]:
        """Read and parse a smali file."""
        try:
            smali = file_path.read_text()

            # Extract method names
            methods = []
            method_pattern = r"\.method\s+(.*?)\s+(\S+)\("
            for match in re.finditer(method_pattern, smali):
                modifiers = match.group(1)
                name = match.group(2)
                methods.append({"name": name, "modifiers": modifiers})

            # Extract fields
            fields = []
            field_pattern = r"\.field\s+(.*?)\s+(\S+):(\S+)"
            for match in re.finditer(field_pattern, smali):
                modifiers = match.group(1)
                name = match.group(2)
                field_type = match.group(3)
                fields.append({"name": name, "type": field_type, "modifiers": modifiers})

            return {
                "success": True,
                "smali": smali,
                "file_path": str(file_path),
                "methods": methods,
                "fields": fields,
                "line_count": len(smali.splitlines()),
            }

        except Exception as e:
            return {"success": False, "error": f"Error reading smali: {e}"}

    @mcp.tool()
    def search_smali(
        output_dir: str,
        pattern: str,
        max_results: int = 50,
        context_lines: int = 3,
    ) -> dict[str, Any]:
        """
        Search smali bytecode for patterns.

        Useful for finding:
        - Method invocations: "invoke-virtual.*Cipher"
        - String constants: "const-string.*password"
        - Class references: "Lcom/example/SecretClass;"

        Args:
            output_dir: Path to decoded APK output
            pattern: Regex pattern to search for
            max_results: Maximum results to return
            context_lines: Lines of context around matches

        Returns:
            Dict with matches and context
        """
        logger.info(f"Searching smali for pattern: {pattern}")

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return {"success": False, "error": f"Invalid regex: {e}"}

        matches = []
        total_matches = 0

        for smali_dir in Path(output_dir).glob("smali*"):
            for smali_file in smali_dir.rglob("*.smali"):
                try:
                    content = smali_file.read_text(errors="ignore")
                    lines = content.splitlines()

                    for i, line in enumerate(lines):
                        if regex.search(line):
                            total_matches += 1

                            if len(matches) < max_results:
                                start = max(0, i - context_lines)
                                end = min(len(lines), i + context_lines + 1)

                                matches.append({
                                    "file": str(smali_file.relative_to(Path(output_dir))),
                                    "line": i + 1,
                                    "content": line.strip(),
                                    "context": "\n".join(lines[start:end]),
                                })

                except Exception as e:
                    logger.warning(f"Error reading {smali_file}: {e}")
                    continue

        return {
            "success": True,
            "matches": matches,
            "total_matches": total_matches,
            "truncated": total_matches > max_results,
        }

    @mcp.tool()
    def get_strings(
        output_dir: str,
        locale: str = "default",
    ) -> dict[str, Any]:
        """
        Extract string resources from the APK.

        Strings often contain:
        - API endpoints and URLs
        - Error messages revealing logic
        - Hardcoded credentials (bad practice but common)

        Args:
            output_dir: Path to decoded APK output
            locale: Locale to extract ("default", "en", "es", etc.)

        Returns:
            Dict with string name-value pairs
        """
        logger.info(f"Extracting strings for locale: {locale}")

        res_dir = Path(output_dir) / "res"
        if not res_dir.exists():
            return {"success": False, "error": f"Resources not found: {res_dir}"}

        # Find strings.xml
        if locale == "default":
            strings_path = res_dir / "values" / "strings.xml"
        else:
            strings_path = res_dir / f"values-{locale}" / "strings.xml"

        if not strings_path.exists():
            # List available locales
            available = []
            for values_dir in res_dir.glob("values*"):
                if (values_dir / "strings.xml").exists():
                    locale_name = values_dir.name.replace("values-", "").replace("values", "default")
                    available.append(locale_name)

            return {
                "success": False,
                "error": f"strings.xml not found for locale '{locale}'",
                "available_locales": available,
            }

        try:
            tree = ET.parse(strings_path)
            root = tree.getroot()

            strings = {}
            for string_elem in root.findall("string"):
                name = string_elem.get("name", "")
                value = string_elem.text or ""
                strings[name] = value

            # Also get string arrays
            string_arrays = {}
            for array_elem in root.findall("string-array"):
                name = array_elem.get("name", "")
                items = [item.text or "" for item in array_elem.findall("item")]
                string_arrays[name] = items

            return {
                "success": True,
                "locale": locale,
                "strings": strings,
                "string_arrays": string_arrays,
                "string_count": len(strings),
            }

        except ET.ParseError as e:
            return {"success": False, "error": f"XML parse error: {e}"}
        except Exception as e:
            return {"success": False, "error": f"Exception: {str(e)}"}

    @mcp.tool()
    def list_resources(
        output_dir: str,
        resource_type: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        List all decoded resources in the APK.

        Args:
            output_dir: Path to decoded APK output
            resource_type: Filter by type ("layout", "drawable", "xml", "raw", etc.)

        Returns:
            Dict with categorized resource listings
        """
        logger.info(f"Listing resources in {output_dir}")

        res_dir = Path(output_dir) / "res"
        if not res_dir.exists():
            return {"success": False, "error": f"Resources not found: {res_dir}"}

        resources = {}

        for subdir in res_dir.iterdir():
            if not subdir.is_dir():
                continue

            # Parse resource type from directory name (e.g., "drawable-hdpi" -> "drawable")
            dir_name = subdir.name
            res_type = dir_name.split("-")[0]

            if resource_type and res_type != resource_type:
                continue

            if res_type not in resources:
                resources[res_type] = []

            for res_file in subdir.iterdir():
                if res_file.is_file():
                    resources[res_type].append({
                        "name": res_file.name,
                        "path": str(res_file.relative_to(Path(output_dir))),
                        "size": res_file.stat().st_size,
                        "qualifier": dir_name.replace(f"{res_type}-", "") if "-" in dir_name else None,
                    })

        # Sort by type
        for res_type in resources:
            resources[res_type].sort(key=lambda x: x["name"])

        return {
            "success": True,
            "resources": resources,
            "total_files": sum(len(files) for files in resources.values()),
            "resource_types": list(resources.keys()),
        }

    @mcp.tool()
    def build(
        output_dir: str,
        output_apk: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Rebuild an APK from decoded sources.

        After modifying smali or resources, use this to create a new APK.
        Note: The rebuilt APK will need to be signed before installation.

        Args:
            output_dir: Path to decoded APK directory
            output_apk: Output APK path (default: {output_dir}/dist/{name}.apk)

        Returns:
            Dict with:
                - apk_path: Path to rebuilt APK
                - success: Whether build succeeded
        """
        logger.info(f"Building APK from {output_dir}")

        if not Path(output_dir).exists():
            return {"success": False, "error": f"Directory not found: {output_dir}"}

        cmd = [
            apktool_path,
            "b",  # build
            output_dir,
        ]

        if output_apk:
            cmd.extend(["-o", output_apk])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Apktool build failed: {result.stderr}",
                }

            # Find output APK
            if output_apk:
                apk_path = output_apk
            else:
                dist_dir = Path(output_dir) / "dist"
                apks = list(dist_dir.glob("*.apk"))
                apk_path = str(apks[0]) if apks else None

            return {
                "success": True,
                "apk_path": apk_path,
                "message": "APK built successfully. Remember to sign it before installation.",
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Build timed out (3 min limit)"}
        except Exception as e:
            return {"success": False, "error": f"Exception: {str(e)}"}

    @mcp.tool()
    def find_security_issues(
        output_dir: str,
    ) -> dict[str, Any]:
        """
        Automated scan for security issues in manifest and resources.

        Checks for:
        - Debuggable flag enabled
        - Backup allowed without encryption
        - Cleartext traffic permitted
        - Exported components without permissions
        - Dangerous permission requests
        - Hardcoded URLs and IPs

        Args:
            output_dir: Path to decoded APK output

        Returns:
            Dict with categorized security findings
        """
        logger.info(f"Scanning for security issues in {output_dir}")

        findings = []

        # Parse manifest
        manifest_result = get_manifest(output_dir)
        if not manifest_result.get("success"):
            return manifest_result

        # Check security flags
        flags = manifest_result.get("security_flags", {})

        if flags.get("debuggable"):
            findings.append({
                "severity": "critical",
                "category": "configuration",
                "issue": "Application is debuggable",
                "description": "android:debuggable=true allows runtime debugging and memory inspection",
                "recommendation": "Set android:debuggable=false for release builds",
            })

        if flags.get("allowBackup"):
            findings.append({
                "severity": "high",
                "category": "configuration",
                "issue": "Backup allowed",
                "description": "android:allowBackup=true allows ADB backup of app data",
                "recommendation": "Set android:allowBackup=false or implement BackupAgent with encryption",
            })

        if flags.get("usesCleartextTraffic"):
            findings.append({
                "severity": "high",
                "category": "network",
                "issue": "Cleartext traffic permitted",
                "description": "android:usesCleartextTraffic=true allows HTTP connections",
                "recommendation": "Use HTTPS only and set usesCleartextTraffic=false",
            })

        # Check exported components
        components = manifest_result.get("components", {})
        for comp_type, comp_list in components.items():
            for comp in comp_list:
                if comp.get("exported") and not comp.get("permission"):
                    findings.append({
                        "severity": "medium",
                        "category": "exported_component",
                        "issue": f"Exported {comp_type[:-1]} without permission",
                        "component": comp.get("name"),
                        "description": "Component is accessible to other apps without permission check",
                        "recommendation": "Add android:permission attribute or set exported=false",
                    })

        # Check dangerous permissions
        dangerous_permissions = [
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ]

        requested = manifest_result.get("permissions", {}).get("uses", [])
        for perm in requested:
            if perm in dangerous_permissions:
                findings.append({
                    "severity": "info",
                    "category": "permission",
                    "issue": f"Dangerous permission requested: {perm}",
                    "description": "Verify this permission is necessary for app functionality",
                    "recommendation": "Request permissions at runtime and handle denial gracefully",
                })

        # Check strings for hardcoded URLs/IPs
        strings_result = get_strings(output_dir)
        if strings_result.get("success"):
            strings = strings_result.get("strings", {})

            # URL pattern
            url_pattern = re.compile(r'https?://[^\s<>"]+|(\d{1,3}\.){3}\d{1,3}')

            for name, value in strings.items():
                if url_pattern.search(value):
                    findings.append({
                        "severity": "info",
                        "category": "hardcoded_endpoint",
                        "issue": "Hardcoded URL/IP in string resource",
                        "string_name": name,
                        "value": value[:100],
                        "recommendation": "Use build variants or configuration files for endpoints",
                    })

        # Categorize findings
        by_severity = {
            "critical": [f for f in findings if f["severity"] == "critical"],
            "high": [f for f in findings if f["severity"] == "high"],
            "medium": [f for f in findings if f["severity"] == "medium"],
            "info": [f for f in findings if f["severity"] == "info"],
        }

        return {
            "success": True,
            "findings": findings,
            "summary": {
                "total": len(findings),
                "critical": len(by_severity["critical"]),
                "high": len(by_severity["high"]),
                "medium": len(by_severity["medium"]),
                "info": len(by_severity["info"]),
            },
            "by_severity": by_severity,
        }

    return mcp


# Standalone execution
if __name__ == "__main__":
    server = create_apktool_server()
    server.run()
