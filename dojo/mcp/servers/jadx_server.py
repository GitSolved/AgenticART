#!/usr/bin/env python3
"""
JADX MCP Server - Java Decompilation for Android Security Research.

JADX is a DEX to Java decompiler that produces readable Java source code
from Android APK files. This MCP server wraps JADX CLI functionality.

Tools provided:
    - decompile: Decompile APK/DEX to Java source
    - search_code: Search decompiled source for patterns
    - get_class: Retrieve source code for a specific class
    - list_classes: List all decompiled classes
    - get_method: Extract a specific method's source

Prerequisites:
    - JADX installed and available in PATH
    - Install via: brew install jadx (macOS) or apt install jadx (Linux)

Usage:
    # As standalone server
    python -m dojo.mcp.servers.jadx_server

    # Or import and create programmatically
    from dojo.mcp.servers.jadx_server import create_jadx_server
    mcp = create_jadx_server()
    mcp.run()
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("jadx-mcp")

# Default output directory for decompiled sources
DEFAULT_OUTPUT_BASE = Path("/tmp/jadx_output")


def create_jadx_server(
    output_base: Optional[Path] = None,
    jadx_path: str = "jadx",
) -> FastMCP:
    """
    Create a JADX MCP server instance.

    Args:
        output_base: Base directory for decompiled output (default: /tmp/jadx_output)
        jadx_path: Path to JADX binary (default: assumes in PATH)

    Returns:
        Configured FastMCP server instance
    """
    mcp = FastMCP("jadx-security")

    _output_base = output_base or DEFAULT_OUTPUT_BASE
    _output_base.mkdir(parents=True, exist_ok=True)

    # Cache of decompiled APKs: {apk_hash: output_dir}
    _decompile_cache: dict[str, Path] = {}

    def _get_apk_hash(apk_path: str) -> str:
        """Generate a hash for the APK to use as cache key."""
        with open(apk_path, "rb") as f:
            # Read first 1MB for faster hashing
            return hashlib.md5(f.read(1024 * 1024)).hexdigest()[:12]

    def _get_output_dir(apk_path: str) -> Path:
        """Get or create output directory for an APK."""
        apk_hash = _get_apk_hash(apk_path)
        apk_name = Path(apk_path).stem
        return _output_base / f"{apk_name}_{apk_hash}"

    @mcp.tool()
    def decompile(
        apk_path: str,
        force: bool = False,
        deobfuscate: bool = True,
        show_bad_code: bool = True,
        threads: int = 4,
    ) -> dict[str, Any]:
        """
        Decompile an APK or DEX file to Java source code.

        This is typically the first step in static analysis. The decompiled
        output is cached, so subsequent calls with the same APK are fast.

        Args:
            apk_path: Path to the APK or DEX file to decompile
            force: Force re-decompilation even if cached
            deobfuscate: Enable deobfuscation (rename obfuscated names)
            show_bad_code: Include decompilation errors as comments
            threads: Number of processing threads

        Returns:
            Dict with:
                - output_dir: Path to decompiled sources
                - success: Whether decompilation succeeded
                - stats: File counts and package info
                - error: Error message if failed
        """
        logger.info(f"Decompiling APK: {apk_path}")

        if not os.path.exists(apk_path):
            return {"success": False, "error": f"APK not found: {apk_path}"}

        output_dir = _get_output_dir(apk_path)

        # Check cache
        if output_dir.exists() and not force:
            logger.info(f"Using cached decompilation: {output_dir}")
            return _get_decompile_stats(output_dir)

        # Clean existing output if forcing
        if output_dir.exists():
            shutil.rmtree(output_dir)

        # Build JADX command
        cmd = [
            jadx_path,
            "-d", str(output_dir),
            "-j", str(threads),
        ]

        if deobfuscate:
            cmd.append("--deobf")
        if show_bad_code:
            cmd.append("--show-bad-code")

        cmd.append(apk_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"JADX failed: {result.stderr}",
                    "output_dir": str(output_dir),
                }

            return _get_decompile_stats(output_dir)

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Decompilation timed out (5 min limit)"}
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"JADX not found at '{jadx_path}'. Install with: brew install jadx",
            }
        except Exception as e:
            return {"success": False, "error": f"Exception: {str(e)}"}

    def _get_decompile_stats(output_dir: Path) -> dict[str, Any]:
        """Get statistics about decompiled output."""
        sources_dir = output_dir / "sources"
        resources_dir = output_dir / "resources"

        java_files = list(sources_dir.rglob("*.java")) if sources_dir.exists() else []

        # Extract package structure
        packages = set()
        for jf in java_files:
            rel_path = jf.relative_to(sources_dir)
            if len(rel_path.parts) > 1:
                packages.add(".".join(rel_path.parts[:-1]))

        return {
            "success": True,
            "output_dir": str(output_dir),
            "stats": {
                "java_files": len(java_files),
                "packages": len(packages),
                "top_packages": sorted(packages)[:20],
                "has_resources": resources_dir.exists(),
            },
        }

    @mcp.tool()
    def search_code(
        output_dir: str,
        pattern: str,
        file_pattern: str = "*.java",
        max_results: int = 50,
        context_lines: int = 3,
    ) -> dict[str, Any]:
        """
        Search decompiled source code for a pattern.

        Use this to find security-relevant code patterns like:
        - SQL queries: "rawQuery|execSQL"
        - Crypto usage: "Cipher|SecretKey|AES"
        - File operations: "FileOutputStream|openFileOutput"
        - Network: "HttpURLConnection|OkHttp"
        - WebView: "setJavaScriptEnabled|addJavascriptInterface"

        Args:
            output_dir: Path to decompiled output (from decompile())
            pattern: Regex pattern to search for
            file_pattern: Glob pattern for files to search (default: *.java)
            max_results: Maximum number of results to return
            context_lines: Lines of context around each match

        Returns:
            Dict with:
                - matches: List of {file, line, content, context}
                - total_matches: Total matches found
                - truncated: Whether results were truncated
        """
        logger.info(f"Searching for pattern '{pattern}' in {output_dir}")

        sources_dir = Path(output_dir) / "sources"
        if not sources_dir.exists():
            return {"success": False, "error": f"Sources not found: {sources_dir}"}

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return {"success": False, "error": f"Invalid regex: {e}"}

        matches = []
        total_matches = 0

        for java_file in sources_dir.rglob(file_pattern):
            try:
                content = java_file.read_text(errors="ignore")
                lines = content.splitlines()

                for i, line in enumerate(lines):
                    if regex.search(line):
                        total_matches += 1

                        if len(matches) < max_results:
                            # Get context
                            start = max(0, i - context_lines)
                            end = min(len(lines), i + context_lines + 1)
                            context = lines[start:end]

                            matches.append({
                                "file": str(java_file.relative_to(sources_dir)),
                                "line": i + 1,
                                "content": line.strip(),
                                "context": "\n".join(context),
                            })

            except Exception as e:
                logger.warning(f"Error reading {java_file}: {e}")
                continue

        return {
            "success": True,
            "matches": matches,
            "total_matches": total_matches,
            "truncated": total_matches > max_results,
        }

    @mcp.tool()
    def get_class(
        output_dir: str,
        class_name: str,
        include_imports: bool = True,
    ) -> dict[str, Any]:
        """
        Retrieve the full source code of a specific Java class.

        Use this after search_code() identifies interesting classes,
        or to examine classes referenced in the manifest.

        Args:
            output_dir: Path to decompiled output
            class_name: Fully qualified class name (e.g., "com.example.MainActivity")
                       or simple name (will search all packages)
            include_imports: Include import statements in output

        Returns:
            Dict with:
                - source: Full Java source code
                - file_path: Path to the source file
                - class_info: Extracted class metadata
        """
        logger.info(f"Getting class: {class_name}")

        sources_dir = Path(output_dir) / "sources"
        if not sources_dir.exists():
            return {"success": False, "error": f"Sources not found: {sources_dir}"}

        # Convert class name to file path
        if "." in class_name:
            # Fully qualified name
            relative_path = class_name.replace(".", "/") + ".java"
            target_file = sources_dir / relative_path

            if target_file.exists():
                return _read_class_file(target_file, sources_dir, include_imports)

        # Search for the class by simple name
        simple_name = class_name.split(".")[-1]
        target_filename = f"{simple_name}.java"

        candidates = list(sources_dir.rglob(target_filename))

        if not candidates:
            return {"success": False, "error": f"Class not found: {class_name}"}

        if len(candidates) == 1:
            return _read_class_file(candidates[0], sources_dir, include_imports)

        # Multiple matches - return list for user to choose
        return {
            "success": False,
            "error": "Multiple classes found with that name",
            "candidates": [str(c.relative_to(sources_dir)) for c in candidates],
        }

    def _read_class_file(
        file_path: Path,
        sources_dir: Path,
        include_imports: bool,
    ) -> dict[str, Any]:
        """Read and parse a Java class file."""
        try:
            source = file_path.read_text(errors="ignore")

            # Extract class metadata
            class_info: dict[str, Any] = {
                "package": None,
                "imports": [],
                "class_type": "class",
                "modifiers": [],
                "extends": None,
                "implements": [],
                "methods": [],
                "fields": [],
            }

            # Parse package
            pkg_match = re.search(r"^package\s+([\w.]+);", source, re.MULTILINE)
            if pkg_match:
                class_info["package"] = pkg_match.group(1)

            # Parse imports
            import_matches = re.findall(r"^import\s+([\w.*]+);", source, re.MULTILINE)
            class_info["imports"] = import_matches

            # Parse class declaration
            class_match = re.search(
                r"(public|private|protected)?\s*(abstract|final)?\s*(class|interface|enum)\s+(\w+)"
                r"(?:\s+extends\s+([\w.]+))?"
                r"(?:\s+implements\s+([\w.,\s]+))?",
                source
            )
            if class_match:
                if class_match.group(1):
                    class_info["modifiers"].append(class_match.group(1))
                if class_match.group(2):
                    class_info["modifiers"].append(class_match.group(2))
                class_info["class_type"] = class_match.group(3)
                class_info["extends"] = class_match.group(5)
                if class_match.group(6):
                    class_info["implements"] = [
                        i.strip() for i in class_match.group(6).split(",")
                    ]

            # Parse method signatures (simplified)
            method_pattern = r"(public|private|protected)?\s*(static)?\s*([\w<>,\s\[\]]+)\s+(\w+)\s*\([^)]*\)"
            method_matches = re.findall(method_pattern, source)
            class_info["methods"] = [
                {"name": m[3], "return_type": m[2].strip(), "modifiers": [x for x in m[:2] if x]}
                for m in method_matches
            ][:50]  # Limit to 50 methods

            output_source = source
            if not include_imports:
                # Remove import section
                output_source = re.sub(r"^import\s+[\w.*]+;\n", "", source, flags=re.MULTILINE)

            return {
                "success": True,
                "source": output_source,
                "file_path": str(file_path.relative_to(sources_dir)),
                "class_info": class_info,
            }

        except Exception as e:
            return {"success": False, "error": f"Error reading class: {e}"}

    @mcp.tool()
    def list_classes(
        output_dir: str,
        package_filter: Optional[str] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """
        List all decompiled classes, optionally filtered by package.

        Useful for understanding app structure before diving into specific classes.

        Args:
            output_dir: Path to decompiled output
            package_filter: Only show classes in this package (e.g., "com.example")
            limit: Maximum number of classes to return

        Returns:
            Dict with:
                - classes: List of {name, package, file_path}
                - total_classes: Total count
                - packages: Unique packages found
        """
        logger.info(f"Listing classes in {output_dir}")

        sources_dir = Path(output_dir) / "sources"
        if not sources_dir.exists():
            return {"success": False, "error": f"Sources not found: {sources_dir}"}

        classes = []
        packages = set()

        for java_file in sources_dir.rglob("*.java"):
            rel_path = java_file.relative_to(sources_dir)
            parts = rel_path.parts

            if len(parts) > 1:
                package = ".".join(parts[:-1])
                class_name = parts[-1].replace(".java", "")
                full_name = f"{package}.{class_name}"
            else:
                package = "(default)"
                class_name = parts[0].replace(".java", "")
                full_name = class_name

            # Apply package filter
            if package_filter and not package.startswith(package_filter):
                continue

            packages.add(package)

            if len(classes) < limit:
                classes.append({
                    "name": class_name,
                    "full_name": full_name,
                    "package": package,
                    "file_path": str(rel_path),
                })

        return {
            "success": True,
            "classes": classes,
            "total_classes": len(list(sources_dir.rglob("*.java"))),
            "packages": sorted(packages),
            "truncated": len(classes) >= limit,
        }

    @mcp.tool()
    def get_method(
        output_dir: str,
        class_name: str,
        method_name: str,
    ) -> dict[str, Any]:
        """
        Extract a specific method's source code from a class.

        Useful for focused analysis of security-relevant methods like
        onClick handlers, network callbacks, or crypto operations.

        Args:
            output_dir: Path to decompiled output
            class_name: Fully qualified or simple class name
            method_name: Name of the method to extract

        Returns:
            Dict with:
                - method_source: The method's source code
                - signature: Method signature
                - start_line: Line number where method starts
        """
        logger.info(f"Getting method {method_name} from {class_name}")

        # First get the full class
        class_result = get_class(output_dir, class_name)
        if not class_result.get("success"):
            return class_result

        source = class_result["source"]
        lines = source.splitlines()

        # Find method start - look for method signature
        method_pattern = rf"(public|private|protected)?\s*(static)?\s*[\w<>,\s\[\]]+\s+{re.escape(method_name)}\s*\("

        method_start = None
        for i, line in enumerate(lines):
            if re.search(method_pattern, line):
                method_start = i
                break

        if method_start is None:
            return {
                "success": False,
                "error": f"Method '{method_name}' not found in class",
                "available_methods": [m["name"] for m in class_result["class_info"]["methods"]],
            }

        # Find method end by counting braces
        brace_count = 0
        method_end = method_start
        started = False

        for i in range(method_start, len(lines)):
            line = lines[i]
            brace_count += line.count("{") - line.count("}")

            if "{" in line:
                started = True

            if started and brace_count == 0:
                method_end = i
                break

        method_lines = lines[method_start:method_end + 1]

        return {
            "success": True,
            "method_source": "\n".join(method_lines),
            "signature": lines[method_start].strip(),
            "start_line": method_start + 1,
            "end_line": method_end + 1,
            "class_name": class_name,
        }

    @mcp.tool()
    def find_security_patterns(
        output_dir: str,
    ) -> dict[str, Any]:
        """
        Automated scan for common security-relevant code patterns.

        This performs multiple searches for patterns commonly associated
        with Android security vulnerabilities. Use this as a starting
        point for manual analysis.

        Args:
            output_dir: Path to decompiled output

        Returns:
            Dict with findings organized by category
        """
        logger.info(f"Scanning for security patterns in {output_dir}")

        patterns = {
            "sql_injection": {
                "pattern": r"(rawQuery|execSQL|query)\s*\(",
                "severity": "high",
                "description": "Potential SQL injection if user input is concatenated",
            },
            "hardcoded_secrets": {
                "pattern": r'(password|secret|api_key|apikey|token)\s*=\s*["\'][^"\']+["\']',
                "severity": "high",
                "description": "Hardcoded secrets in source code",
            },
            "insecure_webview": {
                "pattern": r"setJavaScriptEnabled\s*\(\s*true\s*\)|addJavascriptInterface",
                "severity": "medium",
                "description": "WebView with JavaScript enabled or JS interface",
            },
            "insecure_network": {
                "pattern": r"http://|setHostnameVerifier|AllowAllHostnameVerifier|ALLOW_ALL",
                "severity": "medium",
                "description": "Cleartext traffic or disabled certificate validation",
            },
            "weak_crypto": {
                "pattern": r'(DES|MD5|SHA1)["\s]|ECB|NoPadding',
                "severity": "medium",
                "description": "Weak cryptographic algorithms or modes",
            },
            "intent_injection": {
                "pattern": r"getIntent\(\)\.get.*\(\)|parseUri",
                "severity": "medium",
                "description": "Intent data used without validation",
            },
            "file_operations": {
                "pattern": r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|openFileOutput",
                "severity": "medium",
                "description": "File operations with potential permission issues",
            },
            "logging_sensitive": {
                "pattern": r'Log\.(d|i|v|w|e)\s*\([^,]+,\s*[^)]*(?:password|token|secret|key)',
                "severity": "low",
                "description": "Potentially sensitive data in logs",
            },
            "exported_components": {
                "pattern": r'exported\s*=\s*["\']?true',
                "severity": "info",
                "description": "Exported components (check for authorization)",
            },
        }

        findings = {}

        for category, config in patterns.items():
            result = search_code(
                output_dir=output_dir,
                pattern=config["pattern"],
                max_results=20,
            )

            if result.get("success") and result.get("total_matches", 0) > 0:
                findings[category] = {
                    "severity": config["severity"],
                    "description": config["description"],
                    "count": result["total_matches"],
                    "samples": result["matches"][:5],  # First 5 samples
                }

        return {
            "success": True,
            "findings": findings,
            "categories_found": len(findings),
            "high_severity": sum(1 for f in findings.values() if f["severity"] == "high"),
            "medium_severity": sum(1 for f in findings.values() if f["severity"] == "medium"),
        }

    return mcp


# Standalone execution
if __name__ == "__main__":
    server = create_jadx_server()
    server.run()
