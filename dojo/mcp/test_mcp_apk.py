#!/usr/bin/env python3
"""
Test MCP servers with a real APK file.

This script demonstrates the full MCP integration by:
1. Decoding an APK with Apktool
2. Decompiling with JADX
3. Searching for security patterns
4. Analyzing the manifest
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dojo.mcp import MCPExecutor

APK_PATH = Path(__file__).parent.parent / "targets/vulnerable_apks/cryptovault/app/build/outputs/apk/debug/app-debug.apk"


async def test_apktool(executor: MCPExecutor, apk_path: str) -> str:
    """Test Apktool MCP server. Returns output_dir for chaining."""
    print("\n" + "="*60)
    print("APKTOOL TESTS")
    print("="*60)

    output_dir = None

    # Test 1: Decode APK
    print("\n[1] Decoding APK...")
    result = await executor.execute_tool("decode", {"apk_path": apk_path})
    if result.success:
        output = result.output
        output_dir = output.get('output_dir')
        print(f"    ✓ Decoded to: {output_dir}")
        stats = output.get('stats', {})
        print(f"    ✓ Smali files: {stats.get('smali_files', 0)}")
        print(f"    ✓ Resource files: {stats.get('resource_files', 0)}")
        print(f"    ✓ Time: {result.execution_time_ms}ms")
    else:
        print(f"    ✗ Error: {result.error}")
        return None

    # Test 2: Get Manifest (uses output_dir from decode)
    print("\n[2] Analyzing AndroidManifest.xml...")
    result = await executor.execute_tool("get_manifest", {"output_dir": output_dir})
    if result.success:
        manifest = result.output
        print(f"    ✓ Package: {manifest.get('package', 'unknown')}")
        version = manifest.get('version', {})
        print(f"    ✓ Version: {version.get('name', 'unknown')} (code: {version.get('code', '?')})")

        # Security flags
        security = manifest.get("security_flags", {})
        print(f"    ✓ Debuggable: {security.get('debuggable', False)}")
        print(f"    ✓ Allow Backup: {security.get('allowBackup', True)}")
        print(f"    ✓ Cleartext Traffic: {security.get('usesCleartextTraffic', False)}")

        # Permissions (dict with 'uses' and 'defines')
        perms_data = manifest.get("permissions", {})
        uses_perms = perms_data.get("uses", [])
        print(f"    ✓ Uses Permissions ({len(uses_perms)}):")
        for p in uses_perms[:5]:
            print(f"      - {p.split('.')[-1]}")
        if len(uses_perms) > 5:
            print(f"      ... and {len(uses_perms) - 5} more")

        # Components breakdown
        components = manifest.get("components", {})
        print("    ✓ Components:")
        for comp_type in ["activities", "services", "receivers", "providers"]:
            comp_list = components.get(comp_type, [])
            exported_count = sum(1 for c in comp_list if c.get("exported"))
            print(f"      - {comp_type}: {len(comp_list)} ({exported_count} exported)")

        # Attack surface
        attack_surface = manifest.get("attack_surface", {})
        print(f"    ✓ Attack Surface: {attack_surface.get('total_exported', 0)} exported components")
    else:
        print(f"    ✗ Error: {result.error}")

    # Test 3: Get strings (uses output_dir from decode)
    print("\n[3] Extracting strings.xml...")
    result = await executor.execute_tool("get_strings", {"output_dir": output_dir})
    if result.success:
        strings_data = result.output
        locales = strings_data.get("locales", [])
        print(f"    ✓ Locales found: {locales}")

        default_strings = strings_data.get("strings", {}).get("default", {})
        print(f"    ✓ Default strings: {len(default_strings)} entries")

        # Show a few strings
        for key, value in list(default_strings.items())[:5]:
            val_str = str(value)[:50]
            print(f"      - {key}: {val_str}{'...' if len(str(value)) > 50 else ''}")
    else:
        print(f"    ✗ Error: {result.error}")

    # Test 4: Find security issues (uses output_dir from decode)
    print("\n[4] Scanning for security issues...")
    result = await executor.execute_tool("find_security_issues", {"output_dir": output_dir})
    if result.success:
        issues = result.output
        print(f"    ✓ Risk Level: {issues.get('risk_level', 'unknown')}")
        print("    ✓ Issues Found:")
        for issue in issues.get("issues", []):
            desc = issue.get('description', '?')[:60]
            print(f"      [{issue.get('severity', '?')}] {issue.get('type', '?')}: {desc}")
    else:
        print(f"    ✗ Error: {result.error}")

    return output_dir


async def test_jadx(executor: MCPExecutor, apk_path: str):
    """Test JADX MCP server."""
    print("\n" + "="*60)
    print("JADX TESTS")
    print("="*60)

    output_dir = None

    # Test 1: Decompile APK
    print("\n[1] Decompiling APK (this may take a moment)...")
    result = await executor.execute_tool("decompile", {"apk_path": apk_path})
    if result.success:
        output = result.output
        output_dir = output.get('output_dir')
        print(f"    ✓ Output dir: {output_dir}")
        stats = output.get('stats', {})
        print(f"    ✓ Java files: {stats.get('java_files', 0)}")
        print(f"    ✓ Packages: {stats.get('packages', 0)}")
        print(f"    ✓ Time: {result.execution_time_ms}ms")
    else:
        print(f"    ✗ Error: {result.error}")
        return

    # Test 2: List classes (uses output_dir)
    print("\n[2] Listing classes...")
    result = await executor.execute_tool("list_classes", {"output_dir": output_dir})
    if result.success:
        classes = result.output.get("classes", [])
        print(f"    ✓ Total classes: {len(classes)}")
        print("    ✓ Sample classes:")
        for cls in classes[:5]:
            print(f"      - {cls}")
    else:
        print(f"    ✗ Error: {result.error}")

    # Test 3: Search for crypto patterns (uses output_dir)
    print("\n[3] Searching for crypto usage...")
    result = await executor.execute_tool("search_code", {
        "output_dir": output_dir,
        "pattern": "Cipher|SecretKey|AES|DES|encrypt|decrypt"
    })
    if result.success:
        matches = result.output.get("matches", [])
        total = result.output.get("total_matches", len(matches))
        print(f"    ✓ Found {total} matches (showing {len(matches)})")
        for match in matches[:5]:
            fname = match.get('file', '?').split('/')[-1]
            print(f"      - {fname}:{match.get('line', '?')}")
            print(f"        {match.get('content', '?')[:70]}")
    else:
        print(f"    ✗ Error: {result.error}")

    # Test 4: Find security patterns (uses output_dir)
    print("\n[4] Finding security patterns...")
    result = await executor.execute_tool("find_security_patterns", {"output_dir": output_dir})
    if result.success:
        patterns = result.output
        print("    ✓ Security scan complete:")
        for pattern_type, findings in patterns.items():
            if pattern_type == "success":
                continue
            if isinstance(findings, list) and findings:
                print(f"      [{pattern_type}]: {len(findings)} findings")
                for finding in findings[:2]:
                    if isinstance(finding, dict):
                        fname = finding.get('file', '?').split('/')[-1]
                        print(f"        - {fname}:{finding.get('line', '?')}")
            elif isinstance(findings, list):
                print(f"      [{pattern_type}]: 0 findings")
    else:
        print(f"    ✗ Error: {result.error}")

    # Test 5: Get a specific class (uses output_dir)
    print("\n[5] Getting MainActivity source...")
    result = await executor.execute_tool("get_class", {
        "output_dir": output_dir,
        "class_name": "MainActivity"
    })
    if result.success:
        source = result.output.get("source", "")
        if source:
            lines = source.split("\n")
            print(f"    ✓ Found class ({len(lines)} lines)")
            print("    ✓ Preview:")
            for line in lines[:10]:
                print(f"      {line}")
            if len(lines) > 10:
                print(f"      ... ({len(lines) - 10} more lines)")
        else:
            print(f"    ✓ Class found at: {result.output.get('file_path', 'unknown')}")
    else:
        print(f"    ✗ Error: {result.error}")


async def main():
    print("="*60)
    print("MCP SERVER INTEGRATION TEST")
    print("="*60)
    print(f"APK: {APK_PATH}")
    print(f"Exists: {APK_PATH.exists()}")

    if not APK_PATH.exists():
        print("ERROR: APK file not found!")
        return

    # Initialize executor
    print("\nInitializing MCP Executor...")
    executor = MCPExecutor()
    await executor.initialize()

    status = executor.get_status()
    print(f"Servers: {status['servers']}")
    print(f"Tools: {len(status['available_tools'])} available")

    apk_path = str(APK_PATH)

    try:
        # Run Apktool tests
        await test_apktool(executor, apk_path)

        # Run JADX tests
        await test_jadx(executor, apk_path)

        print("\n" + "="*60)
        print("TEST COMPLETE")
        print("="*60)

    finally:
        await executor.shutdown()
        print("\nExecutor shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
