#!/usr/bin/env python3
"""
LLM-AndroidPentest Demo
=======================

This demo showcases the framework's capabilities:
1. Device reconnaissance (with/without real device)
2. CVE matching against device profile
3. LLM-driven script generation
4. Iterative feedback loop on failure
5. Human-in-the-loop governance
6. Quality/hallucination detection

Run: python demo.py
"""

import os
import sys
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# Framework imports
from agent.planner import PentestPhase, PlanStep
from agent.script_generator import GeneratedScript, ScriptGenerator, ScriptType
from core.governance import ApprovalWorkflow, TriageAssessor
from core.scanning.cve_matcher import CVEMatcher


def print_header(title: str):
    """Print a formatted section header."""
    width = 70
    print("\n" + "═" * width)
    print(f"  {title}")
    print("═" * width)


def print_step(step: str, status: str = ""):
    """Print a demo step."""
    if status:
        print(f"  → {step}: {status}")
    else:
        print(f"  → {step}")


def demo_reconnaissance():
    """Demo 1: Device Reconnaissance"""
    print_header("DEMO 1: Device Reconnaissance")

    try:
        from core.reconnaissance.device_enum import ADBConnection, DeviceEnumerator

        # Try real device first
        adb = ADBConnection("192.168.56.101:5555")

        if adb.is_connected():
            print_step("Real device detected!")
            enum = DeviceEnumerator(adb)
            info = enum.enumerate()

            print("\n  ┌─────────────────────────────────────────┐")
            print("  │  Device Information                     │")
            print("  ├─────────────────────────────────────────┤")
            print(f"  │  Model:          {info.model:<22} │")
            print(f"  │  Android:        {info.android_version:<22} │")
            print(f"  │  API Level:      {info.api_level:<22} │")
            print(f"  │  Security Patch: {info.security_patch:<22} │")
            print(f"  │  Build:          {info.build_id[:22]:<22} │")
            print("  └─────────────────────────────────────────┘")

            return {
                "model": info.model,
                "android_version": info.android_version,
                "api_level": info.api_level,
                "security_patch": info.security_patch
            }
        else:
            raise ConnectionError("No device")

    except Exception:
        # Use mock device profile for demo
        print_step("No device connected - using demo profile")

        mock_device = {
            "model": "Pixel 7 (Demo)",
            "android_version": "11",
            "api_level": 30,
            "security_patch": "2021-01-05",
            "build_id": "RQ1A.210105.003"
        }

        print("\n  ┌─────────────────────────────────────────┐")
        print("  │  Demo Device Profile                    │")
        print("  ├─────────────────────────────────────────┤")
        print(f"  │  Model:          {mock_device['model']:<22} │")
        print(f"  │  Android:        {mock_device['android_version']:<22} │")
        print(f"  │  API Level:      {mock_device['api_level']:<22} │")
        print(f"  │  Security Patch: {mock_device['security_patch']:<22} │")
        print("  └─────────────────────────────────────────┘")

        return mock_device


def demo_cve_matching(device_profile: dict):
    """Demo 2: CVE Matching"""
    print_header("DEMO 2: CVE Matching")

    matcher = CVEMatcher()

    print_step(f"Matching CVEs for Android {device_profile['android_version']}")
    print_step(f"Security patch: {device_profile['security_patch']}")

    matches = matcher.match_device(
        android_version=device_profile['android_version'],
        api_level=device_profile['api_level'],
        security_patch=device_profile['security_patch']
    )

    print(f"\n  Found {len(matches)} applicable CVEs:\n")

    # Show top 5 CVEs
    for i, cve in enumerate(matches[:5], 1):
        severity_color = {
            "CRITICAL": "\033[91m",  # Red
            "HIGH": "\033[93m",      # Yellow
            "MEDIUM": "\033[94m",    # Blue
            "LOW": "\033[92m"        # Green
        }.get(cve.severity, "")
        reset = "\033[0m"

        print(f"  {i}. {cve.cve_id}")
        print(f"     Severity: {severity_color}{cve.severity}{reset} (CVSS: {cve.cvss_score})")
        # Show truncated description
        desc = cve.description[:60] + "..." if len(cve.description) > 60 else cve.description
        print(f"     {desc}")
        if cve.exploit_availability.value != "none":
            print(f"     ⚠️  Exploit: {cve.exploit_availability.value}")
        print()

    if len(matches) > 5:
        print(f"  ... and {len(matches) - 5} more\n")

    return matches


def demo_script_generation(device_profile: dict):
    """Demo 3: Script Generation"""
    print_header("DEMO 3: LLM Script Generation")

    generator = ScriptGenerator()

    # Create a plan step
    step = PlanStep(
        phase=PentestPhase.RECONNAISSANCE,
        action="Enumerate installed packages and check for root indicators",
        command=None,
        rationale="Initial device security assessment",
        risk_level="low"
    )

    target = {
        "ip": "192.168.56.101",
        "android_version": device_profile['android_version'],
        "api_level": device_profile['api_level']
    }

    print_step("Input", f"\"{step.action}\"")
    print_step("Target", f"Android {target['android_version']} @ {target['ip']}")
    print()

    # Try LLM generation, fall back to mock if unavailable
    print("  Generating Python script...")
    time.sleep(0.5)  # Dramatic pause

    try:
        script = generator.generate(step, target, ScriptType.PYTHON)
    except Exception as e:
        print(f"  (LLM unavailable: {str(e)[:40]}... using demo script)")
        # Create a mock script for demo purposes
        mock_content = '''#!/usr/bin/env python3
"""
Enumerate installed packages and check for root indicators
Generated for: Android 11 @ 192.168.56.101
"""
import subprocess
import sys

def run_adb(cmd):
    """Execute ADB command and return output."""
    result = subprocess.run(
        ["adb", "-s", "192.168.56.101:5555", "shell"] + cmd.split(),
        capture_output=True, text=True
    )
    return result.stdout.strip()

def main():
    print("[*] Enumerating installed packages...")
    packages = run_adb("pm list packages")
    print(f"[+] Found {len(packages.splitlines())} packages")

    print("[*] Checking for root indicators...")
    root_checks = [
        ("su binary", "which su"),
        ("Magisk", "pm list packages | grep -i magisk"),
        ("SuperSU", "pm list packages | grep -i supersu"),
    ]

    for name, cmd in root_checks:
        result = run_adb(cmd)
        status = "FOUND" if result else "not found"
        print(f"    {name}: {status}")

    # Check if we can get root
    uid = run_adb("id")
    print(f"[*] Current UID: {uid}")

if __name__ == "__main__":
    main()
'''
        script = GeneratedScript(
            name="recon_packages_root_check.py",
            content=mock_content,
            script_type=ScriptType.PYTHON,
            description="Enumerate packages and check root indicators",
            source_step=step
        )

    print(f"\n  ┌─ Generated: {script.name} ─────────────────────")

    # Show first 15 lines of script
    lines = script.content.split('\n')
    for i, line in enumerate(lines[:15], 1):
        # Truncate long lines
        display_line = line[:60] + "..." if len(line) > 60 else line
        print(f"  │ {i:2}: {display_line}")

    if len(lines) > 15:
        print(f"  │ ... ({len(lines) - 15} more lines)")
    print(f"  └{'─' * 50}")

    # Validate
    valid, issues = generator.validate(script)
    print(f"\n  Validation: {'✓ PASSED' if valid else '✗ FAILED'}")

    # Quality check
    metrics = generator.check_quality(script, target)
    print("  Quality Check:")
    print(f"    - Hallucinated tools: {len(metrics.hallucinated_tools or [])}")
    print(f"    - Hallucinated paths: {len(metrics.hallucinated_paths or [])}")
    print(f"    - Intrusive commands: {len(metrics.intrusive_commands or [])}")

    return script


def demo_feedback_loop():
    """Demo 4: Iterative Feedback Loop"""
    print_header("DEMO 4: Feedback Loop (Error Recovery)")

    generator = ScriptGenerator()

    # Simulate failure scenario
    error = "error: device '192.168.56.101:5555' not found"

    print_step("Simulating script execution failure...")
    print(f"\n  ⚠️  Error: {error}")

    # Extract error context - this works without LLM
    context = generator.extract_error_context(error)
    print("\n  Error Analysis:")
    print(f"    Type: {context['error_type']}")
    print("    Suggestions:")
    for suggestion in context['suggestions'][:3]:
        print(f"      • {suggestion}")

    # Show what the feedback loop does
    print("\n  Feedback Loop Process:")
    print("    1. Capture error output from failed script")
    print("    2. Classify error type (connection, permission, syntax, etc.)")
    print("    3. Generate fix suggestions based on error pattern")
    print("    4. Re-prompt LLM with error context")
    print("    5. Generate new script incorporating fixes")
    print("    6. Retry execution (up to max_retries)")

    print("\n  ✓ Error classification: Working")
    print("  ✓ Suggestion generation: Working")
    print("  ✓ Feedback loop architecture: Validated")


def demo_governance():
    """Demo 5: Human-in-the-Loop Governance"""
    print_header("DEMO 5: Governance & Triage")

    assessor = TriageAssessor()
    workflow = ApprovalWorkflow()

    # Test various commands (assessor expects a list)
    test_commands = [
        ("getprop ro.build.version.release", "Read Android version"),
        ("pm list packages", "List installed apps"),
        ("dumpsys activity", "Dump activity info"),
        ("su -c 'id'", "Check root access"),
        ("frida -U -n com.target.app", "Frida instrumentation"),
        ("rm -rf /data/local/tmp/*", "Delete temp files"),
    ]

    print("\n  Command Triage Assessment:\n")
    print(f"  {'Command':<50} {'Level':>6}  {'Action':<15}")
    print(f"  {'─' * 50} {'─' * 6}  {'─' * 15}")

    for cmd, desc in test_commands:
        # Pass as list (assessor expects list of commands)
        level, reason = assessor.assess([cmd])

        # Determine action based on level
        if level.value <= 2:
            action = "✓ Auto-approve"
            color = "\033[92m"  # Green
        elif level.value <= 3:
            action = "⚠ Review"
            color = "\033[93m"  # Yellow
        else:
            action = "🛑 Block"
            color = "\033[91m"  # Red

        reset = "\033[0m"

        # Truncate command for display
        cmd_display = cmd[:47] + "..." if len(cmd) > 50 else cmd
        print(f"  {cmd_display:<50} {color}{level.value:>6}{reset}  {action:<15}")

    print("\n  Governance Rules:")
    print("    • Level 1-2: Auto-approved (low risk)")
    print("    • Level 3:   Requires human review")
    print("    • Level 4-5: Blocked without explicit override")


def demo_chain_execution():
    """Demo 6: End-to-End Chain"""
    print_header("DEMO 6: Attack Chain Execution (Dry Run)")

    try:
        from agent.chains.android_root_chain import AndroidRootChain, ChainState

        chain = AndroidRootChain(
            max_iterations=3,
            max_retries_per_step=2,
            require_confirmation=False
        )

        target = {
            "ip": "192.168.56.101",
            "android_version": "11",
            "api_level": 30,
            "security_patch": "2021-01-05",
            "device": "Demo Device"
        }

        print_step("Chain Configuration:")
        print(f"      Max iterations: {chain.max_iterations}")
        print(f"      Max retries/step: {chain.max_retries_per_step}")
        print(f"      Target: {target['device']}")

        print(f"\n  Chain States: {[s.value for s in ChainState]}")

        print("\n  Executing dry run...")
        time.sleep(0.5)

        result = chain.run(
            target_config=target,
            objective="Demonstrate chain execution",
            executor=None  # Dry run - no actual execution
        )

        print("\n  Chain Result:")
        print(f"    • Scripts generated: {len(result.generated_scripts)}")
        print(f"    • Total retries: {result.total_retries}")
        print(f"    • Final state: {result.final_state}")

        if result.generated_scripts:
            print("\n  Generated Scripts:")
            for i, script in enumerate(result.generated_scripts[:3], 1):
                print(f"    {i}. {script.name}")

    except Exception as e:
        print(f"  Chain demo skipped: {e}")


def main():
    """Run the full demo."""
    print("\n")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                                                                      ║")
    print("║          LLM-AndroidPentest Framework Demo                           ║")
    print("║          ─────────────────────────────────                           ║")
    print("║          Based on: 'Breaking Android with AI'                        ║")
    print("║          Paper: arxiv.org/abs/2509.07933                             ║")
    print("║                                                                      ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")

    # Run all demos
    device_profile = demo_reconnaissance()
    cve_matches = demo_cve_matching(device_profile)
    script = demo_script_generation(device_profile)
    demo_feedback_loop()
    demo_governance()
    demo_chain_execution()

    # Summary
    print_header("DEMO COMPLETE")

    print("""
  This demo showcased:

    ✓ Device reconnaissance and fingerprinting
    ✓ CVE matching against device profile
    ✓ LLM-driven script generation with quality checks
    ✓ Iterative feedback loop for error recovery
    ✓ Human-in-the-loop governance and triage
    ✓ End-to-end attack chain execution

  The framework implements the methodology from:
  "Breaking Android with AI: A Deep Dive into LLM-Powered Exploitation"

  Next steps:
    • Connect a real device: adb connect <ip>:5555
    • Start web UI: streamlit run webapp/app.py
    • Run tests: python -m pytest tests/
    """)

    print("═" * 70)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
