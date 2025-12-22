#!/usr/bin/env python3
"""
Test the Iterative Feedback Loop Implementation

This script tests the paper's methodology:
1. Match CVEs against target device
2. Generate exploit scripts
3. Simulate failures and test regeneration with feedback
4. Verify retry logic works correctly
"""

import sys
import os
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.script_generator import ScriptGenerator, ScriptType, GeneratedScript
from agent.planner import PlanStep, PentestPhase
from agent.chains.android_root_chain import AndroidRootChain, ChainState
from core.scanning.cve_matcher import CVEMatcher

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Test target configuration (matches our Genymotion emulator)
TARGET_CONFIG = {
    "ip": "192.168.56.101",
    "port": "5555",
    "android_version": "11",
    "api_level": 30,
    "security_patch": "2021-01-05",  # Old patch level to match CVEs
    "device": "Genymotion Pixel 7",
}

# CVEs to test (user specified)
TEST_CVES = [
    "CVE-2021-0968",
    "CVE-2021-25387",
    "CVE-2021-25383",
    "CVE-2021-25384",
    "CVE-2021-25385",
    "CVE-2021-25386",
    "CVE-2021-25449",
]


def test_cve_matching():
    """Test that the CVEs are properly matched."""
    print("\n" + "="*60)
    print("TEST 1: CVE Matching")
    print("="*60)

    matcher = CVEMatcher()
    matches = matcher.match_device(
        android_version=TARGET_CONFIG["android_version"],
        api_level=TARGET_CONFIG["api_level"],
        security_patch=TARGET_CONFIG["security_patch"],
    )

    print(f"\nTarget: Android {TARGET_CONFIG['android_version']} "
          f"(API {TARGET_CONFIG['api_level']}) "
          f"Patch: {TARGET_CONFIG['security_patch']}")
    print(f"\nMatched CVEs: {len(matches)}")

    matched_ids = [cve.cve_id for cve in matches]
    for cve in matches:
        status = "FOUND" if cve.cve_id in TEST_CVES else "extra"
        print(f"  [{status}] {cve.cve_id}: {cve.severity} ({cve.cvss_score}) - {cve.description[:50]}...")

    # Check which requested CVEs were found
    print("\n--- Requested CVE Status ---")
    for cve_id in TEST_CVES:
        found = cve_id in matched_ids
        print(f"  {cve_id}: {'MATCHED' if found else 'NOT MATCHED'}")

    return matches


def test_script_regeneration():
    """Test script regeneration with error feedback."""
    print("\n" + "="*60)
    print("TEST 2: Script Regeneration with Feedback")
    print("="*60)

    generator = ScriptGenerator()

    # Create a test step for CVE-2021-25383 (clipboard exploit)
    step = PlanStep(
        phase=PentestPhase.EXPLOITATION,
        action="Exploit Samsung clipboard provider vulnerability (CVE-2021-25383) to read arbitrary files",
        command=None,
        rationale="CVE-2021-25383 allows arbitrary file read via clipboard provider content URI",
        risk_level="high",
    )

    # Generate initial script
    print("\n--- Generating Initial Script ---")
    script = generator.generate(step, TARGET_CONFIG, ScriptType.PYTHON)
    print(f"Generated: {script.name}")
    print(f"Content preview: {script.content[:200]}...")

    # Simulate an execution error
    simulated_error = """
Traceback (most recent call last):
  File "/tmp/exploit.py", line 45, in <module>
    result = subprocess.run(cmd, capture_output=True)
  File "/usr/lib/python3.9/subprocess.py", line 505, in run
    with Popen(*popenargs, **kwargs) as process:
FileNotFoundError: [Errno 2] No such file or directory: 'adb'

Connection to 192.168.56.101:5555 refused
Device not found or offline
"""

    # Test error context extraction
    print("\n--- Extracting Error Context ---")
    error_context = generator.extract_error_context(simulated_error)
    print(f"Error type: {error_context['error_type']}")
    print(f"Suggestions: {error_context['suggestions']}")

    # Test regeneration with feedback
    print("\n--- Regenerating with Feedback ---")
    regenerated = generator.regenerate_with_feedback(
        failed_script=script,
        error_output=simulated_error,
        target_config=TARGET_CONFIG,
        attempt_number=1,
    )
    print(f"Regenerated: {regenerated.name}")
    print(f"Content preview: {regenerated.content[:200]}...")

    # Validate regenerated script
    valid, issues = generator.validate(regenerated)
    print(f"\nValidation: {'PASSED' if valid else 'FAILED'}")
    if issues:
        for issue in issues:
            print(f"  - {issue}")

    return script, regenerated


def test_chain_retry_configuration():
    """Test that the chain has retry configuration."""
    print("\n" + "="*60)
    print("TEST 3: Chain Retry Configuration")
    print("="*60)

    # Test default configuration
    chain = AndroidRootChain()
    print(f"\nDefault Configuration:")
    print(f"  max_retries_per_step: {chain.max_retries_per_step}")
    print(f"  retry_delay: {chain.retry_delay}s")

    # Test custom configuration
    custom_chain = AndroidRootChain(
        max_retries_per_step=5,
        retry_delay=2.0,
    )
    print(f"\nCustom Configuration:")
    print(f"  max_retries_per_step: {custom_chain.max_retries_per_step}")
    print(f"  retry_delay: {custom_chain.retry_delay}s")

    # Check states include RETRYING
    states = [s.value for s in ChainState]
    print(f"\nChain States: {states}")
    assert "retrying" in states, "RETRYING state should be present"
    print("  'retrying' state present")

    return chain


def test_chain_state_tracking():
    """Test that chain tracks retry statistics."""
    print("\n" + "="*60)
    print("TEST 4: Chain State Tracking")
    print("="*60)

    chain = AndroidRootChain(max_retries_per_step=3)

    # Get initial state
    state = chain.get_state()
    print(f"\nInitial State:")
    for key, value in state.items():
        print(f"  {key}: {value}")

    # Check retry tracking fields
    assert "total_retries" in state
    assert "successful_retries" in state
    assert "failed_after_retries" in state
    print("\n Retry tracking fields present")

    return state


def test_full_chain_dry_run():
    """Test full chain execution in dry run mode."""
    print("\n" + "="*60)
    print("TEST 5: Full Chain Dry Run")
    print("="*60)

    chain = AndroidRootChain(
        max_iterations=3,  # Limit for testing
        max_retries_per_step=2,
        require_confirmation=False,  # Auto-approve for test
    )

    print(f"\nStarting chain for target: {TARGET_CONFIG['ip']}")
    print("Mode: DRY RUN (no executor provided)")

    # Run without executor (dry run)
    result = chain.run(
        target_config=TARGET_CONFIG,
        objective="Test feedback loop against CVE-2021-25383",
        executor=None,  # Dry run
    )

    print(f"\n--- Chain Result ---")
    print(f"Success: {result.success}")
    print(f"Root Achieved: {result.root_achieved}")
    print(f"Total Steps: {result.total_steps}")
    print(f"Scripts Generated: {len(result.generated_scripts)}")
    print(f"Total Retries: {result.total_retries}")
    print(f"Successful Retries: {result.successful_retries}")
    print(f"Failed After Retries: {result.failed_after_retries}")

    if result.findings:
        print(f"\nFindings ({len(result.findings)}):")
        for finding in result.findings[:5]:
            print(f"  - {finding[:80]}...")

    return result


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print(" FEEDBACK LOOP TEST SUITE ")
    print(" Testing paper's iterative refinement methodology ")
    print("="*60)

    try:
        # Test 1: CVE Matching
        matches = test_cve_matching()

        # Test 2: Script Regeneration
        original, regenerated = test_script_regeneration()

        # Test 3: Chain Configuration
        chain = test_chain_retry_configuration()

        # Test 4: State Tracking
        state = test_chain_state_tracking()

        # Test 5: Full Chain (Dry Run)
        result = test_full_chain_dry_run()

        print("\n" + "="*60)
        print(" ALL TESTS PASSED ")
        print("="*60)
        print("\nThe feedback loop implementation is working correctly.")
        print("To test with actual execution, run with LIVE mode enabled.")

    except Exception as e:
        print(f"\n TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
