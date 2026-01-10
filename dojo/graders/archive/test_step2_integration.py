#!/usr/bin/env python3
"""
Test Step 2 Integration: Verify Praxis Runner consumes embedded verification_tasks.

This tests:
1. Challenges load with verification_tasks from YAML
2. PraxisRunner uses 0.8 confidence threshold
3. HALLUCINATION_EVENT is tagged in ReasoningChain metadata
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dojo.graders.praxis_runner import PraxisRunner
from dojo.graders.run_all_challenges import load_challenges_from_file


def test_verification_tasks_loaded():
    """Test that verification_tasks are parsed from YAML."""
    print("\n" + "=" * 60)
    print("TEST 1: Verification Tasks Loaded from YAML")
    print("=" * 60)

    # Load methodology challenges
    challenges_file = Path(__file__).parent.parent / "curriculum" / "v2" / "pillars" / "methodology" / "challenges.yaml"
    challenges = load_challenges_from_file(challenges_file)

    print(f"\nLoaded {len(challenges)} challenges from methodology pillar")

    for ch in challenges[:3]:  # Check first 3
        vt_count = len(ch.verification_tasks)
        print(f"\n  {ch.id}:")
        print(f"    verification_tasks: {vt_count}")
        if vt_count > 0:
            vt = ch.verification_tasks[0]
            print(f"    first task tool: {vt.mcp_tool_call.get('tool', 'unknown')}")
            print(f"    first task command: {vt.mcp_tool_call.get('command', 'unknown')[:50]}...")
        else:
            print("    ⚠ NO VERIFICATION TASKS!")

    # Verify all have verification tasks
    missing = [ch.id for ch in challenges if not ch.verification_tasks]
    if missing:
        print(f"\n⚠ Challenges missing verification_tasks: {missing}")
        return False

    print("\n✓ All challenges have verification_tasks embedded")
    return True


def test_confidence_threshold():
    """Test that PraxisRunner uses 0.8 confidence threshold."""
    print("\n" + "=" * 60)
    print("TEST 2: Confidence Threshold = 0.8")
    print("=" * 60)

    runner = PraxisRunner(model_id="test-model")

    print(f"\n  Default confidence_threshold: {runner.confidence_threshold}")
    print("  Expected: 0.8")

    if runner.confidence_threshold == 0.8:
        print("\n✓ Confidence threshold correctly set to 0.8")
        return True
    else:
        print(f"\n✗ Confidence threshold is {runner.confidence_threshold}, expected 0.8")
        return False


def test_hallucination_detection():
    """Test hallucination detection logic with 0.8 threshold."""
    print("\n" + "=" * 60)
    print("TEST 3: Hallucination Detection Logic")
    print("=" * 60)

    runner = PraxisRunner(model_id="test-model")

    test_cases = [
        # (confidence, execution_rate, reasoning_score, expected_hallucination)
        (0.9, 0.1, 0.7, True),   # High conf, low exec -> hallucination
        (0.85, 0.2, 0.6, True),  # High conf, low exec -> hallucination
        (0.75, 0.1, 0.7, False), # Below 0.8 threshold -> NOT hallucination
        (0.9, 0.8, 0.7, False),  # High exec rate -> NOT hallucination
        (0.5, 0.2, 0.3, False),  # Low conf -> NOT hallucination
    ]

    all_passed = True
    for conf, exec_rate, reason_score, expected in test_cases:
        result = runner.is_hallucination(conf, exec_rate, reason_score)
        status = "✓" if result == expected else "✗"
        if result != expected:
            all_passed = False
        print(f"  {status} conf={conf}, exec={exec_rate} -> {result} (expected {expected})")

    if all_passed:
        print("\n✓ Hallucination detection logic working correctly")
    else:
        print("\n✗ Some hallucination detection tests failed")

    return all_passed


def test_metadata_field_exists():
    """Test that ReasoningChain has metadata field."""
    print("\n" + "=" * 60)
    print("TEST 4: ReasoningChain Metadata Field")
    print("=" * 60)

    from dojo.models_v2 import ReasoningChain

    chain = ReasoningChain(
        challenge_id="test",
        model_id="test-model",
    )

    print(f"\n  Has metadata field: {hasattr(chain, 'metadata')}")
    print(f"  Metadata type: {type(chain.metadata)}")
    print(f"  Default value: {chain.metadata}")

    # Test adding HALLUCINATION_EVENT
    chain.metadata["HALLUCINATION_EVENT"] = True
    chain.metadata["test_detail"] = {"foo": "bar"}

    print(f"  After tagging: {chain.metadata}")

    # Test to_dict includes metadata
    chain_dict = chain.to_dict()
    has_metadata_in_dict = "metadata" in chain_dict

    print(f"  to_dict includes metadata: {has_metadata_in_dict}")

    if has_metadata_in_dict and chain.metadata.get("HALLUCINATION_EVENT"):
        print("\n✓ ReasoningChain metadata field working correctly")
        return True
    else:
        print("\n✗ ReasoningChain metadata field issue")
        return False


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("STEP 2 INTEGRATION TESTS")
    print("=" * 60)

    results = []

    results.append(("Verification Tasks Loaded", test_verification_tasks_loaded()))
    results.append(("Confidence Threshold", test_confidence_threshold()))
    results.append(("Hallucination Detection", test_hallucination_detection()))
    results.append(("Metadata Field", test_metadata_field_exists()))

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    all_passed = True
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {name}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n✓ All Step 2 integration tests passed!")
    else:
        print("\n✗ Some tests failed")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
