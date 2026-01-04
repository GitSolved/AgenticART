#!/usr/bin/env python3
"""
Phase 2 Test Script - Test the Dojo feedback loop against a live emulator.

Usage:
    python -m dojo.test_phase2 --mode mock      # Test infrastructure with mock LLM
    python -m dojo.test_phase2 --mode live      # Test with real LLM (Ollama)
    python -m dojo.test_phase2 --mode manual    # Interactive mode for each challenge
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from agent.llm_client import OllamaClient  # noqa: E402
from dojo import (  # noqa: E402
    Belt,
    ChallengeLoader,
    Challenger,
    ChallengeSession,
    ContextInjector,
    ErrorExtractor,
    Executor,
)

# ============================================================================
# Test Results Tracking
# ============================================================================

@dataclass
class TestResult:
    """Result of a single test."""
    name: str
    passed: bool
    message: str
    duration: float = 0.0


class TestRunner:
    """Run and track test results."""

    def __init__(self):
        self.results: list[TestResult] = []
        self.start_time: Optional[datetime] = None

    def start(self):
        self.start_time = datetime.now()
        print("\n" + "=" * 70)
        print("PHASE 2 TEST SUITE - AgenticART Dojo")
        print("=" * 70 + "\n")

    def record(self, name: str, passed: bool, message: str, duration: float = 0.0):
        result = TestResult(name, passed, message, duration)
        self.results.append(result)
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}")
        if message:
            print(f"       {message}")
        if duration > 0:
            print(f"       Duration: {duration:.2f}s")
        print()

    def summary(self):
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)

        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(f"Passed: {passed}/{total}")
        print(f"Failed: {failed}/{total}")

        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            print(f"Total Duration: {duration:.2f}s")

        if failed > 0:
            print("\nFailed Tests:")
            for r in self.results:
                if not r.passed:
                    print(f"  - {r.name}: {r.message}")

        print("=" * 70)

        # Return exit code
        return 0 if failed == 0 else 1


# ============================================================================
# Mock LLM Client
# ============================================================================

class MockLLMClient:
    """Mock LLM that returns expected answers for testing."""

    # Expected answers for white belt challenges
    ANSWERS = {
        "white_001": "shell getprop ro.build.version.release",
        "white_002": "shell pm list packages",
        "white_003": "shell getprop ro.product.model",
        "white_004": "shell ps",
        "white_005": "shell cat /data/system/packages.xml",  # Will fail, then retry
    }

    # Retry answers (after seeing error context)
    RETRY_ANSWERS = {
        "white_005": "shell su -c 'cat /data/system/packages.xml'",
    }

    # Unique identifiers for each challenge (checked in order of specificity)
    CHALLENGE_IDENTIFIERS = [
        ("white_005", ["packages.xml", "/data/system", "protected file"]),
        ("white_004", ["running processes", "process enumeration", "process id"]),
        ("white_003", ["device model", "model name", "marketing name"]),
        ("white_002", ["installed packages", "package manager", "pm list"]),
        ("white_001", ["android version", "version number", "version of"]),
    ]

    def __init__(self):
        self.call_count = 0
        self.last_challenge_id = None
        self.retry_mode = False

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate a mock response."""
        self.call_count += 1
        prompt_lower = prompt.lower()

        # Check if this is a retry prompt
        if "previous attempt failed" in prompt_lower or "your previous command failed" in prompt_lower:
            self.retry_mode = True
            if self.last_challenge_id and self.last_challenge_id in self.RETRY_ANSWERS:
                return self.RETRY_ANSWERS[self.last_challenge_id]

        # Check for explicit challenge ID first
        for cid in self.ANSWERS:
            if cid in prompt:
                self.last_challenge_id = cid
                self.retry_mode = False
                return self.ANSWERS[cid]

        # Match by unique keywords (in order of specificity)
        for cid, keywords in self.CHALLENGE_IDENTIFIERS:
            if any(kw in prompt_lower for kw in keywords):
                self.last_challenge_id = cid
                self.retry_mode = False
                return self.ANSWERS[cid]

        # Default response
        return "shell echo 'unknown challenge'"


# ============================================================================
# Manual LLM Client (Interactive)
# ============================================================================

class ManualLLMClient:
    """Interactive client that asks user for input."""

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Ask user for the command."""
        print("\n" + "-" * 50)
        print("CHALLENGE PROMPT:")
        print("-" * 50)
        print(prompt[:500] + ("..." if len(prompt) > 500 else ""))
        print("-" * 50)
        response = input("Your command: ").strip()
        return response if response else "shell echo 'skipped'"


# ============================================================================
# Test Functions
# ============================================================================

def test_executor_connection(runner: TestRunner, executor: Executor) -> bool:
    """Test 1: Verify executor can connect to device."""
    start = time.time()
    try:
        connected = executor.check_device_connected()
        duration = time.time() - start

        if connected:
            info = executor.get_device_info()
            runner.record(
                "Executor Connection",
                True,
                f"Connected to {executor.device_id} (Android {info.get('android_version', 'unknown')})",
                duration,
            )
            return True
        else:
            runner.record(
                "Executor Connection",
                False,
                "Device not responding. Is the emulator running?",
                duration,
            )
            return False
    except Exception as e:
        runner.record("Executor Connection", False, str(e), time.time() - start)
        return False


def test_loader(runner: TestRunner, loader: ChallengeLoader) -> bool:
    """Test 2: Verify challenge loader works."""
    start = time.time()
    try:
        challenges = loader.load_belt(Belt.WHITE)
        duration = time.time() - start

        if len(challenges) == 5:
            ids = [c.id for c in challenges]
            runner.record(
                "Challenge Loader",
                True,
                f"Loaded {len(challenges)} challenges: {', '.join(ids)}",
                duration,
            )
            return True
        else:
            runner.record(
                "Challenge Loader",
                False,
                f"Expected 5 challenges, got {len(challenges)}",
                duration,
            )
            return False
    except Exception as e:
        runner.record("Challenge Loader", False, str(e), time.time() - start)
        return False


def test_single_challenge(
    runner: TestRunner,
    challenger: Challenger,
    loader: ChallengeLoader,
    challenge_id: str,
    expect_retry: bool = False,
) -> Optional[ChallengeSession]:
    """Test a single challenge."""
    start = time.time()

    try:
        challenge = loader.load_challenge(challenge_id)
        session = challenger.run_challenge(challenge)
        duration = time.time() - start

        # Determine success criteria
        if expect_retry:
            # For retry test, success = retry was triggered
            triggered_retry = session.total_attempts > 1
            passed = triggered_retry
            if triggered_retry:
                message = f"Retry triggered ({session.total_attempts} attempts)"
                if session.final_success:
                    message += " - eventually succeeded"
                else:
                    last_error = session.attempts[-1].error_context
                    message += f" - final error: {last_error.error_type if last_error else 'unknown'}"
            else:
                message = "Expected retry but command succeeded on first try"
        else:
            passed = session.final_success
            if passed:
                output = session.successful_output or ""
                message = f"Output: {output[:50]}{'...' if len(output) > 50 else ''}"
            else:
                last_error = session.attempts[-1].error_context
                message = f"Failed: {last_error.error_message if last_error else 'unknown error'}"

        runner.record(
            f"Challenge {challenge_id}",
            passed,
            message,
            duration,
        )

        return session

    except Exception as e:
        runner.record(f"Challenge {challenge_id}", False, str(e), time.time() - start)
        return None


def test_error_extraction(runner: TestRunner, sessions: list[ChallengeSession]) -> bool:
    """Test 4: Verify error extraction works for failed attempts."""
    start = time.time()

    # Find sessions with failures
    failed_attempts = []
    for session in sessions:
        for attempt in session.attempts:
            if not attempt.execution_result.success:
                failed_attempts.append(attempt)

    if not failed_attempts:
        runner.record(
            "Error Extraction",
            True,
            "No failures to test (all challenges passed)",
            time.time() - start,
        )
        return True

    # Check that errors were extracted properly
    errors_extracted = 0
    for attempt in failed_attempts:
        if attempt.error_context and attempt.error_context.error_type:
            errors_extracted += 1

    duration = time.time() - start
    passed = errors_extracted == len(failed_attempts)

    runner.record(
        "Error Extraction",
        passed,
        f"{errors_extracted}/{len(failed_attempts)} failures had error context extracted",
        duration,
    )

    return passed


def test_session_data_integrity(runner: TestRunner, sessions: list[ChallengeSession]) -> bool:
    """Test 5: Verify all session data is complete."""
    start = time.time()

    issues = []
    for session in sessions:
        if not session.challenge:
            issues.append("Session missing challenge")
        if not session.attempts:
            issues.append(f"{session.challenge.id}: No attempts recorded")
        for i, attempt in enumerate(session.attempts):
            if not attempt.model_output:
                issues.append(f"{session.challenge.id} attempt {i}: No model output")
            if not attempt.execution_result:
                issues.append(f"{session.challenge.id} attempt {i}: No execution result")

    duration = time.time() - start
    passed = len(issues) == 0

    runner.record(
        "Session Data Integrity",
        passed,
        "All sessions have complete data" if passed else f"{len(issues)} issues found",
        duration,
    )

    if not passed:
        for issue in issues[:5]:  # Show first 5 issues
            print(f"       - {issue}")

    return passed


# ============================================================================
# Main Test Flow
# ============================================================================

def find_adb_path() -> str:
    """Find the ADB executable path."""
    import shutil

    # Check environment variable first
    adb_path = os.environ.get("ADB_PATH")
    if adb_path and os.path.exists(adb_path):
        return adb_path

    # Check if adb is in PATH
    adb_in_path = shutil.which("adb")
    if adb_in_path:
        return adb_in_path

    # Common Windows locations
    if sys.platform == "win32":
        common_paths = [
            os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
            os.path.expandvars(r"%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe"),
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path

    # Fall back to 'adb' and hope it's in PATH
    return "adb"


def run_tests(mode: str = "mock", device_id: str = "emulator-5554") -> int:
    """Run the full test suite."""

    runner = TestRunner()
    runner.start()

    # Find ADB path
    adb_path = find_adb_path()

    # Initialize components
    print(f"Mode: {mode.upper()}")
    print(f"Device: {device_id}")
    print(f"ADB: {adb_path}")
    print()

    # Create LLM client based on mode
    llm: Any
    if mode == "mock":
        llm = MockLLMClient()
        print("Using MOCK LLM (returns expected answers)")
    elif mode == "live":
        llm = OllamaClient()
        if not llm.is_available():
            print("ERROR: Ollama not running")
            print("Falling back to mock mode")
            llm = MockLLMClient()
        else:
            print("Using LIVE LLM (Ollama)")
    elif mode == "manual":
        llm = ManualLLMClient()
        print("Using MANUAL mode (you provide commands)")
    else:
        print(f"Unknown mode: {mode}")
        return 1

    print()

    # Create executor with detected ADB path
    executor = Executor(device_id=device_id, adb_path=adb_path)

    # Test 1: Executor connection
    if not test_executor_connection(runner, executor):
        print("\nCANNOT CONTINUE: Emulator not connected")
        print("Please start your Android emulator and try again.")
        runner.summary()
        return 1

    # Create remaining components
    loader = ChallengeLoader()
    error_extractor = ErrorExtractor(executor)
    context_injector = ContextInjector(max_attempts=3)

    # Test 2: Challenge loader
    if not test_loader(runner, loader):
        print("\nCANNOT CONTINUE: Failed to load challenges")
        runner.summary()
        return 1

    # Create challenger with callback for visibility
    def on_attempt(attempt):
        status = "OK" if attempt.execution_result.success else "FAIL"
        print(f"       Attempt {attempt.attempt_number}: {status}")

    challenger = Challenger(
        llm_client=llm,
        executor=executor,
        error_extractor=error_extractor,
        context_injector=context_injector,
        max_retries=3,
        on_attempt=on_attempt if mode != "manual" else None,
    )

    # Test 3: Run each white belt challenge
    print("-" * 70)
    print("RUNNING WHITE BELT CHALLENGES")
    print("-" * 70 + "\n")

    sessions = []

    # Challenges that should pass on first try
    for cid in ["white_001", "white_002", "white_003", "white_004"]:
        session = test_single_challenge(runner, challenger, loader, cid, expect_retry=False)
        if session:
            sessions.append(session)

    # Challenge designed to test retry loop
    session = test_single_challenge(runner, challenger, loader, "white_005", expect_retry=True)
    if session:
        sessions.append(session)

    # Test 4: Error extraction
    test_error_extraction(runner, sessions)

    # Test 5: Data integrity
    test_session_data_integrity(runner, sessions)

    # Print detailed results for review
    print("\n" + "-" * 70)
    print("DETAILED SESSION DATA")
    print("-" * 70)

    for session in sessions:
        print(f"\n{session.challenge.id}: {session.challenge.name}")
        print(f"  Final: {'PASS' if session.final_success else 'FAIL'}")
        print(f"  Attempts: {session.total_attempts}")
        for i, attempt in enumerate(session.attempts):
            print(f"  [{i+1}] Command: {attempt.model_output[:60]}...")
            print(f"      Result: {'OK' if attempt.execution_result.success else 'FAIL'}")
            if attempt.error_context:
                print(f"      Error: {attempt.error_context.error_type}")

    # Summary
    return runner.summary()


# ============================================================================
# Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Phase 2 Test Script")
    parser.add_argument(
        "--mode",
        choices=["mock", "live", "manual"],
        default="mock",
        help="LLM mode: mock (expected answers), live (Ollama), manual (interactive)",
    )
    parser.add_argument(
        "--device",
        default="emulator-5554",
        help="Device ID for ADB",
    )

    args = parser.parse_args()

    exit_code = run_tests(mode=args.mode, device_id=args.device)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
