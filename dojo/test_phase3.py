#!/usr/bin/env python3
"""
Phase 3 Test Script - Test the Sensei grading and training data pipeline.

Usage:
    python -m dojo.test_phase3                    # Test with mock sessions
    python -m dojo.test_phase3 --with-phase2      # Run Phase 2 first, then Phase 3
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dojo import (
    Belt,
    Grade,
    Challenge,
    ChallengeInput,
    ExpectedOutput,
    ScriptType,
    ScoringRubric,
    ChallengeSession,
    AttemptRecord,
    ExecutionResult,
    ErrorContext,
    Sensei,
    Grader,
    TrainingExtractor,
    TrainingDataExporter,
    ExportFormat,
    ProgressTracker,
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
        print("PHASE 3 TEST SUITE - AgenticART Dojo Sensei")
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

        return 0 if failed == 0 else 1


# ============================================================================
# Mock Data Generators
# ============================================================================

def create_mock_challenge(challenge_id: str = "white_001") -> Challenge:
    """Create a mock challenge for testing."""
    return Challenge(
        id=challenge_id,
        name="Test Challenge",
        description="Write an ADB command to get the Android version.",
        belt=Belt.WHITE,
        difficulty=1,
        inputs=ChallengeInput(
            device_context={"connection": "adb", "task": "get version"},
        ),
        expected_output=ExpectedOutput(
            script_type=ScriptType.ADB,
            must_contain=["getprop"],
        ),
        scoring=ScoringRubric(),
        kata_solution="shell getprop ro.build.version.release",
        hints=["Use getprop command"],
    )


def create_mock_execution_result(
    success: bool = True,
    stdout: str = "7.0",
    stderr: str = "",
    error_type: Optional[str] = None,
) -> ExecutionResult:
    """Create a mock execution result."""
    return ExecutionResult(
        success=success,
        exit_code=0 if success else 1,
        stdout=stdout,
        stderr=stderr,
        duration=0.5,
        command="adb shell getprop ro.build.version.release",
        error_type=error_type,
    )


def create_mock_error_context(error_type: str = "permission_denied") -> ErrorContext:
    """Create a mock error context."""
    return ErrorContext(
        error_type=error_type,
        error_message=f"Error: {error_type}",
        failed_command="shell cat /data/system/file",
        device_state={"connected": True, "android_version": "7.0"},
        suggestions=["Try with root access"],
        raw_stderr=f"Error: {error_type}",
        raw_stdout="",
    )


def create_mock_session(
    challenge: Optional[Challenge] = None,
    success: bool = True,
    attempts: int = 1,
) -> ChallengeSession:
    """Create a mock challenge session."""
    challenge = challenge or create_mock_challenge()

    session = ChallengeSession(challenge=challenge)

    for i in range(attempts):
        is_last = i == attempts - 1
        attempt_success = success if is_last else False

        if attempt_success:
            exec_result = create_mock_execution_result(success=True)
            error_ctx = None
            output = "shell getprop ro.build.version.release"
        else:
            exec_result = create_mock_execution_result(
                success=False,
                stderr="Permission denied",
                error_type="permission_denied",
            )
            error_ctx = create_mock_error_context()
            output = "shell cat /data/system/packages.xml"

        attempt = AttemptRecord(
            attempt_number=i + 1,
            prompt_used="Test prompt",
            model_output=output,
            execution_result=exec_result,
            error_context=error_ctx,
        )
        session.attempts.append(attempt)

    session.completed_at = datetime.now()
    return session


# ============================================================================
# Test Functions
# ============================================================================

def test_grader(runner: TestRunner) -> bool:
    """Test the Grader component."""
    start = time.time()

    try:
        grader = Grader()

        # Test successful session (1 attempt)
        session = create_mock_session(success=True, attempts=1)
        assessment = grader.grade_session(session)

        if assessment.grade != Grade.A:
            runner.record(
                "Grader - Success Grade",
                False,
                f"Expected Grade A, got {assessment.grade.value}",
                time.time() - start,
            )
            return False

        # Test session with retries (3 attempts = 2 retries * 5 = 10 point penalty)
        session = create_mock_session(success=True, attempts=3)
        assessment = grader.grade_session(session)

        # Should have penalty for retries: 100 - 10 = 90
        if assessment.score > 90:
            runner.record(
                "Grader - Retry Penalty",
                False,
                f"Expected score <= 90 with retries, got {assessment.score}",
                time.time() - start,
            )
            return False

        if assessment.grade != Grade.A:
            # Score of 90 should still be Grade A
            runner.record(
                "Grader - Retry Grade",
                False,
                f"Score 90 should be Grade A, got {assessment.grade.value}",
                time.time() - start,
            )
            return False

        # Test failed session
        session = create_mock_session(success=False, attempts=3)
        assessment = grader.grade_session(session)

        if assessment.grade.is_passing:
            runner.record(
                "Grader - Failed Grade",
                False,
                f"Expected failing grade, got {assessment.grade.value}",
                time.time() - start,
            )
            return False

        # Test correction generation
        if not assessment.corrected_output:
            runner.record(
                "Grader - Correction",
                False,
                "Expected corrected output for failed session",
                time.time() - start,
            )
            return False

        runner.record(
            "Grader",
            True,
            f"Grading logic validated (grades: A→{assessment.grade.value})",
            time.time() - start,
        )
        return True

    except Exception as e:
        runner.record("Grader", False, str(e), time.time() - start)
        return False


def test_training_extractor(runner: TestRunner) -> bool:
    """Test the TrainingExtractor component."""
    start = time.time()

    try:
        grader = Grader()
        extractor = TrainingExtractor()

        # Test positive example extraction
        session = create_mock_session(success=True, attempts=1)
        assessment = grader.grade_session(session)
        examples = extractor.extract_from_session(session, assessment)

        positive_examples = [e for e in examples if e.example_type == "positive"]
        if not positive_examples:
            runner.record(
                "Extractor - Positive",
                False,
                "No positive examples extracted",
                time.time() - start,
            )
            return False

        # Test kata example extraction
        kata_examples = [e for e in examples if e.example_type == "kata"]
        if not kata_examples:
            runner.record(
                "Extractor - Kata",
                False,
                "No kata examples extracted",
                time.time() - start,
            )
            return False

        # Test error recovery extraction
        session = create_mock_session(success=True, attempts=3)
        assessment = grader.grade_session(session)
        examples = extractor.extract_from_session(session, assessment)

        recovery_examples = [e for e in examples if e.example_type == "error_recovery"]
        if not recovery_examples:
            runner.record(
                "Extractor - Error Recovery",
                False,
                "No error recovery examples from retry session",
                time.time() - start,
            )
            return False

        # Test negative example extraction
        session = create_mock_session(success=False, attempts=3)
        assessment = grader.grade_session(session)
        examples = extractor.extract_from_session(session, assessment)

        negative_examples = [e for e in examples if e.example_type == "negative"]
        if not negative_examples:
            runner.record(
                "Extractor - Negative",
                False,
                "No negative examples from failed session",
                time.time() - start,
            )
            return False

        runner.record(
            "Training Extractor",
            True,
            f"All example types extracted (pos:{len(positive_examples)}, neg:{len(negative_examples)}, kata:{len(kata_examples)})",
            time.time() - start,
        )
        return True

    except Exception as e:
        runner.record("Training Extractor", False, str(e), time.time() - start)
        return False


def test_exporter(runner: TestRunner) -> bool:
    """Test the TrainingDataExporter component."""
    start = time.time()

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            exporter = TrainingDataExporter(output_dir=Path(tmpdir))
            grader = Grader()
            extractor = TrainingExtractor()

            # Generate test examples
            all_examples = []

            # Successful session
            session = create_mock_session(success=True, attempts=1)
            assessment = grader.grade_session(session)
            all_examples.extend(extractor.extract_from_session(session, assessment))

            # Failed session
            session = create_mock_session(success=False, attempts=3)
            assessment = grader.grade_session(session)
            all_examples.extend(extractor.extract_from_session(session, assessment))

            # Session with retries
            session = create_mock_session(success=True, attempts=3)
            assessment = grader.grade_session(session)
            all_examples.extend(extractor.extract_from_session(session, assessment))

            # Test JSONL export
            path = exporter.export(all_examples, ExportFormat.JSONL, "test")
            if not path.exists():
                runner.record(
                    "Exporter - JSONL",
                    False,
                    "JSONL file not created",
                    time.time() - start,
                )
                return False

            # Test Alpaca export
            path = exporter.export(all_examples, ExportFormat.ALPACA, "test")
            if not path.exists():
                runner.record(
                    "Exporter - Alpaca",
                    False,
                    "Alpaca file not created",
                    time.time() - start,
                )
                return False

            # Test ShareGPT export
            path = exporter.export(all_examples, ExportFormat.SHAREGPT, "test")
            if not path.exists():
                runner.record(
                    "Exporter - ShareGPT",
                    False,
                    "ShareGPT file not created",
                    time.time() - start,
                )
                return False

            # Test DPO export
            try:
                path = exporter.export(all_examples, ExportFormat.DPO, "test")
                dpo_created = path.exists()
            except Exception:
                dpo_created = False

            # Get stats
            stats = exporter.get_export_stats(all_examples)

            runner.record(
                "Training Exporter",
                True,
                f"Exports created (examples: {stats['total_examples']}, DPO pairs: {stats['potential_dpo_pairs']})",
                time.time() - start,
            )
            return True

    except Exception as e:
        runner.record("Training Exporter", False, str(e), time.time() - start)
        return False


def test_progress_tracker(runner: TestRunner) -> bool:
    """Test the ProgressTracker component."""
    start = time.time()

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = ProgressTracker(storage_path=Path(tmpdir))
            grader = Grader()

            model_id = "test-model"

            # Test initial progress
            progress = tracker.get_progress(model_id)
            if progress.current_belt != Belt.WHITE:
                runner.record(
                    "Progress - Initial",
                    False,
                    f"Expected WHITE belt, got {progress.current_belt.value}",
                    time.time() - start,
                )
                return False

            # Record some assessments
            for i in range(5):
                session = create_mock_session(success=True, attempts=1)
                assessment = grader.grade_session(session)
                tracker.record_assessment(model_id, assessment)

            # Check progress update
            progress = tracker.get_progress(model_id)
            if progress.challenges_attempted != 5:
                runner.record(
                    "Progress - Recording",
                    False,
                    f"Expected 5 attempts, got {progress.challenges_attempted}",
                    time.time() - start,
                )
                return False

            # Test promotion eligibility
            eligible, next_belt = tracker.check_promotion(model_id)
            if not eligible:
                runner.record(
                    "Progress - Promotion Eligibility",
                    False,
                    "Should be eligible for promotion",
                    time.time() - start,
                )
                return False

            # Test promotion
            new_belt = tracker.promote(model_id)
            if new_belt != Belt.YELLOW:
                runner.record(
                    "Progress - Promotion",
                    False,
                    f"Expected YELLOW belt, got {new_belt.value}",
                    time.time() - start,
                )
                return False

            # Test persistence
            progress = tracker.load_progress(model_id)
            if progress.current_belt != Belt.YELLOW:
                runner.record(
                    "Progress - Persistence",
                    False,
                    "Progress not persisted correctly",
                    time.time() - start,
                )
                return False

            runner.record(
                "Progress Tracker",
                True,
                f"Progress tracked and persisted (belt: {progress.current_belt.display})",
                time.time() - start,
            )
            return True

    except Exception as e:
        runner.record("Progress Tracker", False, str(e), time.time() - start)
        return False


def test_sensei_integration(runner: TestRunner) -> bool:
    """Test the full Sensei integration."""
    start = time.time()

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            sensei = Sensei(output_dir=Path(tmpdir))

            model_id = "integration-test-model"

            # Create test sessions
            sessions = [
                create_mock_session(success=True, attempts=1),
                create_mock_session(success=True, attempts=2),
                create_mock_session(success=True, attempts=3),
                create_mock_session(success=False, attempts=3),
                create_mock_session(success=True, attempts=1),
            ]

            # Run training cycle
            result = sensei.run_training_cycle(
                sessions=sessions,
                model_id=model_id,
                export_formats=[ExportFormat.JSONL, ExportFormat.ALPACA],
            )

            # Validate results
            if len(result.assessments) != 5:
                runner.record(
                    "Sensei - Assessments",
                    False,
                    f"Expected 5 assessments, got {len(result.assessments)}",
                    time.time() - start,
                )
                return False

            if not result.examples:
                runner.record(
                    "Sensei - Examples",
                    False,
                    "No training examples extracted",
                    time.time() - start,
                )
                return False

            if not result.exports:
                runner.record(
                    "Sensei - Exports",
                    False,
                    "No exports created",
                    time.time() - start,
                )
                return False

            # Check promotion (should be eligible with 5 challenges, 4 passed)
            if result.promotion != Belt.YELLOW:
                runner.record(
                    "Sensei - Promotion",
                    False,
                    f"Expected promotion to YELLOW, got {result.promotion}",
                    time.time() - start,
                )
                return False

            # Test feedback generation
            feedback = sensei.get_session_feedback(sessions[0], result.assessments[0])
            if not feedback:
                runner.record(
                    "Sensei - Feedback",
                    False,
                    "No feedback generated",
                    time.time() - start,
                )
                return False

            # Test model report
            report = sensei.get_model_report(model_id)
            if not report:
                runner.record(
                    "Sensei - Report",
                    False,
                    "No report generated",
                    time.time() - start,
                )
                return False

            runner.record(
                "Sensei Integration",
                True,
                f"Full cycle complete ({len(result.examples)} examples, promoted to {result.promotion.display})",
                time.time() - start,
            )
            return True

    except Exception as e:
        runner.record("Sensei Integration", False, str(e), time.time() - start)
        return False


def test_export_formats(runner: TestRunner) -> bool:
    """Test all export format contents."""
    start = time.time()

    try:
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            sensei = Sensei(output_dir=Path(tmpdir))

            sessions = [
                create_mock_session(success=True, attempts=1),
                create_mock_session(success=False, attempts=3),
            ]

            result = sensei.run_training_cycle(
                sessions=sessions,
                model_id="format-test",
                export_formats=list(ExportFormat),
            )

            # Check JSONL format
            if ExportFormat.JSONL in result.exports:
                with open(result.exports[ExportFormat.JSONL], "r") as f:
                    first_line = f.readline()
                    data = json.loads(first_line)
                    if "instruction" not in data or "metadata" not in data:
                        runner.record(
                            "Export Formats - JSONL",
                            False,
                            "JSONL missing expected fields",
                            time.time() - start,
                        )
                        return False

            # Check Alpaca format
            if ExportFormat.ALPACA in result.exports:
                with open(result.exports[ExportFormat.ALPACA], "r") as f:
                    data = json.load(f)
                    if not isinstance(data, list) or not data:
                        runner.record(
                            "Export Formats - Alpaca",
                            False,
                            "Alpaca should be a non-empty array",
                            time.time() - start,
                        )
                        return False
                    if "instruction" not in data[0]:
                        runner.record(
                            "Export Formats - Alpaca Fields",
                            False,
                            "Alpaca missing instruction field",
                            time.time() - start,
                        )
                        return False

            # Check ShareGPT format
            if ExportFormat.SHAREGPT in result.exports:
                with open(result.exports[ExportFormat.SHAREGPT], "r") as f:
                    first_line = f.readline()
                    data = json.loads(first_line)
                    if "conversations" not in data:
                        runner.record(
                            "Export Formats - ShareGPT",
                            False,
                            "ShareGPT missing conversations field",
                            time.time() - start,
                        )
                        return False

            runner.record(
                "Export Formats",
                True,
                f"All formats valid ({len(result.exports)} files created)",
                time.time() - start,
            )
            return True

    except Exception as e:
        runner.record("Export Formats", False, str(e), time.time() - start)
        return False


# ============================================================================
# Main Test Flow
# ============================================================================

def run_tests() -> int:
    """Run the full test suite."""

    runner = TestRunner()
    runner.start()

    # Run component tests
    test_grader(runner)
    test_training_extractor(runner)
    test_exporter(runner)
    test_progress_tracker(runner)
    test_sensei_integration(runner)
    test_export_formats(runner)

    # Print summary
    return runner.summary()


def main():
    parser = argparse.ArgumentParser(description="Phase 3 Test Script")
    parser.add_argument(
        "--with-phase2",
        action="store_true",
        help="Run Phase 2 first to get real sessions",
    )

    args = parser.parse_args()

    if args.with_phase2:
        print("Phase 2 integration not implemented in this test.")
        print("Run test_phase2.py separately, then use Sensei on those sessions.")
        return 1

    exit_code = run_tests()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
