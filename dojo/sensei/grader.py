"""Grader - evaluates challenge sessions and produces assessments."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from dojo.curriculum import ChallengeSession
from dojo.models import (
    Challenge,
    ExecutionMode,
    Grade,
    ScriptType,
    SenseiAssessment,
)


@dataclass
class GradingCriteria:
    """Evaluation criteria results."""

    syntax_correct: bool = False
    api_valid: bool = False
    executes_successfully: bool = False
    achieves_objective: bool = False


@dataclass
class GradingResult:
    """Detailed grading outcome."""

    criteria: GradingCriteria
    score: int
    grade: Grade
    syntax_issues: list[str] = field(default_factory=list)
    api_errors: list[str] = field(default_factory=list)
    logic_flaws: list[str] = field(default_factory=list)
    security_issues: list[str] = field(default_factory=list)


class Grader:
    """Grade challenge sessions and produce assessments."""

    # Penalty per retry attempt
    ATTEMPT_PENALTY = 5

    # Common syntax error patterns
    SYNTAX_PATTERNS = {
        "unclosed_quote": r"(['\"])(?:(?!\1).)*$",
        "unclosed_paren": r"\([^)\n]*$",
        "unclosed_bracket": r"\[[^\]\n]*$",
        "unclosed_brace": r"\{[^}\n]*$",
        "double_operator": r"[&|]{3,}",
        "empty_command": r"^\s*$",
    }

    # Security concern patterns
    SECURITY_PATTERNS = {
        "hardcoded_credential": r'(password|passwd|pwd|secret|key)\s*[=:]\s*["\'][^"\']+["\']',
        "dangerous_rm": r"rm\s+(-rf?|--force)\s+/",
        "world_writable": r"chmod\s+777",
        "eval_usage": r"\beval\b",
    }

    # Detection success patterns - indicators that agent identified vulnerability
    DETECTION_SUCCESS_PATTERNS = [
        # CVE identification
        r"CVE-\d{4}-\d+",
        r"vulnerability\s+(found|detected|identified)",
        r"(vulnerable|affected)\s+(to|by)",
        # Analysis indicators
        r"analysis\s+(complete|shows|indicates)",
        r"(identified|detected|found)\s+(issue|flaw|weakness|vulnerability)",
        r"security\s+(issue|flaw|risk|concern)",
        # Technical findings
        r"(buffer|heap|stack)\s+overflow",
        r"use[- ]after[- ]free",
        r"race\s+condition",
        r"privilege\s+escalation",
        r"information\s+(leak|disclosure)",
        r"(null|nullptr)\s+(pointer|dereference)",
        # Output indicators
        r"affected\s+version",
        r"patch\s+(available|required|needed)",
        r"mitigation",
        r"exploitable",
    ]

    def __init__(self, attempt_penalty: int = 5):
        """
        Initialize the grader.

        Args:
            attempt_penalty: Points deducted per retry attempt.
        """
        self.attempt_penalty = attempt_penalty

    def grade_session(self, session: ChallengeSession) -> SenseiAssessment:
        """
        Grade a complete challenge session.

        Args:
            session: The challenge session to grade.

        Returns:
            SenseiAssessment with grade, score, and feedback.
        """
        challenge = session.challenge

        # Get the output to grade
        if session.final_success:
            model_output = session.successful_output or ""
        else:
            model_output = session.attempts[-1].model_output if session.attempts else ""

        # Evaluate each criterion
        syntax_ok, syntax_issues = self._evaluate_syntax(model_output, challenge)
        api_ok, api_errors = self._evaluate_api(model_output, challenge)
        exec_ok, exec_issues = self._evaluate_execution(session)
        obj_ok, obj_issues = self._evaluate_objective(session)
        security_issues = self._identify_security_issues(model_output)

        # Calculate base score
        rubric = challenge.scoring
        base_score = rubric.calculate_score(syntax_ok, api_ok, exec_ok, obj_ok)

        # Apply attempt penalty
        attempt_penalty = (session.total_attempts - 1) * self.attempt_penalty
        final_score = max(0, base_score - attempt_penalty)

        # Determine grade
        grade = Grade.from_score(final_score)

        # Store diagnostics in the last attempt for transparency
        if session.attempts:
            session.attempts[-1].diagnostics = {
                "syntax_issues": syntax_issues,
                "api_errors": api_errors,
                "logic_flaws": obj_issues,
                "security_issues": security_issues,
                "score_breakdown": {
                    "syntax_ok": syntax_ok,
                    "api_ok": api_ok,
                    "exec_ok": exec_ok,
                    "obj_ok": obj_ok,
                },
            }

        # Generate correction if needed (D or F grade)
        corrected_output = None
        correction_explanation = None

        if grade.is_negative_example:
            corrected_output, correction_explanation = self._generate_correction(
                session,
                syntax_issues + api_errors + exec_issues + obj_issues,
            )

            # Guard: Don't treat infrastructure errors as valid corrections
            if corrected_output and self._is_infrastructure_error(corrected_output):
                corrected_output = None
                correction_explanation = None

        # Get execution output for reference
        exec_output = None
        if session.attempts:
            last_attempt = session.attempts[-1]
            exec_output = last_attempt.execution_result.stdout

        # Calculate performance metrics
        attempt_count = session.total_attempts
        execution_time = sum(
            attempt.execution_result.execution_time
            for attempt in session.attempts
            if attempt.execution_result
        )

        return SenseiAssessment(
            challenge_id=challenge.id,
            model_output=model_output,
            grade=grade,
            score=final_score,
            syntax_issues=syntax_issues,
            api_errors=api_errors,
            logic_flaws=obj_issues,
            security_issues=security_issues,
            corrected_output=corrected_output,
            correction_explanation=correction_explanation,
            execution_output=exec_output,
            execution_time=execution_time,
            attempt_count=attempt_count,
        )

    def _evaluate_syntax(
        self,
        output: str,
        challenge: Challenge,
    ) -> tuple[bool, list[str]]:
        """
        Check for syntax correctness with language-awareness.
        """
        issues = []
        script_type = challenge.expected_output.script_type

        if not output or not output.strip():
            issues.append("Output is empty")
            return False, issues

        # --- SMART GRADING LOGIC ---
        # Only use simplistic regex checks for one-line ADB/SHELL commands
        if script_type in (ScriptType.ADB, ScriptType.SHELL):
            for error_name, pattern in self.SYNTAX_PATTERNS.items():
                if re.search(pattern, output, re.MULTILINE):
                    issues.append(f"Potential syntax error: {error_name.replace('_', ' ')}")
        else:
            # For FRIDA and C_EXPLOIT, we rely on the Executor (Runtime Check)
            # rather than primitive regex which fails on multi-line blocks.
            # We only check for critical non-code noise.
            pass

        # Check for markdown artifacts that shouldn't be there
        if output.strip().startswith("```"):
            issues.append("Output contains markdown code block markers")

        if output.strip().startswith("`") and output.strip().endswith("`"):
            issues.append("Output wrapped in backticks")

        return len(issues) == 0, issues

    def _evaluate_api(
        self,
        output: str,
        challenge: Challenge,
    ) -> tuple[bool, list[str]]:
        """
        Check for valid API/command usage.

        Args:
            output: The model output to check.
            challenge: The challenge for context.

        Returns:
            Tuple of (is_valid, list of issues).
        """
        issues = []

        # Check expected output patterns from challenge
        expected = challenge.expected_output
        is_valid, pattern_issues = expected.validate(output)
        issues.extend(pattern_issues)

        # Script-type specific checks
        script_type = expected.script_type.value

        if script_type == "adb":
            # ADB-specific validation
            if not any(
                output.startswith(prefix)
                for prefix in [
                    "shell",
                    "push",
                    "pull",
                    "install",
                    "uninstall",
                    "logcat",
                    "adb",
                ]
            ):
                # It's okay if it doesn't start with these - might be just the command
                pass

        return len(issues) == 0, issues

    def _evaluate_execution(
        self,
        session: ChallengeSession,
    ) -> tuple[bool, list[str]]:
        """
        Check if execution was successful.

        Handles execution mode awareness:
        - DETECTION_ANALYSIS/DETECTION_ONLY: Errors may be intentional (probing)
        - SYNTAX_ONLY: No execution expected
        - SIMULATION: Simulated execution, real errors less critical

        Args:
            session: The challenge session.

        Returns:
            Tuple of (is_valid, list of issues).
        """
        issues = []
        challenge = session.challenge
        exec_mode = challenge.execution_mode

        if not session.attempts:
            # For syntax_only, no execution is expected
            if exec_mode == ExecutionMode.SYNTAX_ONLY:
                return True, []
            issues.append("No execution attempts recorded")
            return False, issues

        # Check final execution result
        last_attempt = session.attempts[-1]
        exec_result = last_attempt.execution_result

        if not exec_result.success:
            # For detection modes, execution "failure" might be intentional
            # (e.g., probing for a vulnerability that causes a crash)
            if exec_mode.is_detection_based:
                # Check if we got meaningful output despite the "failure"
                if exec_result.stdout and len(exec_result.stdout) > 20:
                    # Got output - this counts as successful probing
                    return True, ["Execution produced output (detection mode)"]
                if exec_result.stderr and "permission denied" in exec_result.stderr.lower():
                    # Permission denied is actually useful info for detection
                    return True, ["Permission boundary detected (detection mode)"]

            # For simulation mode, be lenient
            if exec_mode == ExecutionMode.SIMULATION:
                if exec_result.stdout or last_attempt.model_output:
                    return True, ["Simulation produced output"]

            # Standard failure handling
            if exec_result.error_type:
                issues.append(f"Execution failed: {exec_result.error_type}")
            if exec_result.stderr:
                # Truncate long error messages
                error_msg = exec_result.stderr[:200]
                issues.append(f"Error output: {error_msg}")

        return exec_result.success, issues

    def _evaluate_objective(
        self,
        session: ChallengeSession,
    ) -> tuple[bool, list[str]]:
        """
        Check if challenge objective was achieved.

        Handles different execution modes:
        - FULL_EXECUTION: Must fully achieve the objective
        - DETECTION_ANALYSIS: Analysis/identification is sufficient
        - DETECTION_ONLY: Just identifying the vulnerability is enough
        - SYNTAX_ONLY: Valid syntax is the objective
        - SIMULATION: Demonstrating the pattern is sufficient
        - TRY_HARDER: Partial progress counts

        Args:
            session: The challenge session.

        Returns:
            Tuple of (is_valid, list of issues).
        """
        issues = []
        challenge = session.challenge
        exec_mode = challenge.execution_mode

        # Route to appropriate evaluation based on execution mode
        if exec_mode.is_detection_based:
            return self._evaluate_detection_objective(session)
        elif exec_mode == ExecutionMode.SYNTAX_ONLY:
            return self._evaluate_syntax_only_objective(session)
        elif exec_mode == ExecutionMode.SIMULATION:
            return self._evaluate_simulation_objective(session)
        elif exec_mode == ExecutionMode.TRY_HARDER:
            return self._evaluate_try_harder_objective(session)

        # Default: FULL_EXECUTION - original logic
        if not session.final_success:
            issues.append("Challenge objective not achieved")
            return False, issues

        # Additional validation from challenge requirements
        if session.successful_output:
            validation = challenge.inputs.additional_context.get("validation", {})
            if validation:
                val_type = validation.get("type", "")
                expected = validation.get("expected", "")

                if val_type == "output_contains" and expected:
                    if expected not in session.attempts[-1].execution_result.stdout:
                        issues.append(f"Output missing expected content: {expected}")
                        return False, issues

        return True, issues

    def _evaluate_detection_objective(
        self,
        session: ChallengeSession,
    ) -> tuple[bool, list[str]]:
        """
        Evaluate objective for detection-based challenges.

        Success criteria:
        - Model output contains detection/analysis indicators
        - OR execution produced relevant security findings
        - OR CVE-related content was identified

        Args:
            session: The challenge session.

        Returns:
            Tuple of (is_valid, list of issues).
        """
        issues = []

        # Combine all outputs for analysis
        combined_output = ""
        if session.attempts:
            last_attempt = session.attempts[-1]
            combined_output = (
                (last_attempt.model_output or "") +
                (last_attempt.execution_result.stdout or "") +
                (last_attempt.execution_result.stderr or "")
            ).lower()

        # Check for detection success patterns
        detection_found = False
        for pattern in self.DETECTION_SUCCESS_PATTERNS:
            if re.search(pattern, combined_output, re.IGNORECASE):
                detection_found = True
                break

        # Also check if the challenge's CVE was mentioned
        challenge = session.challenge
        cve_id = challenge.inputs.cve_id
        if cve_id and cve_id.lower() in combined_output:
            detection_found = True

        # Check challenge-specific validation if present
        validation = challenge.inputs.additional_context.get("validation", {})
        if validation:
            val_type = validation.get("type", "")
            expected = validation.get("expected", "")
            if val_type == "output_contains" and expected:
                if expected.lower() in combined_output:
                    detection_found = True

        if not detection_found:
            # For detection_analysis, we're more lenient - check if execution ran at all
            if session.attempts and session.attempts[-1].execution_result.success:
                # Execution succeeded, give partial credit
                return True, ["Detection analysis executed successfully"]

            issues.append("No vulnerability detection/analysis indicators found")
            return False, issues

        return True, issues

    def _evaluate_syntax_only_objective(
        self,
        session: ChallengeSession,
    ) -> tuple[bool, list[str]]:
        """
        Evaluate objective for syntax-only challenges.

        Success = valid code structure was produced (syntax check already passed).

        Args:
            session: The challenge session.

        Returns:
            Tuple of (is_valid, list of issues).
        """
        # If we got here, syntax was already validated
        # Just check that we have non-empty output
        if session.attempts and session.attempts[-1].model_output:
            return True, []
        return False, ["No code output produced"]

    def _evaluate_simulation_objective(
        self,
        session: ChallengeSession,
    ) -> tuple[bool, list[str]]:
        """
        Evaluate objective for simulation challenges.

        Success = demonstrated understanding of the attack pattern.

        Args:
            session: The challenge session.

        Returns:
            Tuple of (is_valid, list of issues).
        """
        issues = []

        if not session.attempts:
            issues.append("No simulation attempt recorded")
            return False, issues

        # For simulations, having relevant output is sufficient
        last_attempt = session.attempts[-1]
        if last_attempt.model_output and len(last_attempt.model_output.strip()) > 50:
            return True, []

        issues.append("Simulation output insufficient")
        return False, issues

    def _evaluate_try_harder_objective(
        self,
        session: ChallengeSession,
    ) -> tuple[bool, list[str]]:
        """
        Evaluate objective for try_harder (aspirational) challenges.

        These are difficult challenges where partial progress is valuable.

        Args:
            session: The challenge session.

        Returns:
            Tuple of (is_valid, list of issues).
        """
        issues = []

        # Full success
        if session.final_success:
            return True, []

        # Partial credit for making progress
        if session.attempts:
            last_attempt = session.attempts[-1]

            # Did execution at least run?
            if last_attempt.execution_result.success:
                return True, ["Partial progress - execution succeeded"]

            # Did we get meaningful output?
            if last_attempt.execution_result.stdout and len(last_attempt.execution_result.stdout) > 100:
                return True, ["Partial progress - produced output"]

        issues.append("Try-harder challenge: no meaningful progress made")
        return False, issues

    def _identify_security_issues(self, output: str) -> list[str]:
        """
        Identify any security concerns in the output.

        Args:
            output: The model output to check.

        Returns:
            List of security concerns.
        """
        issues = []

        for issue_name, pattern in self.SECURITY_PATTERNS.items():
            if re.search(pattern, output, re.IGNORECASE):
                issues.append(f"Security concern: {issue_name.replace('_', ' ')}")

        return issues

    def _is_infrastructure_error(self, output: str) -> bool:
        """
        Detect if output contains infrastructure/runtime errors rather than valid code.

        This prevents exceptions from upstream services from being treated as
        valid "correct" solutions in training data.

        Args:
            output: The output string to check.

        Returns:
            True if this appears to be an error, not a valid solution.
        """
        if not output:
            return False

        error_patterns = [
            "[ERROR:",
            "Traceback (most recent call last)",
            "TypeError:",
            "ValueError:",
            "AttributeError:",
            "KeyError:",
            "RuntimeError:",
            "Exception:",
            "got an unexpected keyword argument",
            "missing required positional argument",
            "object has no attribute",
        ]

        output_lower = output.lower()
        for pattern in error_patterns:
            if pattern.lower() in output_lower:
                return True

        return False

    def _generate_correction(
        self,
        session: ChallengeSession,
        issues: list[str],
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Generate corrected output for failed attempts.

        Args:
            session: The challenge session.
            issues: List of identified issues.

        Returns:
            Tuple of (corrected_output, explanation).
        """
        challenge = session.challenge

        # Use kata solution if available
        if challenge.kata_solution:
            explanation = self._build_correction_explanation(issues, challenge.kata_solution)
            return challenge.kata_solution, explanation

        # No correction available
        return None, None

    def _build_correction_explanation(
        self,
        issues: list[str],
        correct_solution: str,
    ) -> str:
        """
        Build an explanation of what was wrong and how it was fixed.

        Args:
            issues: List of identified issues.
            correct_solution: The correct solution.

        Returns:
            Explanation string.
        """
        lines = ["Issues identified:"]
        for issue in issues[:5]:  # Limit to top 5 issues
            lines.append(f"  - {issue}")

        lines.append("")
        lines.append("The correct approach is shown in the corrected output.")

        return "\n".join(lines)

    def grade_sessions(
        self,
        sessions: list[ChallengeSession],
    ) -> list[SenseiAssessment]:
        """
        Grade multiple sessions.

        Args:
            sessions: List of challenge sessions.

        Returns:
            List of assessments.
        """
        return [self.grade_session(session) for session in sessions]

    def get_grading_summary(
        self,
        assessments: list[SenseiAssessment],
    ) -> dict:
        """
        Get summary statistics for a set of assessments.

        Args:
            assessments: List of assessments.

        Returns:
            Summary dictionary.
        """
        if not assessments:
            return {
                "total": 0,
                "by_grade": {},
                "average_score": 0.0,
                "pass_rate": 0.0,
            }

        # Count by grade
        by_grade = {}
        for grade in Grade:
            count = sum(1 for a in assessments if a.grade == grade)
            if count > 0:
                by_grade[grade.value] = count

        # Calculate stats
        total = len(assessments)
        total_score = sum(a.score for a in assessments)
        passed = sum(1 for a in assessments if a.grade.is_passing)

        return {
            "total": total,
            "by_grade": by_grade,
            "average_score": round(total_score / total, 2),
            "pass_rate": round((passed / total) * 100, 2),
            "positive_examples": sum(1 for a in assessments if a.is_positive_example),
            "negative_examples": sum(1 for a in assessments if a.is_negative_example),
        }
