"Grader - evaluates challenge sessions and produces assessments."

from __future__ import annotations

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from core.reconnaissance.device_enum import ADBConnection
from dojo.curriculum import ChallengeSession
from dojo.models import (
    Challenge,
    Grade,
    SenseiAssessment,
)

logger = logging.getLogger(__name__)

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

    ATTEMPT_PENALTY = 5

    SYNTAX_PATTERNS = {
        "unclosed_quote": r"['\"][^'\"]*$",
        "unclosed_paren": r"\([^)]*$",
        "unclosed_bracket": r"\[[^\]]*$",
        "unclosed_brace": r"\{[^}]*$",
        "double_operator": r"[&|]{3,}",
        "empty_command": r"^\s*$",
    }

    SECURITY_PATTERNS = {
        "hardcoded_credential": r'(password|passwd|pwd|secret|key)\s*[=:]\s*["\'][^"\"]+["\']',
        "dangerous_rm": r'rm\s+(-rf?|--force)\s+/',
        "world_writable": r'chmod\s+777',
        "eval_usage": r'\beval\b',
    }

    HALLUCINATED_API_PATTERNS = [
        r"android\[a-z]+\.[A-Z][a-zA-Z]+",
        r"/proc/[a-z_]+_fake",
        r"getprop\s+ro\.[a-z]+\.[a-z_]+_invalid",
    ]

    VALID_ADB_COMMANDS = {
        "shell", "push", "pull", "install", "uninstall", "logcat",
        "devices", "connect", "disconnect", "root", "remount",
        "forward", "reverse", "reboot", "wait-for-device", "start-server",
        "kill-server", "get-state", "get-serialno", "get-devpath",
        "bugreport", "jdwp", "backup", "restore", "help", "version",
    }

    HALLUCINATED_PATH_PATTERNS = [
        r"/path/to/", r"/your/", r"/example/", r"<[^>]+>", r"\$\{[^}]+\}",
    ]

    def __init__(self, attempt_penalty: int = 5, adb_connection: Optional[ADBConnection] = None):
        self.attempt_penalty = attempt_penalty
        self.adb = adb_connection

    def grade_session(self, session: ChallengeSession) -> SenseiAssessment:
        challenge = session.challenge
        if session.final_success:
            model_output = session.successful_output or ""
        else:
            model_output = session.attempts[-1].model_output if session.attempts else ""

        syntax_ok, syntax_issues = self._evaluate_syntax(model_output, challenge)
        api_ok, api_errors = self._evaluate_api(model_output, challenge)
        exec_ok, exec_issues = self._evaluate_execution(session)
        obj_ok, obj_issues = self._evaluate_objective(session)
        security_issues = self._identify_security_issues(model_output)

        hallucination_count, hallucination_types = self._detect_hallucinations(model_output, challenge)

        # Empirical Verification
        verification_score, verification_logs = self._verify_empirical_claims(model_output)
        if verification_score < 1.0:
            obj_ok = False
            obj_issues.append(f"Empirical verification failed (Score: {verification_score:.2f})")

        rubric = challenge.scoring
        base_score = rubric.calculate_score(syntax_ok, api_ok, exec_ok, obj_ok)
        attempt_penalty = (session.total_attempts - 1) * self.attempt_penalty
        final_score = max(0, base_score - attempt_penalty)
        grade = Grade.from_score(final_score)

        corrected_output = None
        correction_explanation = None
        if grade.is_negative_example:
            corrected_output, correction_explanation = self._generate_correction(
                session, syntax_issues + api_errors + exec_issues + obj_issues + verification_logs
            )

        exec_output = session.attempts[-1].execution_result.stdout if session.attempts else None

        return SenseiAssessment(
            challenge_id=challenge.id,
            model_output=model_output,
            grade=grade,
            score=final_score,
            syntax_issues=syntax_issues,
            api_errors=api_errors,
            logic_flaws=obj_issues,
            security_issues=security_issues,
            hallucination_count=hallucination_count,
            hallucination_types=hallucination_types,
            verification_score=verification_score,
            verification_logs=verification_logs,
            corrected_output=corrected_output,
            correction_explanation=correction_explanation,
            execution_output=exec_output,
        )

    def _verify_empirical_claims(self, output: str) -> tuple[float, list[str]]:
        logs = []
        verified_count = 0
        
        # 1. Robust JSON Extraction
        json_content = output
        if "==========" in json_content:
            parts = json_content.split("==========")
            if len(parts) >= 2:
                json_content = parts[1]

        if "```json" in json_content:
            match = re.search(r"```json(.*?)```", json_content, re.DOTALL)
            if match: json_content = match.group(1)
        elif "{" in json_content:
            start = json_content.find("{")
            end = json_content.rfind("}")
            if start != -1 and end != -1:
                json_content = json_content[start:end+1]

        try:
            # Pre-process: fix common unescaped double quotes in command strings
            # This looks for quotes that are not preceded by a backslash and not followed by a colon or comma/brace
            fixed_json = json_content.strip()
            # Simple heuristic: if a line is "command": "...", escape internal "
            lines = []
            for line in fixed_json.split("\n"):
                if '"command": "' in line:
                    # extract the value part
                    start_idx = line.find('"command": "') + 12
                    end_idx = line.rfind('"')
                    if end_idx > start_idx:
                        prefix = line[:start_idx]
                        suffix = line[end_idx:]
                        value = line[start_idx:end_idx]
                        # escape unescaped quotes in the value
                        value = value.replace('"', '\\"')
                        line = prefix + value + suffix
                lines.append(line)
            fixed_json = "\n".join(lines)
            
            data = json.loads(fixed_json)
        except Exception as e:
            # If sophisticated fix fails, try raw
            try:
                data = json.loads(json_content.strip())
            except Exception as e2:
                logs.append(f"JSON Parse Error: {str(e2)}")
                return 0.0, logs

        # 2. Extract Claims
        items = []
        if isinstance(data, dict):
            if "command" in data: items.append(data)
            if "tasks" in data: items.extend(data["tasks"])
            if "observations" in data: 
                for obs in data["observations"]:
                    if isinstance(obs, dict) and "command" in obs: items.append(obs)

        if not items:
            return 1.0, ["No verifiable claims found in JSON."]

        # 3. Verify
        for item in items:
            cmd = item.get("command")
            expected = str(item.get("expected_output", ""))
            if not cmd: continue

            if self.adb and self.adb.is_connected():
                stdout, _, _ = self.adb.execute(f"shell {cmd}")
                if expected in stdout or stdout.strip() == expected:
                    verified_count += 1
                    logs.append(f"✅ Verified: {cmd}")
                else:
                    logs.append(f"❌ Failed: {cmd}")
            else:
                # Mock Mode
                valid_prefixes = ["adb", "apktool", "jadx", "grep", "frida", "ls", "ps", "dumpsys", "am", "pm"]
                if any(p in cmd.lower() for p in valid_prefixes):
                    verified_count += 1
                    logs.append(f"🛡️  Mock Verified: {cmd}")
                else:
                    logs.append(f"❌ Mock Invalid: {cmd}")

        return verified_count / len(items), logs

    def _evaluate_syntax(self, output: str, challenge: Challenge) -> tuple[bool, list[str]]:
        issues = []
        if not output or not output.strip():
            issues.append("Output is empty")
            return False, issues
        for name, pattern in self.SYNTAX_PATTERNS.items():
            if re.search(pattern, output, re.MULTILINE):
                issues.append(f"Syntax error: {name}")
        return len(issues) == 0, issues

    def _evaluate_api(self, output: str, challenge: Challenge) -> tuple[bool, list[str]]:
        issues = []
        is_valid, pattern_issues = challenge.expected_output.validate(output)
        issues.extend(pattern_issues)
        return len(issues) == 0, issues

    def _evaluate_execution(self, session: ChallengeSession) -> tuple[bool, list[str]]:
        if not session.attempts: return False, ["No attempts"]
        res = session.attempts[-1].execution_result
        if not res.success: return False, [f"Exec failed: {res.error_type}"]
        return True, []

    def _evaluate_objective(self, session: ChallengeSession) -> tuple[bool, list[str]]:
        if not session.final_success: return False, ["Objective not met"]
        return True, []

    def _identify_security_issues(self, output: str) -> list[str]:
        issues = []
        for name, pattern in self.SECURITY_PATTERNS.items():
            if re.search(pattern, output, re.IGNORECASE):
                issues.append(f"Security: {name}")
        return issues

    def _detect_hallucinations(self, output: str, challenge: Challenge) -> tuple[int, list[str]]:
        halls = []
        for pattern in self.HALLUCINATED_API_PATTERNS:
            matches = re.findall(pattern, output)
            for m in matches: halls.append(f"api:{m}")
        adb_matches = re.findall(r"adb\s+([a-z_-]+)", output, re.IGNORECASE)
        for cmd in adb_matches:
            if cmd.lower() not in self.VALID_ADB_COMMANDS: halls.append(f"adb:{cmd}")
        for pattern in self.HALLUCINATED_PATH_PATTERNS:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for m in matches: halls.append(f"path:{m}")
        return len(halls), halls

    def _generate_correction(self, session: ChallengeSession, issues: list[str]) -> tuple[Optional[str], Optional[str]]:
        if session.challenge.kata_solution:
            return session.challenge.kata_solution, f"Issues: {', '.join(issues[:3])}"
        return None, None

    def get_grading_summary(self, assessments: list[SenseiAssessment]) -> dict:
        if not assessments: return {"total": 0}
        total = len(assessments)
        passed = sum(1 for a in assessments if a.grade.is_passing)
        return {
            "total": total,
            "pass_rate": round((passed / total) * 100, 2),
            "avg_score": round(sum(a.score for a in assessments) / total, 2),
            "hallucination_rate": round(sum(a.hallucination_count for a in assessments) / total, 2),
            "verification_rate": round(sum(a.verification_score for a in assessments) / total, 2),
        }
