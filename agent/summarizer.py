"""
Summarizer Module

Inspired by HackSynth's Summarizer component.
Processes output from executed commands and provides context for the Planner.

The Summarizer is the "analytical brain" that understands WHAT HAPPENED
and extracts actionable insights.
"""

import re
from dataclasses import dataclass
from typing import Optional
from enum import Enum

from .llm_client import LLMClient, BaseLLMClient


class ActionResult(Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"


@dataclass
class ExecutionSummary:
    """Summary of a command execution."""
    command: str
    raw_output: str
    result: ActionResult
    key_findings: list[str]
    vulnerabilities: list[str]
    next_steps: list[str]
    error_message: Optional[str] = None


@dataclass
class ContextWindow:
    """Maintains sliding window of execution context."""
    summaries: list[ExecutionSummary]
    max_size: int = 10
    compressed_history: str = ""

    def add(self, summary: ExecutionSummary):
        self.summaries.append(summary)
        if len(self.summaries) > self.max_size:
            # Compress oldest summaries
            oldest = self.summaries.pop(0)
            self.compressed_history += f"\n- {oldest.command}: {oldest.result.value}"

    def get_context(self) -> str:
        """Get full context string for Planner."""
        recent = "\n".join(
            f"[{s.result.value}] {s.command}: {', '.join(s.key_findings)}"
            for s in self.summaries[-5:]
        )
        return f"History: {self.compressed_history}\n\nRecent:\n{recent}"


class Summarizer:
    """
    Analyzes command outputs and extracts actionable intelligence.

    Key responsibilities:
    1. Parse raw command output
    2. Identify successful/failed actions
    3. Extract vulnerabilities and findings
    4. Suggest next steps for Planner
    5. Maintain execution context
    """

    def __init__(self, llm_client: Optional[BaseLLMClient] = None):
        self.llm = llm_client or LLMClient.create()
        self.context = ContextWindow(summaries=[])

    def summarize(self, command: str, output: str) -> ExecutionSummary:
        """
        Summarize the output of an executed command.

        Args:
            command: The command that was executed
            output: Raw stdout/stderr from command

        Returns:
            ExecutionSummary with parsed findings
        """
        system_prompt = """You are an expert Android security analyst.
Analyze command outputs from penetration testing activities.
Extract key findings, identify vulnerabilities, and suggest next steps.
Be concise but thorough. Focus on actionable intelligence."""

        analysis_prompt = f"""
Analyze this penetration testing command output:

COMMAND: {command}

OUTPUT:
```
{output[:4000]}  # Truncate very long outputs
```

Provide analysis in this format:
RESULT: success|partial|failure|blocked|timeout
KEY_FINDINGS:
- finding 1
- finding 2
VULNERABILITIES:
- vuln 1 (if any)
NEXT_STEPS:
- recommended action 1
- recommended action 2
ERROR: <error message if failed>
"""

        response = self.llm.complete(analysis_prompt, system=system_prompt)
        summary = self._parse_summary(command, output, response.content)
        self.context.add(summary)
        return summary

    def get_context_for_planner(self) -> str:
        """Get summarized context for the Planner module."""
        return self.context.get_context()

    def _parse_summary(
        self, command: str, raw_output: str, llm_response: str
    ) -> ExecutionSummary:
        """Parse LLM analysis into ExecutionSummary."""

        # Extract result
        result = ActionResult.PARTIAL
        result_match = re.search(r"RESULT:\s*(\w+)", llm_response, re.IGNORECASE)
        if result_match:
            result_str = result_match.group(1).lower()
            result = ActionResult(result_str) if result_str in [r.value for r in ActionResult] else ActionResult.PARTIAL

        # Extract findings
        findings = self._extract_list(llm_response, "KEY_FINDINGS")

        # Extract vulnerabilities
        vulns = self._extract_list(llm_response, "VULNERABILITIES")

        # Extract next steps
        next_steps = self._extract_list(llm_response, "NEXT_STEPS")

        # Extract error
        error = None
        error_match = re.search(r"ERROR:\s*(.+?)(?:\n|$)", llm_response)
        if error_match:
            error = error_match.group(1).strip()

        return ExecutionSummary(
            command=command,
            raw_output=raw_output,
            result=result,
            key_findings=findings,
            vulnerabilities=vulns,
            next_steps=next_steps,
            error_message=error,
        )

    def _extract_list(self, text: str, section: str) -> list[str]:
        """Extract bullet points from a section."""
        pattern = rf"{section}:\s*\n((?:\s*-\s*.+\n?)+)"
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            items = re.findall(r"-\s*(.+)", match.group(1))
            return [item.strip() for item in items if item.strip()]
        return []

    def compress_context(self) -> str:
        """
        Compress the full context history for long-running sessions.
        Uses LLM to create a condensed summary.
        """
        if not self.context.summaries:
            return ""

        full_context = "\n".join(
            f"- {s.command}: {s.result.value} - {', '.join(s.key_findings[:2])}"
            for s in self.context.summaries
        )

        compress_prompt = f"""
Compress this penetration testing session history into a brief summary
that preserves critical findings and current state:

{full_context}

Output a 3-5 sentence summary of:
1. What has been done
2. Key discoveries
3. Current access level
4. Remaining objectives
"""

        response = self.llm.complete(compress_prompt)
        return response.content
