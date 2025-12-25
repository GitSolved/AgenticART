"""Context injector - builds retry prompts with error context."""

from __future__ import annotations

from dojo.curriculum.error_extractor import ErrorContext
from dojo.models import Challenge


class ContextInjector:
    """Inject error context into prompts for retry attempts."""

    # Template for retry prompts
    RETRY_TEMPLATE = """Your previous attempt failed. Please fix the error and try again.

## ORIGINAL TASK
{original_task}

## YOUR PREVIOUS OUTPUT
```
{previous_output}
```

## ERROR ENCOUNTERED
{error_details}

## SUGGESTIONS
{suggestions}

## INSTRUCTIONS
Generate a corrected version that fixes the error above.
Only output the command/script, no explanations.
This is attempt {attempt_number} of {max_attempts}."""

    SIMPLE_RETRY_TEMPLATE = """Your previous command failed with: {error_message}

Original task: {original_task}

Your attempt:
```
{previous_output}
```

Suggested fix: {primary_suggestion}

Please provide a corrected command. Output only the command, no explanation."""

    def __init__(self, max_attempts: int = 3, verbose: bool = True):
        """
        Initialize context injector.

        Args:
            max_attempts: Maximum retry attempts.
            verbose: If True, use detailed template. If False, use simple template.
        """
        self.max_attempts = max_attempts
        self.verbose = verbose

    def build_retry_prompt(
        self,
        challenge: Challenge,
        previous_output: str,
        error_context: ErrorContext,
        attempt_number: int,
    ) -> str:
        """
        Build a retry prompt with error context injected.

        Args:
            challenge: The original challenge.
            previous_output: The model's failed output.
            error_context: Extracted error information.
            attempt_number: Current attempt number (1-indexed).

        Returns:
            New prompt with error context for retry.
        """
        if self.verbose:
            return self._build_verbose_prompt(
                challenge, previous_output, error_context, attempt_number
            )
        else:
            return self._build_simple_prompt(
                challenge, previous_output, error_context, attempt_number
            )

    def _build_verbose_prompt(
        self,
        challenge: Challenge,
        previous_output: str,
        error_context: ErrorContext,
        attempt_number: int,
    ) -> str:
        """Build detailed retry prompt."""
        # Format error details
        error_details = self._format_error_details(error_context)

        # Format suggestions
        suggestions = self._format_suggestions(error_context.suggestions)

        return self.RETRY_TEMPLATE.format(
            original_task=challenge.description,
            previous_output=previous_output.strip(),
            error_details=error_details,
            suggestions=suggestions,
            attempt_number=attempt_number,
            max_attempts=self.max_attempts,
        )

    def _build_simple_prompt(
        self,
        challenge: Challenge,
        previous_output: str,
        error_context: ErrorContext,
        attempt_number: int,
    ) -> str:
        """Build simple/concise retry prompt."""
        primary_suggestion = (
            error_context.suggestions[0]
            if error_context.suggestions
            else "Review and fix the error"
        )

        return self.SIMPLE_RETRY_TEMPLATE.format(
            error_message=error_context.error_message,
            original_task=challenge.description,
            previous_output=previous_output.strip(),
            primary_suggestion=primary_suggestion,
        )

    def _format_error_details(self, error_context: ErrorContext) -> str:
        """Format error details section."""
        lines = [
            f"Type: {error_context.error_type}",
            f"Message: {error_context.error_message}",
        ]

        if error_context.failed_line:
            lines.append(f"Failed at: {error_context.failed_line}")

        if error_context.device_state:
            lines.append("\nDevice State:")
            for key, value in error_context.device_state.items():
                lines.append(f"  {key}: {value}")

        return "\n".join(lines)

    def _format_suggestions(self, suggestions: list[str]) -> str:
        """Format suggestions as bullet list."""
        if not suggestions:
            return "- Review the error message and adjust your approach"

        return "\n".join(f"- {s}" for s in suggestions)

    def build_initial_prompt(self, challenge: Challenge) -> str:
        """
        Build the initial prompt for a challenge (before any retries).

        Args:
            challenge: The challenge to attempt.

        Returns:
            Initial prompt string.
        """
        prompt_parts = [challenge.description]

        # Add device context if available
        if challenge.inputs.device_context:
            prompt_parts.append("\n## Device Context")
            for key, value in challenge.inputs.device_context.items():
                prompt_parts.append(f"- {key}: {value}")

        # Add hints if this is first attempt
        if challenge.hints:
            prompt_parts.append("\n## Hints")
            for hint in challenge.hints:
                prompt_parts.append(f"- {hint}")

        # Add output format instruction
        prompt_parts.append("\n## Output Format")
        script_type = challenge.expected_output.script_type.value
        prompt_parts.append(
            f"Provide only the {script_type} command/script. No explanations or markdown."
        )

        return "\n".join(prompt_parts)

    def build_system_prompt(self, challenge: Challenge) -> str:
        """
        Build a system prompt for the challenge.

        Args:
            challenge: The challenge being attempted.

        Returns:
            System prompt string.
        """
        script_type = challenge.expected_output.script_type.value

        return f"""You are an Android security expert. Your task is to generate {script_type} commands/scripts that execute correctly on Android devices.

Rules:
1. Output ONLY the command or script, no explanations
2. Do not wrap output in markdown code blocks
3. Commands must be syntactically correct
4. Use proper escaping for shell special characters
5. Assume ADB is connected to the target device

Belt Level: {challenge.belt.display}
Difficulty: {challenge.difficulty}/5"""
