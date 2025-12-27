"""Training extractor - extracts training examples from graded sessions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from dojo.curriculum import ChallengeSession, ErrorContext
from dojo.models import (
    Belt,
    Challenge,
    Grade,
    SenseiAssessment,
    TrainingExample,
)


@dataclass
class ExtractionConfig:
    """Configuration for training data extraction."""

    include_positive: bool = True
    include_negative: bool = True
    include_error_recovery: bool = True
    include_kata: bool = True
    min_grade_for_positive: Grade = Grade.B

    # Only extract error recovery when improvement was made
    require_improvement_for_recovery: bool = True


class TrainingExtractor:
    """Extract training examples from graded sessions."""

    # System prompt for ADB challenges
    ADB_SYSTEM_PROMPT = (
        "You are an Android security expert. Generate ADB commands "
        "that execute correctly on Android devices. Output only the command, "
        "no explanations or markdown."
    )

    def __init__(self, config: Optional[ExtractionConfig] = None):
        """
        Initialize the extractor.

        Args:
            config: Extraction configuration.
        """
        self.config = config or ExtractionConfig()

    def extract_from_session(
        self,
        session: ChallengeSession,
        assessment: SenseiAssessment,
    ) -> list[TrainingExample]:
        """
        Extract all applicable training examples from a session.
        Strictly filters for successful outputs to prevent training on failures.

        Args:
            session: The challenge session.
            assessment: The grading assessment.

        Returns:
            List of training examples.
        """
        examples = []

        # 1. Kata (golden) example - Always high quality
        if self.config.include_kata:
            example = self._extract_kata_example(session)
            if example:
                examples.append(example)

        # 2. Positive example (successful, high-quality output)
        # ONLY if the final result was a success
        if session.final_success and self.config.include_positive and assessment.is_positive_example:
            example = self._extract_positive_example(session, assessment)
            if example:
                examples.append(example)

        # 3. Negative example with correction
        # We still keep these, but they are flagged as 'negative' type
        # so the Exporter can filter them out of SFT (Alpaca) and into DPO.
        if self.config.include_negative and assessment.is_negative_example:
            example = self._extract_negative_example(session, assessment)
            if example:
                examples.append(example)

        # 4. Error recovery examples (from retry sequences)
        # These are useful for 'Agentic' behavior training
        if self.config.include_error_recovery:
            recovery_examples = self._extract_error_recovery_examples(session)
            examples.extend(recovery_examples)

        # 5. Exploration examples (from Probing Mode)
        # We ALWAYS extract these to the Discovery log
        if session.challenge.belt == Belt.BLACK:
            exploration_examples = self._extract_exploration_examples(session, assessment)
            examples.extend(exploration_examples)

        return examples

    def _extract_exploration_examples(
        self,
        session: ChallengeSession,
        assessment: SenseiAssessment,
    ) -> list[TrainingExample]:
        """Extract ALL attempts from an exploration session as training examples."""
        if not session.attempts:
            return []

        challenge = session.challenge
        extracted = []

        for attempt in session.attempts:
            extracted.append(TrainingExample(
                instruction=challenge.description,
                input_text=attempt.prompt_used,
                output_text=attempt.model_output,
                source_challenge_id=challenge.id,
                example_type="exploration",
                belt=challenge.belt,
                grade=assessment.grade, # Using overall session grade for now
            ))
        return extracted

    def _extract_positive_example(
        self,
        session: ChallengeSession,
        assessment: SenseiAssessment,
    ) -> Optional[TrainingExample]:
        """
        Extract positive example from successful attempt.

        Args:
            session: The challenge session.
            assessment: The grading assessment.

        Returns:
            TrainingExample or None.
        """
        if not session.final_success or not session.successful_output:
            return None

        challenge = session.challenge

        return TrainingExample(
            instruction=self._build_instruction(challenge),
            input_text=self._build_input(challenge),
            output_text=session.successful_output,
            source_challenge_id=challenge.id,
            example_type="positive",
            belt=challenge.belt,
            grade=assessment.grade,
        )

    def _extract_negative_example(
        self,
        session: ChallengeSession,
        assessment: SenseiAssessment,
    ) -> Optional[TrainingExample]:
        """
        Extract negative example with correction.

        Args:
            session: The challenge session.
            assessment: The grading assessment.

        Returns:
            TrainingExample or None.
        """
        if not assessment.corrected_output:
            return None

        challenge = session.challenge
        failed_output = assessment.model_output

        # Format as incorrect/correct pair
        output_text = (
            f"INCORRECT:\n{failed_output}\n\n"
            f"CORRECT:\n{assessment.corrected_output}"
        )

        # Add explanation if available
        if assessment.correction_explanation:
            output_text += f"\n\nEXPLANATION:\n{assessment.correction_explanation}"

        instruction = (
            f"{self._build_instruction(challenge)}\n\n"
            "Note: The following shows an INCORRECT attempt followed by the CORRECT solution."
        )

        return TrainingExample(
            instruction=instruction,
            input_text=self._build_input(challenge),
            output_text=output_text,
            source_challenge_id=challenge.id,
            example_type="negative",
            belt=challenge.belt,
            grade=assessment.grade,
        )

    def _extract_error_recovery_examples(
        self,
        session: ChallengeSession,
    ) -> list[TrainingExample]:
        """
        Extract error->fix sequences from retry history.

        Args:
            session: The challenge session.

        Returns:
            List of error recovery examples.
        """
        examples = []
        challenge = session.challenge

        for i in range(len(session.attempts) - 1):
            current = session.attempts[i]
            next_attempt = session.attempts[i + 1]

            # Only extract if current failed and has error context
            if current.execution_result.success or not current.error_context:
                continue

            # Check if next attempt is an improvement
            if self.config.require_improvement_for_recovery:
                is_improvement = (
                    next_attempt.execution_result.success
                    or next_attempt.error_context is None
                    or (
                        next_attempt.error_context
                        and next_attempt.error_context.error_type
                        != current.error_context.error_type
                    )
                )
                if not is_improvement:
                    continue

            example = TrainingExample(
                instruction="The previous command failed. Fix the error and provide a corrected version.",
                input_text=self._format_error_recovery_input(
                    challenge=challenge,
                    failed_output=current.model_output,
                    error_context=current.error_context,
                ),
                output_text=next_attempt.model_output,
                source_challenge_id=challenge.id,
                example_type="error_recovery",
                belt=challenge.belt,
            )
            examples.append(example)

        return examples

    def _extract_kata_example(
        self,
        session: ChallengeSession,
    ) -> Optional[TrainingExample]:
        """
        Extract kata (golden) example from challenge definition.

        Args:
            session: The challenge session.

        Returns:
            TrainingExample or None.
        """
        challenge = session.challenge

        if not challenge.kata_solution:
            return None

        return TrainingExample(
            instruction=self._build_instruction(challenge),
            input_text=self._build_input(challenge),
            output_text=challenge.kata_solution,
            source_challenge_id=challenge.id,
            example_type="kata",
            belt=challenge.belt,
            grade=Grade.A,  # Kata is always Grade A
        )

    def _build_instruction(self, challenge: Challenge) -> str:
        """
        Build instruction text from challenge.

        Args:
            challenge: The challenge.

        Returns:
            Instruction string.
        """
        return challenge.description.strip()

    def _build_input(self, challenge: Challenge) -> str:
        """
        Build input context from challenge.

        Args:
            challenge: The challenge.

        Returns:
            Input context string.
        """
        parts = []

        # Add device context
        if challenge.inputs.device_context:
            parts.append("Device Context:")
            for key, value in challenge.inputs.device_context.items():
                parts.append(f"  - {key}: {value}")

        # Add hints if available
        if challenge.hints:
            parts.append("")
            parts.append("Hints:")
            for hint in challenge.hints:
                parts.append(f"  - {hint}")

        return "\n".join(parts) if parts else ""

    def _format_error_recovery_input(
        self,
        challenge: Challenge,
        failed_output: str,
        error_context: ErrorContext,
    ) -> str:
        """
        Format input for error recovery example.

        Args:
            challenge: The challenge.
            failed_output: The failed model output.
            error_context: The error context.

        Returns:
            Formatted input string.
        """
        lines = [
            "## Task",
            challenge.description,
            "",
            "## Failed Attempt",
            "```",
            failed_output,
            "```",
            "",
            "## Error Information",
            f"Type: {error_context.error_type}",
            f"Message: {error_context.error_message}",
        ]

        # Add suggestions if available
        if error_context.suggestions:
            lines.append("")
            lines.append("## Suggestions")
            for suggestion in error_context.suggestions[:3]:
                lines.append(f"- {suggestion}")

        lines.append("")
        lines.append("## Instructions")
        lines.append(f"Correct the command to resolve the {error_context.error_type} error.")

        return "\n".join(lines)

    def get_extraction_summary(
        self,
        examples: list[TrainingExample],
    ) -> dict:
        """
        Get summary of extracted examples.

        Args:
            examples: List of training examples.

        Returns:
            Summary dictionary.
        """
        by_type: dict[str, int] = {}
        by_belt: dict[str, int] = {}

        for example in examples:
            # Count by type
            by_type[example.example_type] = by_type.get(example.example_type, 0) + 1

            # Count by belt
            belt_name = example.belt.value
            by_belt[belt_name] = by_belt.get(belt_name, 0) + 1

        return {
            "total": len(examples),
            "by_type": by_type,
            "by_belt": by_belt,
        }
