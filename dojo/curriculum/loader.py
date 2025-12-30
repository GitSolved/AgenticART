"""Challenge loader - loads challenges from YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml  # type: ignore

from dojo.exceptions import ChallengeNotFoundError, CurriculumError
from dojo.models import (
    Belt,
    Challenge,
    ChallengeInput,
    Compatibility,
    ExpectedOutput,
    ScoringRubric,
    ScriptType,
)


class ChallengeLoader:
    """Load challenge definitions from YAML files."""

    def __init__(self, curriculum_dir: Optional[Path] = None):
        """
        Initialize the challenge loader.

        Args:
            curriculum_dir: Path to curriculum directory. If None, uses default.
        """
        if curriculum_dir is None:
            curriculum_dir = Path(__file__).parent
        self.curriculum_dir = Path(curriculum_dir)
        self._cache: dict[str, Challenge] = {}

    def _get_belt_dir(self, belt: Belt) -> Path:
        """Get the directory for a specific belt."""
        return self.curriculum_dir / f"{belt.value}_belt"

    def _get_challenges_file(self, belt: Belt) -> Path:
        """Get the challenges.yaml file for a belt."""
        return self._get_belt_dir(belt) / "challenges.yaml"

    def _parse_challenge(self, data: dict, belt: Belt) -> Challenge:
        """Parse a challenge dictionary into a Challenge object."""
        try:
            # Parse script type
            script_type_str = data.get("script_type", "adb")
            try:
                script_type = ScriptType(script_type_str.lower())
            except ValueError:
                script_type = ScriptType.ADB

            # Parse inputs
            inputs_data = data.get("inputs", {})
            inputs = ChallengeInput(
                device_context=inputs_data.get("device_context", {}),
                target_class=inputs_data.get("target_class"),
                target_method=inputs_data.get("target_method"),
                cve_id=inputs_data.get("cve_id"),
                additional_context=inputs_data.get("additional_context", {}),
            )

            # Add device_id to device_context if specified at top level
            if "device_id" in inputs_data:
                inputs.device_context["device_id"] = inputs_data["device_id"]

            # Parse expected output
            expected_data = data.get("expected_output", {})
            validation_data = data.get("validation", {})

            expected_output = ExpectedOutput(
                script_type=script_type,
                must_contain=expected_data.get("must_contain", []),
                must_not_contain=expected_data.get("must_not_contain", []),
                expected_patterns=expected_data.get("expected_patterns", []),
            )

            # Store validation rules in additional_context for executor to use
            if validation_data:
                inputs.additional_context["validation"] = validation_data

            # Parse scoring rubric
            scoring_data = data.get("scoring", {})
            scoring = ScoringRubric(
                syntax_correct=scoring_data.get("syntax_correct", 25),
                api_valid=scoring_data.get("api_valid", 25),
                executes_successfully=scoring_data.get("executes_successfully", 30),
                achieves_objective=scoring_data.get("achieves_objective", 20),
            )

            # Parse compatibility
            compat_str = data.get("compatibility", "universal")
            compatibility = Compatibility.from_string(compat_str)

            return Challenge(
                id=data["id"],
                name=data["name"],
                description=data["description"],
                belt=belt,
                difficulty=data.get("difficulty", 1),
                inputs=inputs,
                expected_output=expected_output,
                scoring=scoring,
                kata_solution=data.get("kata_solution"),
                hints=data.get("hints", []),
                tags=data.get("tags", []),
                compatibility=compatibility,
            )

        except KeyError as e:
            raise CurriculumError(
                f"Missing required field in challenge: {e}",
                file_path=str(self._get_challenges_file(belt)),
            )

    def load_belt(self, belt: Belt) -> list[Challenge]:
        """
        Load all challenges for a specific belt.

        Args:
            belt: The belt level to load challenges for.

        Returns:
            List of Challenge objects.

        Raises:
            CurriculumError: If the challenges file cannot be loaded.
        """
        challenges_file = self._get_challenges_file(belt)

        if not challenges_file.exists():
            return []

        try:
            with open(challenges_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise CurriculumError(
                f"Invalid YAML in challenges file: {e}",
                file_path=str(challenges_file),
                cause=e,
            )

        if not data or "challenges" not in data:
            return []

        challenges = []
        for challenge_data in data["challenges"]:
            challenge = self._parse_challenge(challenge_data, belt)
            challenges.append(challenge)
            self._cache[challenge.id] = challenge

        return challenges

    def load_challenge(self, challenge_id: str) -> Challenge:
        """
        Load a specific challenge by ID.

        Args:
            challenge_id: The unique challenge identifier.

        Returns:
            The Challenge object.

        Raises:
            ChallengeNotFoundError: If the challenge doesn't exist.
        """
        # Check cache first
        if challenge_id in self._cache:
            return self._cache[challenge_id]

        # Try to find the challenge by loading all belts
        for belt in Belt:
            challenges = self.load_belt(belt)
            for challenge in challenges:
                if challenge.id == challenge_id:
                    return challenge

        raise ChallengeNotFoundError(challenge_id)

    def list_challenges(self, belt: Optional[Belt] = None) -> list[str]:
        """
        List available challenge IDs.

        Args:
            belt: If specified, only list challenges for this belt.

        Returns:
            List of challenge IDs.
        """
        if belt is not None:
            challenges = self.load_belt(belt)
            return [c.id for c in challenges]

        # Load all belts
        all_ids: list[str] = []
        for b in Belt:
            challenges = self.load_belt(b)
            all_ids.extend(c.id for c in challenges)
        return all_ids

    def get_belt_from_challenge_id(self, challenge_id: str) -> Belt:
        """
        Determine the belt from a challenge ID.

        Args:
            challenge_id: The challenge ID (e.g., "white_001").

        Returns:
            The Belt enum value.

        Raises:
            InvalidBeltError: If the belt cannot be determined.
        """
        # Try to parse belt from ID prefix
        for belt in Belt:
            if challenge_id.startswith(belt.value):
                return belt

        # Fall back to loading and checking
        challenge = self.load_challenge(challenge_id)
        return challenge.belt

    def clear_cache(self) -> None:
        """Clear the challenge cache."""
        self._cache.clear()

    def load_belt_for_device(
        self, belt: Belt, api_level: int
    ) -> list[Challenge]:
        """
        Load challenges for a belt filtered by device compatibility.

        Args:
            belt: The belt level to load challenges for.
            api_level: The Android API level of the target device.

        Returns:
            List of Challenge objects compatible with the device.
        """
        all_challenges = self.load_belt(belt)
        return [
            c for c in all_challenges
            if c.compatibility.is_compatible_with_api(api_level)
        ]

    def filter_by_compatibility(
        self, challenges: list[Challenge], api_level: int
    ) -> list[Challenge]:
        """
        Filter a list of challenges by device compatibility.

        Args:
            challenges: List of challenges to filter.
            api_level: The Android API level of the target device.

        Returns:
            Filtered list of compatible challenges.
        """
        return [
            c for c in challenges
            if c.compatibility.is_compatible_with_api(api_level)
        ]
