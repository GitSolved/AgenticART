#!/usr/bin/env python3
"""
Persona Validation Script for AgenticART.

Validates that a device matches the expected persona configuration,
checking for required apps, minimum data counts, and file presence.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@dataclass
class ValidationResult:
    """Result of a single validation check."""

    check: str
    passed: bool
    expected: str
    actual: str
    details: str = ""


@dataclass
class PersonaValidation:
    """Complete persona validation results."""

    persona_name: str
    device_id: str
    passed: bool = False
    results: list[ValidationResult] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    def summary(self) -> str:
        status = "✅ PASSED" if self.passed else "❌ FAILED"
        return (
            f"Persona: {self.persona_name}\n"
            f"Device: {self.device_id}\n"
            f"Status: {status}\n"
            f"Checks: {self.pass_count}/{len(self.results)} passed"
        )


class PersonaValidator:
    """Validates device against persona requirements."""

    persona_path: Path
    device_id: str
    adb_path: str
    persona: dict

    def __init__(
        self,
        persona_path: Path,
        device_id: Optional[str] = None,
        adb_path: str = "adb",
    ):
        self.persona_path = persona_path
        self.device_id = device_id or os.getenv("EMULATOR_DEVICE") or "emulator-5554"
        self.adb_path = adb_path
        self.persona = self._load_persona()

    def _load_persona(self) -> dict:
        """Load persona with inheritance."""
        with open(self.persona_path, "r") as f:
            persona = yaml.safe_load(f)

        if persona.get("inherits"):
            base_path = self.persona_path.parent / f"{persona['inherits']}.yaml"
            if base_path.exists():
                with open(base_path, "r") as f:
                    base = yaml.safe_load(f)
                persona = self._deep_merge(base, persona)

        return persona

    def _deep_merge(self, base: dict, override: dict) -> dict:
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _adb_shell(self, command: str) -> str:
        """Execute ADB shell command."""
        cmd = [self.adb_path, "-s", self.device_id, "shell", command]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip()

    def validate(self) -> PersonaValidation:
        """Run all validation checks."""
        validation = PersonaValidation(
            persona_name=self.persona.get("name", "Unknown"),
            device_id=self.device_id,
        )

        print(f"🔍 Validating persona: {validation.persona_name}")
        print(f"   Device: {self.device_id}")
        print()

        # Get validation requirements
        requirements = self.persona.get("validation", {})

        # Check Android version
        validation.results.append(self._check_android_version())

        # Check minimum contacts
        if "min_contacts" in requirements:
            validation.results.append(self._check_contact_count(requirements["min_contacts"]))

        # Check minimum SMS
        if "min_sms" in requirements:
            validation.results.append(self._check_sms_count(requirements["min_sms"]))

        # Check required apps
        if "required_apps" in requirements:
            for package in requirements["required_apps"]:
                validation.results.append(self._check_app_installed(package))

        # Check required files
        if "required_files" in requirements:
            for file_path in requirements["required_files"]:
                validation.results.append(self._check_file_exists(file_path))

        # Check minimum app count
        if "min_apps" in requirements:
            validation.results.append(self._check_app_count(requirements["min_apps"]))

        # Determine overall pass/fail
        validation.passed = all(r.passed for r in validation.results)

        return validation

    def _check_android_version(self) -> ValidationResult:
        """Check Android version matches persona."""
        expected_api = self.persona.get("device", {}).get("api_level", 30)

        actual = self._adb_shell("getprop ro.build.version.sdk")
        try:
            actual_api = int(actual)
        except ValueError:
            actual_api = 0

        passed = actual_api == expected_api

        return ValidationResult(
            check="Android API Level",
            passed=passed,
            expected=str(expected_api),
            actual=str(actual_api),
            details=f"Android {self._adb_shell('getprop ro.build.version.release')}",
        )

    def _check_contact_count(self, min_count: int) -> ValidationResult:
        """Check minimum number of contacts."""
        output = self._adb_shell(
            "content query --uri content://contacts/people 2>/dev/null | wc -l"
        )

        try:
            actual = int(output.strip())
        except ValueError:
            actual = 0

        return ValidationResult(
            check="Minimum Contacts",
            passed=actual >= min_count,
            expected=f">= {min_count}",
            actual=str(actual),
        )

    def _check_sms_count(self, min_count: int) -> ValidationResult:
        """Check minimum number of SMS messages."""
        output = self._adb_shell("content query --uri content://sms 2>/dev/null | wc -l")

        try:
            actual = int(output.strip())
        except ValueError:
            actual = 0

        return ValidationResult(
            check="Minimum SMS",
            passed=actual >= min_count,
            expected=f">= {min_count}",
            actual=str(actual),
        )

    def _check_app_installed(self, package: str) -> ValidationResult:
        """Check if an app is installed."""
        output = self._adb_shell(f"pm list packages {package}")
        installed = f"package:{package}" in output

        return ValidationResult(
            check=f"App: {package}",
            passed=installed,
            expected="installed",
            actual="installed" if installed else "not found",
        )

    def _check_file_exists(self, file_path: str) -> ValidationResult:
        """Check if a file exists on device."""
        output = self._adb_shell(f"test -f {file_path} && echo exists")
        exists = "exists" in output

        return ValidationResult(
            check=f"File: {file_path}",
            passed=exists,
            expected="exists",
            actual="exists" if exists else "not found",
        )

    def _check_app_count(self, min_count: int) -> ValidationResult:
        """Check minimum number of installed apps."""
        output = self._adb_shell("pm list packages | wc -l")

        try:
            actual = int(output.strip())
        except ValueError:
            actual = 0

        return ValidationResult(
            check="Minimum Apps",
            passed=actual >= min_count,
            expected=f">= {min_count}",
            actual=str(actual),
        )


def main():
    parser = argparse.ArgumentParser(description="Validate device matches persona requirements")
    parser.add_argument(
        "persona",
        help="Persona name or path to YAML file",
    )
    parser.add_argument(
        "--device",
        "-d",
        help="Device ID",
    )
    parser.add_argument(
        "--adb",
        default="adb",
        help="Path to adb executable",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    # Resolve persona path
    if args.persona.endswith(".yaml"):
        persona_path = Path(args.persona)
    else:
        persona_path = Path(__file__).parent.parent / f"{args.persona}.yaml"

    if not persona_path.exists():
        print(f"❌ Persona not found: {persona_path}")
        sys.exit(1)

    # Create validator
    validator = PersonaValidator(
        persona_path=persona_path,
        device_id=args.device,
        adb_path=args.adb,
    )

    # Run validation
    results = validator.validate()

    # Output results
    print()
    print("=" * 60)
    print(results.summary())
    print("=" * 60)
    print()

    for result in results.results:
        status = "✓" if result.passed else "✗"
        print(f"  {status} {result.check}")
        print(f"      Expected: {result.expected}")
        print(f"      Actual:   {result.actual}")
        if result.details:
            print(f"      Details:  {result.details}")
        print()

    sys.exit(0 if results.passed else 1)


if __name__ == "__main__":
    main()
