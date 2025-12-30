"""Tests for training data validation."""

from __future__ import annotations

import json

# Import the validation module
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from validate_training_data import TrainingDataValidator


class TestJSONLFormat:
    """Tests for JSONL format validation."""

    def test_valid_jsonl(self):
        """Valid JSONL files pass validation."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write(json.dumps({"messages": [{"role": "user", "content": "test"}]}) + "\n")
            f.write(json.dumps({"messages": [{"role": "assistant", "content": "response"}]}) + "\n")
            filepath = Path(f.name)

        validator = TrainingDataValidator()
        assert validator.validate_file(filepath) is True
        assert len(validator.errors) == 0

        filepath.unlink()

    def test_invalid_json_line(self):
        """Invalid JSON lines are caught."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write('{"valid": true}\n')
            f.write('{"invalid: json}\n')  # Missing quote
            filepath = Path(f.name)

        validator = TrainingDataValidator()
        assert validator.validate_file(filepath) is False
        assert any("Invalid JSON" in str(e) for e in validator.errors)

        filepath.unlink()


class TestRequiredFields:
    """Tests for required field validation."""

    def test_chat_format_requires_messages(self):
        """Chat format requires messages field."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write(json.dumps({"not_messages": []}) + "\n")
            filepath = Path(f.name)

        validator = TrainingDataValidator()
        validator.validate_file(filepath)
        assert any("Unknown format" in str(e) for e in validator.errors)

        filepath.unlink()

    def test_chat_format_requires_role_and_content(self):
        """Chat messages require role and content."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write(json.dumps({"messages": [{"role": "user"}]}) + "\n")  # Missing content
            filepath = Path(f.name)

        validator = TrainingDataValidator()
        validator.validate_file(filepath)
        assert any("missing 'content'" in str(e) for e in validator.errors)

        filepath.unlink()

    def test_trajectory_format_validates(self):
        """Trajectory format is validated correctly."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write(json.dumps({
                "challenge_id": "test_001",
                "objective": "Test objective",
                "steps": [{"thought": "thinking", "action": "doing"}],
            }) + "\n")
            filepath = Path(f.name)

        validator = TrainingDataValidator()
        assert validator.validate_file(filepath) is True

        filepath.unlink()


class TestDuplicateDetection:
    """Tests for duplicate entry detection."""

    def test_detects_duplicates(self):
        """Duplicate entries are detected."""
        entry = {"messages": [{"role": "user", "content": "same content"}]}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write(json.dumps(entry) + "\n")
            f.write(json.dumps(entry) + "\n")  # Duplicate
            filepath = Path(f.name)

        validator = TrainingDataValidator()
        validator.validate_file(filepath)
        assert any("Duplicate" in str(e) for e in validator.errors)

        filepath.unlink()

    def test_allows_unique_entries(self):
        """Unique entries don't trigger duplicate error."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write(json.dumps({"messages": [{"role": "user", "content": "first"}]}) + "\n")
            f.write(json.dumps({"messages": [{"role": "user", "content": "second"}]}) + "\n")
            filepath = Path(f.name)

        validator = TrainingDataValidator()
        assert validator.validate_file(filepath) is True
        assert not any("Duplicate" in str(e) for e in validator.errors)

        filepath.unlink()


class TestQualityThresholds:
    """Tests for quality threshold validation."""

    def test_warns_on_low_success_rate(self):
        """Warns when success rate is below threshold."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            # 1 success, 9 failures = 10% success rate
            for i in range(10):
                f.write(json.dumps({
                    "challenge_id": f"test_{i}",
                    "objective": "Test",
                    "steps": [{"thought": "t", "action": "a"}],
                    "final_outcome": "success" if i == 0 else "failure",
                }) + "\n")
            filepath = Path(f.name)

        validator = TrainingDataValidator(strict=True)
        validator.validate_file(filepath)
        assert any("Low success rate" in str(w) for w in validator.warnings)

        filepath.unlink()

    def test_warns_on_small_dataset(self):
        """Warns when dataset is too small in strict mode."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            # Only 3 entries
            for i in range(3):
                f.write(json.dumps({
                    "messages": [{"role": "user", "content": f"msg {i}"}]
                }) + "\n")
            filepath = Path(f.name)

        validator = TrainingDataValidator(strict=True)
        validator.validate_file(filepath)
        assert any("only" in str(w) and "entries" in str(w) for w in validator.warnings)

        filepath.unlink()


class TestFileOperations:
    """Tests for file operation handling."""

    def test_nonexistent_file(self):
        """Handles nonexistent file gracefully."""
        validator = TrainingDataValidator()
        result = validator.validate_file(Path("/nonexistent/file.jsonl"))
        assert result is False
        assert any("does not exist" in str(e) for e in validator.errors)

    def test_empty_file(self):
        """Handles empty file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            filepath = Path(f.name)

        validator = TrainingDataValidator()
        # Empty file should pass (no entries, no errors)
        assert validator.validate_file(filepath) is True

        filepath.unlink()

    def test_directory_validation(self):
        """Validates all JSONL files in directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create valid file
            (tmppath / "valid.jsonl").write_text(
                json.dumps({"messages": [{"role": "user", "content": "test"}]}) + "\n"
            )

            # Create invalid file
            (tmppath / "invalid.jsonl").write_text('{"bad json\n')

            validator = TrainingDataValidator()
            result = validator.validate_directory(tmppath)

            assert result is False  # Should fail due to invalid file
            assert len(validator.errors) >= 1
