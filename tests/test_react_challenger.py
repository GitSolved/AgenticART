"""Tests for react_challenger.py ReAct parsing logic."""

from __future__ import annotations

import pytest

from dojo.react_challenger import ReActChallenger
from dojo.trajectory_schema import ReasoningType


class MockLLM:
    """Mock LLM for testing."""

    def __init__(self, response: str = ""):
        self.response = response
        self.calls: list[tuple[str, str | None]] = []

    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        self.calls.append((prompt, system_prompt))
        return self.response


class MockExecutor:
    """Mock executor for testing."""

    def get_device_info(self) -> dict:
        return {"device_id": "test-device", "android_version": "11"}

    def execute(self, command: str):
        class Result:
            stdout = "mock output"
            stderr = ""
            exit_code = 0
            duration = 0.1

        return Result()


class TestParseReActResponse:
    """Tests for _parse_react_response method."""

    @pytest.fixture
    def challenger(self):
        """Create a challenger instance for testing."""
        import tempfile

        from dojo.trajectory_logger import TrajectoryLogger

        logger = TrajectoryLogger(output_dir=tempfile.mkdtemp(), auto_save=False)
        return ReActChallenger(
            llm_client=MockLLM(),
            executor=MockExecutor(),
            trajectory_logger=logger,
        )

    def test_extracts_thought(self, challenger):
        """Correctly extracts THOUGHT from response."""
        response = """THOUGHT: I need to check the Android version first.

ACTION: shell getprop ro.build.version.release"""

        parsed = challenger._parse_react_response(response)

        assert "check the Android version" in parsed.thought
        assert parsed.action == "shell getprop ro.build.version.release"
        assert parsed.action_type == "command"

    def test_extracts_action(self, challenger):
        """Correctly extracts ACTION from response."""
        response = """THOUGHT: Let me list packages.

ACTION: shell pm list packages"""

        parsed = challenger._parse_react_response(response)

        assert parsed.action == "shell pm list packages"

    def test_detects_done(self, challenger):
        """Correctly detects [DONE] action."""
        response = """THOUGHT: The task is complete.

ACTION: [DONE]"""

        parsed = challenger._parse_react_response(response)

        assert parsed.action_type == "done"
        assert parsed.action == ""

    def test_detects_give_up(self, challenger):
        """Correctly detects [GIVE_UP] action."""
        response = """THOUGHT: This is impossible to solve.

ACTION: [GIVE_UP]"""

        parsed = challenger._parse_react_response(response)

        assert parsed.action_type == "give_up"
        assert parsed.action == ""

    def test_detects_continue_with_command(self, challenger):
        """Correctly handles [CONTINUE] with command."""
        response = """THOUGHT: Need to try more.

ACTION: [CONTINUE] shell ls /sdcard"""

        parsed = challenger._parse_react_response(response)

        assert parsed.action_type == "continue"
        assert "shell ls /sdcard" in parsed.action

    def test_cleans_markdown_from_action(self, challenger):
        """Removes markdown formatting from action."""
        response = """THOUGHT: Running command.

ACTION: ```shell getprop ro.build.version```"""

        parsed = challenger._parse_react_response(response)

        assert "```" not in parsed.action

    def test_handles_multiline_thought(self, challenger):
        """Handles multi-line THOUGHT content."""
        response = """THOUGHT: First, I'll analyze the task.
This requires checking system properties.
The getprop command should work.

ACTION: shell getprop ro.build.version.release"""

        parsed = challenger._parse_react_response(response)

        assert "analyze the task" in parsed.thought
        assert "getprop command" in parsed.thought

    def test_case_insensitive_parsing(self, challenger):
        """Parsing is case-insensitive for keywords."""
        response = """thought: Testing case sensitivity.

action: shell echo test"""

        parsed = challenger._parse_react_response(response)

        assert "Testing case sensitivity" in parsed.thought
        assert "shell echo test" in parsed.action


class TestInferActionType:
    """Tests for _infer_action_type method."""

    @pytest.fixture
    def challenger(self):
        """Create a challenger instance for testing."""
        import tempfile

        from dojo.trajectory_logger import TrajectoryLogger

        logger = TrajectoryLogger(output_dir=tempfile.mkdtemp(), auto_save=False)
        return ReActChallenger(
            llm_client=MockLLM(),
            executor=MockExecutor(),
            trajectory_logger=logger,
        )

    def test_adb_shell(self, challenger):
        """Detects adb_shell action type."""
        assert challenger._infer_action_type("shell getprop test") == "adb_shell"

    def test_adb_command_push(self, challenger):
        """Detects adb_command for push."""
        assert challenger._infer_action_type("push /local/file /remote") == "adb_command"

    def test_adb_command_pull(self, challenger):
        """Detects adb_command for pull."""
        assert challenger._infer_action_type("pull /remote/file /local") == "adb_command"

    def test_adb_command_install(self, challenger):
        """Detects adb_command for install."""
        assert challenger._infer_action_type("install app.apk") == "adb_command"

    def test_frida_script(self, challenger):
        """Detects frida_script action type."""
        assert challenger._infer_action_type("frida -U -f com.app") == "frida_script"

    def test_frida_java(self, challenger):
        """Detects frida_script for Java hooks."""
        assert challenger._infer_action_type("Java.perform(function() {})") == "frida_script"

    def test_default_adb_shell(self, challenger):
        """Defaults to adb_shell for unknown commands."""
        assert challenger._infer_action_type("some unknown command") == "adb_shell"


class TestInferReasoningType:
    """Tests for _infer_reasoning_type method."""

    @pytest.fixture
    def challenger(self):
        """Create a challenger instance for testing."""
        import tempfile

        from dojo.trajectory_logger import TrajectoryLogger

        logger = TrajectoryLogger(output_dir=tempfile.mkdtemp(), auto_save=False)
        return ReActChallenger(
            llm_client=MockLLM(),
            executor=MockExecutor(),
            trajectory_logger=logger,
        )

    def test_error_analysis(self, challenger):
        """Detects error analysis reasoning."""
        thought = "The command failed with permission denied"
        assert challenger._infer_reasoning_type(thought) == ReasoningType.ERROR_ANALYSIS

    def test_strategy_pivot(self, challenger):
        """Detects strategy pivot reasoning."""
        thought = "Let me try a different approach instead"
        assert challenger._infer_reasoning_type(thought) == ReasoningType.STRATEGY_PIVOT

    def test_goal_decomposition(self, challenger):
        """Detects goal decomposition reasoning."""
        thought = "First, I need to understand the app structure"
        assert challenger._infer_reasoning_type(thought) == ReasoningType.GOAL_DECOMPOSITION

    def test_tool_selection(self, challenger):
        """Detects tool selection reasoning."""
        thought = "I'll use the ADB command to query this"
        assert challenger._infer_reasoning_type(thought) == ReasoningType.TOOL_SELECTION

    def test_verification(self, challenger):
        """Detects verification reasoning."""
        thought = "Let me verify that the output is correct"
        assert challenger._infer_reasoning_type(thought) == ReasoningType.VERIFICATION


class TestEstimateConfidence:
    """Tests for _estimate_confidence method."""

    @pytest.fixture
    def challenger(self):
        """Create a challenger instance for testing."""
        import tempfile

        from dojo.trajectory_logger import TrajectoryLogger

        logger = TrajectoryLogger(output_dir=tempfile.mkdtemp(), auto_save=False)
        return ReActChallenger(
            llm_client=MockLLM(),
            executor=MockExecutor(),
            trajectory_logger=logger,
        )

    def test_high_confidence(self, challenger):
        """Detects high confidence from thought."""
        thought = "I definitely know this command will work"
        assert challenger._estimate_confidence(thought) == 0.9

    def test_low_confidence(self, challenger):
        """Detects low confidence from thought."""
        thought = "Maybe this will work, I'm not sure"
        assert challenger._estimate_confidence(thought) == 0.4

    def test_medium_confidence_default(self, challenger):
        """Returns medium confidence by default."""
        thought = "Running the command now"
        assert challenger._estimate_confidence(thought) == 0.7
