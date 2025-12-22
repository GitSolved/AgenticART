"""
Tests for the Agent Layer

Run with: pytest tests/test_agent.py -v
"""

import pytest
from unittest.mock import Mock, patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.llm_client import LLMClient, LLMProvider, LLMResponse
from agent.planner import Planner, PentestPhase, PlanStep
from agent.summarizer import Summarizer, ActionResult
from agent.script_generator import ScriptGenerator, ScriptType


class TestLLMClient:
    """Tests for LLM Client."""

    def test_create_openai_client(self):
        """Test creating OpenAI client."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            client = LLMClient.create(provider="openai")
            assert client is not None

    def test_create_invalid_provider(self):
        """Test that invalid provider raises error."""
        with pytest.raises(ValueError):
            LLMClient.create(provider="invalid")


class TestPlanner:
    """Tests for Planner module."""

    @pytest.fixture
    def mock_llm(self):
        """Create mock LLM client."""
        mock = Mock()
        mock.complete.return_value = LLMResponse(
            content="ACTION: Test action\nCOMMAND: test command",
            model="test",
            provider=LLMProvider.OPENAI,
            tokens_used=100,
            finish_reason="stop",
        )
        return mock

    def test_create_plan(self, mock_llm):
        """Test plan creation."""
        planner = Planner(llm_client=mock_llm)
        plan = planner.create_plan(
            target="Test device",
            objective="Test objective",
        )

        assert plan is not None
        assert plan.target == "Test device"
        assert len(plan.steps) > 0

    def test_get_next_action(self, mock_llm):
        """Test getting next action for a phase."""
        planner = Planner(llm_client=mock_llm)
        step = planner.get_next_action(
            phase=PentestPhase.RECONNAISSANCE,
            target="Test device",
            objective="Test objective",
            context="",
        )

        assert isinstance(step, PlanStep)
        assert step.phase == PentestPhase.RECONNAISSANCE


class TestSummarizer:
    """Tests for Summarizer module."""

    @pytest.fixture
    def mock_llm(self):
        """Create mock LLM client."""
        mock = Mock()
        mock.complete.return_value = LLMResponse(
            content="""RESULT: success
KEY_FINDINGS:
- Found device model: Pixel 7
- Android version: 13
VULNERABILITIES:
- None identified
NEXT_STEPS:
- Proceed to scanning phase""",
            model="test",
            provider=LLMProvider.OPENAI,
            tokens_used=100,
            finish_reason="stop",
        )
        return mock

    def test_summarize(self, mock_llm):
        """Test command output summarization."""
        summarizer = Summarizer(llm_client=mock_llm)
        summary = summarizer.summarize(
            command="adb shell getprop",
            output="ro.product.model=Pixel 7\nro.build.version.release=13",
        )

        assert summary.result == ActionResult.SUCCESS
        assert len(summary.key_findings) > 0

    def test_context_maintenance(self, mock_llm):
        """Test that context is maintained across summaries."""
        summarizer = Summarizer(llm_client=mock_llm)

        # Add multiple summaries
        summarizer.summarize("cmd1", "output1")
        summarizer.summarize("cmd2", "output2")

        context = summarizer.get_context_for_planner()
        assert context is not None
        assert len(context) > 0


class TestScriptGenerator:
    """Tests for Script Generator."""

    @pytest.fixture
    def mock_llm(self):
        """Create mock LLM client."""
        mock = Mock()
        mock.complete.return_value = LLMResponse(
            content="""```python
import subprocess

def main():
    result = subprocess.run(['adb', 'devices'], capture_output=True)
    print(result.stdout)

if __name__ == '__main__':
    main()
```""",
            model="test",
            provider=LLMProvider.OPENAI,
            tokens_used=100,
            finish_reason="stop",
        )
        return mock

    def test_generate_script(self, mock_llm):
        """Test script generation."""
        generator = ScriptGenerator(llm_client=mock_llm)

        step = PlanStep(
            phase=PentestPhase.RECONNAISSANCE,
            action="List connected devices",
            command="adb devices",
            rationale="Check device connectivity",
            risk_level="low",
        )

        script = generator.generate(
            step=step,
            target_config={"ip": "192.168.56.101"},
            script_type=ScriptType.PYTHON,
        )

        assert script is not None
        assert script.script_type == ScriptType.PYTHON
        assert "subprocess" in script.content

    def test_validate_safe_script(self, mock_llm):
        """Test validation of safe script."""
        generator = ScriptGenerator(llm_client=mock_llm)

        step = PlanStep(
            phase=PentestPhase.RECONNAISSANCE,
            action="Safe action",
            command=None,
            rationale="Test",
            risk_level="low",
        )

        script = generator.generate(step, {}, ScriptType.PYTHON)
        valid, issues = generator.validate(script)

        # Should pass basic validation (no dangerous patterns)
        assert valid or all("WARNING" in i for i in issues)

    def test_validate_dangerous_script(self):
        """Test validation catches dangerous patterns."""
        from agent.script_generator import GeneratedScript

        generator = ScriptGenerator()

        dangerous_script = GeneratedScript(
            name="dangerous",
            script_type=ScriptType.BASH,
            content="rm -rf /",
            description="Dangerous test",
            source_step=PlanStep(
                phase=PentestPhase.EXPLOITATION,
                action="Test",
                command=None,
                rationale="Test",
                risk_level="high",
            ),
        )

        valid, issues = generator.validate(dangerous_script)
        assert not valid
        assert any("BLOCKED" in i for i in issues)


class TestMemory:
    """Tests for Memory system."""

    def test_working_memory(self):
        """Test working memory operations."""
        from agent.memory import WorkingMemory

        memory = WorkingMemory()

        # Test set/get
        memory.set("key1", "value1")
        assert memory.get("key1") == "value1"

        # Test default
        assert memory.get("nonexistent", "default") == "default"

        # Test append
        memory.set("list_key", [])
        memory.append("list_key", "item1")
        memory.append("list_key", "item2")
        assert memory.get("list_key") == ["item1", "item2"]

        # Test export
        export = memory.export()
        assert "key1" in export
        assert "list_key" in export


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
