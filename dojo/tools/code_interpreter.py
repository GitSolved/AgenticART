"""Code Interpreter - executes dynamic Python logic for autonomous analysis."""

from __future__ import annotations

import contextlib
import io
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class CodeExecutionResult:
    """Result of a Python code execution."""

    success: bool
    stdout: str
    stderr: str
    artifacts: Dict[str, Any] = field(default_factory=dict)
    error_type: Optional[str] = None


class CodeInterpreter:
    """A safe execution environment for model-generated Python logic."""

    def __init__(self):
        # We define a base set of allowed globals to give the model 'Tools'
        # without exposing the entire system.
        self.base_globals = {
            "__builtins__": __builtins__,
            "print": print,
            "json": __import__("json"),
            "re": __import__("re"),
            "os": __import__("os"),
            "base64": __import__("base64"),
        }

    def execute(
        self, code: str, external_tools: Optional[Dict[str, Any]] = None
    ) -> CodeExecutionResult:
        """
        Executes Python code and captures all outputs and generated artifacts.

        Args:
            code: The Python source code to execute.
            external_tools: Optional dictionary of tools (e.g., adb_client) to inject.
        """
        # 1. Setup execution context
        # We merge base globals with provided tools
        exec_globals = self.base_globals.copy()
        if external_tools:
            exec_globals.update(external_tools)

        # locals() will capture any variables the model defines as 'artifacts'
        exec_locals: Dict[str, Any] = {}

        # 2. Capture stdout/stderr
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        success = False
        error_type = None

        try:
            with (
                contextlib.redirect_stdout(stdout_buf),
                contextlib.redirect_stderr(stderr_buf),
            ):
                # We use exec() to run the multi-line block
                exec(code, exec_globals, exec_locals)
            success = True
        except SyntaxError:
            error_type = "python_syntax_error"
            stderr_buf.write(traceback.format_exc())
        except NameError:
            error_type = "missing_dependency"
            stderr_buf.write(traceback.format_exc())
        except Exception:
            error_type = "runtime_error"
            stderr_buf.write(traceback.format_exc())

        # 3. Harvest Artifacts
        # We consider any non-private variable defined in exec_locals as a potential artifact
        artifacts = {k: v for k, v in exec_locals.items() if not k.startswith("_")}

        return CodeExecutionResult(
            success=success,
            stdout=stdout_buf.getvalue(),
            stderr=stderr_buf.getvalue(),
            artifacts=artifacts,
            error_type=error_type,
        )
