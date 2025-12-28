"""Context injector - builds prompts with structured context blocks.

Uses clear delimiters for each section to enable:
1. Easier model learning of prompt structure
2. Automatic validation/checking of prompts
3. Consistent parsing for training data extraction

Block Types:
    [TASK] - Original task description
    [DEVICE_CONTEXT] - Target device information
    [HINTS] - Optional hints for the challenge
    [OUTPUT_FORMAT] - Expected output format specification
    [FAILED_COMMAND] - Previous failed attempt
    [ERROR] - Structured error information with type and message
    [RAW_STDERR] - Raw stderr when structured error unavailable
    [SUGGESTIONS] - Suggestions for fixing the error
    [INSTRUCTIONS] - Instructions for the current attempt
    [REFERENCE] - Reference examples/blueprints
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from dojo.curriculum.error_extractor import ErrorContext
from dojo.models import Challenge


class BlockType(Enum):
    """Enumeration of structured context block types."""

    TASK = "TASK"
    DEVICE_CONTEXT = "DEVICE_CONTEXT"
    HINTS = "HINTS"
    OUTPUT_FORMAT = "OUTPUT_FORMAT"
    FAILED_COMMAND = "FAILED_COMMAND"
    ERROR = "ERROR"
    RAW_STDERR = "RAW_STDERR"
    SUGGESTIONS = "SUGGESTIONS"
    INSTRUCTIONS = "INSTRUCTIONS"
    REFERENCE = "REFERENCE"
    ATTEMPT_INFO = "ATTEMPT_INFO"


@dataclass
class ContextBlock:
    """A structured context block with type and content."""

    block_type: BlockType
    content: str
    metadata: Optional[Dict[str, str]] = None

    def render(self) -> str:
        """Render the block with delimiters."""
        tag = self.block_type.value

        # For ERROR blocks, include metadata as attributes
        if self.metadata and self.block_type == BlockType.ERROR:
            attrs = "; ".join(f"{k}={v}" for k, v in self.metadata.items())
            return f"[{tag}] {attrs}\n{self.content}\n[/{tag}]"

        return f"[{tag}]\n{self.content}\n[/{tag}]"


class ContextInjector:
    """Inject structured error context into prompts for retry attempts.

    All prompts use structured blocks with clear delimiters for:
    - Machine-readable parsing
    - Consistent training data extraction
    - Automatic validation

    Instructions are context-aware based on error type to align with suggestions.
    """

    # Error-type-specific instruction templates with explicit constraints
    # Each template has: CONSTRAINT (what you must/must not do) + ACTION (what to output)
    ERROR_INSTRUCTIONS: Dict[str, str] = {
        "permission_denied": (
            "CONSTRAINT: You MUST NOT retry the same command or any variation that reads "
            "the same protected path. Blindly re-running 'cat', 'ls', or similar on "
            "/data/*, /proc/kallsyms, or other protected paths will fail again.\n\n"
            "ACTION: You MUST pivot strategy as described in SUGGESTIONS. Output ONE "
            "replacement command that either:\n"
            "  - Uses an unprivileged alternative (e.g., 'getprop' instead of reading files)\n"
            "  - Searches for privilege escalation vectors (SUID binaries, kernel info)\n"
            "  - Uses 'run-as <pkg>' if targeting app-specific data"
        ),
        "command_not_found": (
            "CONSTRAINT: The binary you tried does NOT exist on Android. You MUST NOT "
            "retry with the same tool name or assume it will appear.\n\n"
            "ACTION: You MUST choose an existing Android binary. Output ONE replacement "
            "command using:\n"
            "  - Toybox/toolbox equivalents (check /system/bin)\n"
            "  - Shell builtins (printf, echo, test)\n"
            "  - Alternative tools listed in SUGGESTIONS"
        ),
        "device_offline": (
            "CONSTRAINT: The device is unreachable. You MUST NOT retry the original "
            "command - it will fail immediately.\n\n"
            "ACTION: You MUST first verify connectivity. Output ONE command that:\n"
            "  - Checks device status ('adb devices')\n"
            "  - Restarts ADB server if needed ('adb kill-server && adb start-server')\n"
            "  - Only after connectivity is confirmed, retry the original task"
        ),
        "timeout": (
            "CONSTRAINT: Your command took too long. You MUST NOT retry the same "
            "long-running command.\n\n"
            "ACTION: You MUST simplify. Output ONE replacement command that:\n"
            "  - Targets a smaller scope (fewer files, specific path)\n"
            "  - Adds limits (head, tail, timeout prefix)\n"
            "  - Breaks the task into a single focused step"
        ),
        "syntax_error": (
            "CONSTRAINT: Your command has invalid syntax. You MUST fix the specific "
            "syntax issue, not change the overall approach.\n\n"
            "ACTION: You MUST correct the syntax. Output ONE replacement command that:\n"
            "  - Fixes quoting/escaping issues\n"
            "  - Corrects flag usage for Android's limited toolset\n"
            "  - Maintains the original intent with valid syntax"
        ),
        "connection_refused": (
            "CONSTRAINT: The target port/service rejected the connection. You MUST NOT "
            "blindly retry the same connection.\n\n"
            "ACTION: You MUST verify the target. Output ONE command that:\n"
            "  - Checks if the service is running (ps, netstat)\n"
            "  - Verifies the correct port number\n"
            "  - Uses an alternative approach if the service is down"
        ),
        "segfault": (
            "CONSTRAINT: The binary crashed. This is a compatibility issue. You MUST NOT "
            "retry the same command - it will crash again.\n\n"
            "ACTION: You MUST use a different approach. Output ONE replacement command that:\n"
            "  - Uses a different binary to achieve the same goal\n"
            "  - Avoids the problematic operation entirely\n"
            "  - Gathers information about the crash if needed for debugging"
        ),
    }

    # Default instruction for unknown error types
    DEFAULT_INSTRUCTION = (
        "CONSTRAINT: The previous command failed. You MUST NOT blindly retry it.\n\n"
        "ACTION: Analyze the ERROR block and apply SUGGESTIONS. Output ONE replacement "
        "command that directly addresses the failure cause."
    )

    # Script-type-specific output format templates
    OUTPUT_FORMAT_TEMPLATES: Dict[str, str] = {
        "shell": (
            "FORMAT: Return a single ADB shell command on ONE line.\n"
            "START WITH: 'shell ' prefix (e.g., 'shell ls /sdcard')\n"
            "NO EXTRA TEXT: No explanations, no comments, no markdown."
        ),
        "frida": (
            "FORMAT: Return a complete Frida JavaScript snippet.\n"
            "STRUCTURE: Must include Java.perform() or Interceptor.attach() as appropriate.\n"
            "NO EXTRA TEXT: No explanations, no markdown code blocks."
        ),
        "c_exploit": (
            "FORMAT: Return complete C source code.\n"
            "STRUCTURE: Must include necessary #include headers and main() or exploit function.\n"
            "NO EXTRA TEXT: No explanations, no markdown code blocks."
        ),
        "python": (
            "FORMAT: Return a complete Python script.\n"
            "STRUCTURE: Must be directly executable with python3.\n"
            "NO EXTRA TEXT: No explanations, no markdown code blocks."
        ),
    }

    # Default format template
    DEFAULT_FORMAT_TEMPLATE = (
        "FORMAT: Return the command/script on a single output.\n"
        "NO EXTRA TEXT: No explanations, no comments, no markdown."
    )

    # Do/Don't block - explicit behavioral constraints
    DO_DONT_BLOCK = """
DO:
  ✓ Output ONLY the executable command/script
  ✓ Change only what is necessary to fix the issue
  ✓ Follow the format specified in OUTPUT_FORMAT
  ✓ Use commands/APIs available on Android 7.0

DON'T:
  ✗ Add explanations or commentary
  ✗ Wrap output in quotes, backticks, or markdown
  ✗ Propose privilege escalation beyond what HINTS suggest
  ✗ Include multiple alternative commands (pick ONE)
  ✗ Add comments inside the command/script
""".strip()

    def __init__(self, max_attempts: int = 3, verbose: bool = True):
        """
        Initialize context injector.

        Args:
            max_attempts: Maximum retry attempts.
            verbose: If True, use detailed blocks. If False, use minimal blocks.
        """
        self.max_attempts = max_attempts
        self.verbose = verbose

    def build_block(
        self,
        block_type: BlockType,
        content: str,
        metadata: Optional[Dict[str, str]] = None,
    ) -> ContextBlock:
        """Create a structured context block."""
        return ContextBlock(block_type=block_type, content=content, metadata=metadata)

    def render_blocks(self, blocks: List[ContextBlock]) -> str:
        """Render multiple blocks into a single prompt string."""
        return "\n\n".join(block.render() for block in blocks)

    def build_initial_prompt(self, challenge: Challenge) -> str:
        """
        Build the initial prompt for a challenge (before any retries).

        Args:
            challenge: The challenge to attempt.

        Returns:
            Initial prompt string with structured blocks.
        """
        blocks: List[ContextBlock] = []

        # Task block
        blocks.append(self.build_block(BlockType.TASK, challenge.description))

        # Device context block
        if challenge.inputs.device_context:
            context_lines = [
                f"{key}: {value}"
                for key, value in challenge.inputs.device_context.items()
            ]
            blocks.append(
                self.build_block(BlockType.DEVICE_CONTEXT, "\n".join(context_lines))
            )

        # Hints block
        if challenge.hints:
            hint_lines = [f"- {hint}" for hint in challenge.hints]
            blocks.append(self.build_block(BlockType.HINTS, "\n".join(hint_lines)))

        # Output format block - script-type-specific
        script_type = challenge.expected_output.script_type.value
        format_template = self.OUTPUT_FORMAT_TEMPLATES.get(
            script_type, self.DEFAULT_FORMAT_TEMPLATE
        )
        blocks.append(self.build_block(BlockType.OUTPUT_FORMAT, format_template))

        # Instructions block with Do/Don't
        instructions = (
            "Generate the requested command/script.\n\n"
            f"{self.DO_DONT_BLOCK}"
        )
        blocks.append(self.build_block(BlockType.INSTRUCTIONS, instructions))

        return self.render_blocks(blocks)

    def build_retry_prompt(
        self,
        challenge: Challenge,
        previous_output: str,
        error_context: ErrorContext,
        attempt_number: int,
    ) -> str:
        """
        Build a retry prompt with structured error context.

        Args:
            challenge: The original challenge.
            previous_output: The model's failed output.
            error_context: Extracted error information.
            attempt_number: Current attempt number (1-indexed).

        Returns:
            New prompt with structured error context for retry.
        """
        blocks: List[ContextBlock] = []

        # Task block (original task)
        blocks.append(self.build_block(BlockType.TASK, challenge.description))

        # Failed command block
        blocks.append(
            self.build_block(BlockType.FAILED_COMMAND, previous_output.strip())
        )

        # Error block with structured metadata
        error_content = self._format_error_content(error_context)
        error_metadata = {
            "type": error_context.error_type,
            "message": error_context.error_message[:100],  # Truncate for readability
        }
        blocks.append(
            self.build_block(BlockType.ERROR, error_content, metadata=error_metadata)
        )

        # Suggestions block
        if error_context.suggestions:
            suggestion_lines = [f"- {s}" for s in error_context.suggestions]
            blocks.append(
                self.build_block(BlockType.SUGGESTIONS, "\n".join(suggestion_lines))
            )
        else:
            blocks.append(
                self.build_block(
                    BlockType.SUGGESTIONS,
                    "- Review the error message and adjust your approach",
                )
            )

        # Attempt info block
        attempt_info = (
            f"Attempt: {attempt_number} of {self.max_attempts}\n"
            f"Status: Previous attempt failed, correction needed"
        )
        blocks.append(self.build_block(BlockType.ATTEMPT_INFO, attempt_info))

        # Instructions block - context-aware based on error type
        instructions = self._get_error_instructions(error_context.error_type)
        blocks.append(self.build_block(BlockType.INSTRUCTIONS, instructions))

        return self.render_blocks(blocks)

    def _get_error_instructions(self, error_type: str) -> str:
        """
        Get error-type-specific instructions that align with suggestions.

        Args:
            error_type: The type of error encountered.

        Returns:
            Instructions string appropriate for this error type.
        """
        base_instruction = self.ERROR_INSTRUCTIONS.get(
            error_type, self.DEFAULT_INSTRUCTION
        )

        # Add common suffix
        return f"{base_instruction}\nOutput only the command/script, no explanations."

    def build_raw_failure_prompt(
        self,
        challenge: Challenge,
        previous_output: str,
        raw_stderr: str,
        attempt_number: int,
    ) -> str:
        """
        Build a retry prompt when no structured error context is available.

        Args:
            challenge: The original challenge.
            previous_output: The model's failed output.
            raw_stderr: Raw stderr from execution.
            attempt_number: Current attempt number (1-indexed).

        Returns:
            New prompt with raw error for retry.
        """
        blocks: List[ContextBlock] = []

        # Task block
        blocks.append(self.build_block(BlockType.TASK, challenge.description))

        # Failed command block
        blocks.append(
            self.build_block(BlockType.FAILED_COMMAND, previous_output.strip())
        )

        # Raw stderr block (truncated if too long)
        max_stderr_len = 500
        stderr_content = raw_stderr.strip() or "[No error output captured]"
        if len(stderr_content) > max_stderr_len:
            stderr_content = stderr_content[:max_stderr_len] + "\n... [truncated]"
        blocks.append(self.build_block(BlockType.RAW_STDERR, stderr_content))

        # Attempt info block
        attempt_info = (
            f"Attempt: {attempt_number} of {self.max_attempts}\n"
            f"Status: Previous attempt failed with unrecognized error"
        )
        blocks.append(self.build_block(BlockType.ATTEMPT_INFO, attempt_info))

        # Instructions block
        instructions = (
            "Analyze the error output above and provide a corrected version.\n"
            "Output only the command/script, no explanations."
        )
        blocks.append(self.build_block(BlockType.INSTRUCTIONS, instructions))

        return self.render_blocks(blocks)

    def build_system_prompt(self, challenge: Challenge) -> str:
        """
        Build a system prompt for the challenge with structured blocks.

        Args:
            challenge: The challenge to build system prompt for.

        Returns:
            System prompt string with structured blocks.
        """
        script_type = challenge.expected_output.script_type.value
        blocks: List[ContextBlock] = []

        # Role/context instruction (not in a block - this is meta-instruction)
        role = f"You are an Android security expert. Generate {script_type} logic that executes correctly on Android devices."

        # Device context block
        device_context = (
            "OS Version: Android 7.0 (Legacy command syntax)\n"
            "Available Tools: 'netstat' available, 'ss' NOT available\n"
            "Privileges: NO root access (unless stated in challenge)\n"
            "Security: SELinux is ENFORCING"
        )
        blocks.append(self.build_block(BlockType.DEVICE_CONTEXT, device_context))

        # Reference block based on script type
        reference_content = self._get_reference_content(script_type)
        blocks.append(self.build_block(BlockType.REFERENCE, reference_content))

        # Output format block - script-type-specific with Do/Don't
        format_template = self.OUTPUT_FORMAT_TEMPLATES.get(
            script_type, self.DEFAULT_FORMAT_TEMPLATE
        )
        output_rules = f"{format_template}\n\n{self.DO_DONT_BLOCK}"
        blocks.append(self.build_block(BlockType.OUTPUT_FORMAT, output_rules))

        # Attempt info with belt/difficulty
        attempt_info = (
            f"Belt Level: {challenge.belt.display}\n"
            f"Difficulty: {challenge.difficulty}/5"
        )
        blocks.append(self.build_block(BlockType.ATTEMPT_INFO, attempt_info))

        # Combine role with blocks
        return role + "\n\n" + self.render_blocks(blocks)

    def _format_error_content(self, error_context: ErrorContext) -> str:
        """Format error details for the ERROR block content."""
        lines = []

        if error_context.failed_line:
            lines.append(f"Failed Line: {error_context.failed_line}")

        if error_context.device_state:
            lines.append("Device State:")
            for key, value in error_context.device_state.items():
                lines.append(f"  {key}: {value}")

        return "\n".join(lines) if lines else "No additional error details available."

    def _get_reference_content(self, script_type: str) -> str:
        """Get reference examples based on script type."""
        if script_type == "frida":
            return (
                "Frida/JavaScript Blueprints:\n"
                "- Hook Java Method: Java.use('pkg.cls').method.implementation = function() { ... }\n"
                "- Hook Native: Interceptor.attach(Module.findExportByName(null, 'name'), { ... })\n"
                "- Log: console.log('message')\n"
                "- Read Memory: Memory.readByteArray(ptr('0x...'), length)"
            )
        elif script_type == "c_exploit":
            return (
                "C/Kernel Blueprints:\n"
                "- System Header: #include <sys/ioctl.h>\n"
                "- Credential Struct: struct cred *new_cred = prepare_kernel_cred(0);\n"
                "- Privilege Escalation: commit_creds(new_cred);\n"
                "- Device I/O: ioctl(fd, COMMAND, &args);"
            )
        else:
            # Default ADB reference
            return (
                "ADB Command Blueprints:\n"
                "- Get Android version: shell getprop ro.build.version.release\n"
                "- List packages: shell pm list packages\n"
                "- App permissions: shell dumpsys package <pkg> | grep permission\n"
                "- Start activity: shell am start -n <package>/<activity>\n"
                "- Capture logcat: shell logcat -d ActivityManager:E *:S\n"
                "- Process memory: shell cat /proc/$(pidof <process>)/maps\n"
                "- ADB forwarding: forward tcp:<port> tcp:<port>"
            )


# Utility functions for parsing structured prompts


def parse_blocks(prompt: str) -> Dict[str, str]:
    """
    Parse a structured prompt into its component blocks.

    Args:
        prompt: Prompt string with [TAG]...[/TAG] delimiters.

    Returns:
        Dictionary mapping block type names to their content.
    """
    import re

    blocks = {}
    # Match [TAG] content [/TAG] patterns
    pattern = r"\[(\w+)\](?:\s*[^[\n]*\n)?(.*?)\[/\1\]"
    matches = re.findall(pattern, prompt, re.DOTALL)

    for tag, content in matches:
        blocks[tag] = content.strip()

    return blocks


def validate_prompt_structure(prompt: str, required_blocks: List[str]) -> List[str]:
    """
    Validate that a prompt contains all required blocks.

    Args:
        prompt: Prompt string to validate.
        required_blocks: List of required block type names.

    Returns:
        List of missing block names (empty if valid).
    """
    blocks = parse_blocks(prompt)
    return [block for block in required_blocks if block not in blocks]


def extract_error_metadata(error_block: str) -> Dict[str, str]:
    """
    Extract metadata from an ERROR block header.

    Args:
        error_block: Raw ERROR block content including header.

    Returns:
        Dictionary of error metadata (type, message, etc.)
    """
    import re

    metadata = {}
    # Match key=value pairs after [ERROR]
    header_match = re.match(r"\[ERROR\]\s*(.+?)\n", error_block)
    if header_match:
        attrs = header_match.group(1)
        for pair in attrs.split(";"):
            pair = pair.strip()
            if "=" in pair:
                key, value = pair.split("=", 1)
                metadata[key.strip()] = value.strip()

    return metadata
