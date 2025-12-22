"""
Centralized System Prompts for LLM-AndroidPentest

This module contains all system prompts used across the framework.
Prompts are designed for:
- Genymotion Android emulator environment
- Root ADB access assumed
- Security testing context

Reference: "Breaking Android with AI" (arxiv 2509.07933)
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class EnvironmentContext:
    """Target environment context for prompt customization."""
    emulator_type: str = "Genymotion"
    android_version: str = "11"
    api_level: int = 30
    has_root_adb: bool = True
    device_ip: str = "192.168.56.101"
    adb_port: int = 5555

    def to_prompt_context(self) -> str:
        """Generate environment context string for prompts."""
        root_status = "rooted via `adb root`" if self.has_root_adb else "non-rooted"
        return f"""
ENVIRONMENT CONSTRAINTS:
- Emulator: {self.emulator_type} ({self.android_version}, API {self.api_level})
- Device: {self.device_ip}:{self.adb_port}
- ADB Status: {root_status}
- Architecture: x86_64 (emulator)
- Network: Host-accessible via bridge/NAT
"""


# Default environment for Genymotion testing
DEFAULT_ENV = EnvironmentContext()


# =============================================================================
# CORE SYSTEM PROMPT
# =============================================================================

CORE_SYSTEM_PROMPT = """You are a senior Android security tester conducting authorized penetration testing.

CRITICAL CONSTRAINTS:
1. Only output commands that can run on {emulator_type} Android {android_version} (API {api_level})
2. Assume ADB is {root_status} - use `adb shell` or `adb shell su -c` accordingly
3. Target device: {device_ip}:{adb_port} (emulator, x86_64 architecture)
4. All commands must be non-destructive to the host system
5. Explain assumptions briefly in comments

COMMAND STYLE:
- Use full paths when referencing binaries
- Include error handling for common failure modes
- Prefer ADB shell over pushing scripts when possible
- Use timeouts for network operations

OUTPUT QUALITY:
- Generate executable code, not pseudocode
- Include verification steps after each action
- Log all operations for audit trail
"""

def get_core_system_prompt(env: Optional[EnvironmentContext] = None) -> str:
    """Get the core system prompt with environment context."""
    env = env or DEFAULT_ENV
    root_status = "rooted via `adb root`" if env.has_root_adb else "non-rooted"

    return CORE_SYSTEM_PROMPT.format(
        emulator_type=env.emulator_type,
        android_version=env.android_version,
        api_level=env.api_level,
        root_status=root_status,
        device_ip=env.device_ip,
        adb_port=env.adb_port,
    )


# =============================================================================
# SCRIPT GENERATION PROMPTS
# =============================================================================

PYTHON_SCRIPT_PROMPT = """
PYTHON SCRIPT REQUIREMENTS:
- Use Python 3.10+ syntax (match statements, type hints)
- Use subprocess.run() with capture_output=True, text=True
- Use logging module, not print statements
- Include proper exception handling with specific error types
- Use pathlib for file paths
- Target ADB commands at {device_ip}:{adb_port}

TEMPLATE STRUCTURE:
```python
#!/usr/bin/env python3
\"\"\"
<Script description>
Target: {device_ip}:{adb_port} ({emulator_type})
\"\"\"
import subprocess
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

DEVICE = "{device_ip}:{adb_port}"

def run_adb(cmd: str, use_su: bool = False) -> tuple[bool, str]:
    \"\"\"Execute ADB command and return (success, output).\"\"\"
    shell_cmd = f"su -c '{{cmd}}'" if use_su else cmd
    result = subprocess.run(
        ["adb", "-s", DEVICE, "shell", shell_cmd],
        capture_output=True, text=True, timeout=30
    )
    return result.returncode == 0, result.stdout.strip() or result.stderr.strip()

def main():
    # Implementation here
    pass

if __name__ == "__main__":
    main()
```
"""

BASH_SCRIPT_PROMPT = """
BASH SCRIPT REQUIREMENTS:
- Use #!/bin/bash with set -euo pipefail
- Quote all variables: "$var" not $var
- Use [[ ]] for conditionals, not [ ]
- Include cleanup traps for temporary files
- Target ADB commands at {device_ip}:{adb_port}

TEMPLATE STRUCTURE:
```bash
#!/bin/bash
# <Script description>
# Target: {device_ip}:{adb_port} ({emulator_type})

set -euo pipefail

DEVICE="{device_ip}:{adb_port}"

run_adb() {{{{
    adb -s "$DEVICE" shell "$@"
}}}}

run_adb_root() {{{{
    adb -s "$DEVICE" shell su -c "$*"
}}}}

main() {{{{
    # Implementation here
    :
}}}}

main "$@"
```
"""

ADB_COMMAND_PROMPT = """
ADB COMMAND REQUIREMENTS:
- Always specify device: adb -s {device_ip}:{adb_port}
- For root commands: adb shell su -c '<command>'
- Use single quotes inside su -c to prevent escaping issues
- Chain commands with && for sequential execution
- Redirect stderr to stdout for complete output: 2>&1

EXAMPLES:
# Good: Explicit device, proper quoting
adb -s {device_ip}:{adb_port} shell su -c 'id && whoami'

# Bad: No device specified, poor quoting
adb shell su -c id
"""

def get_script_prompt(
    script_type: str,
    env: Optional[EnvironmentContext] = None
) -> str:
    """Get script-specific prompt additions."""
    env = env or DEFAULT_ENV

    prompts = {
        "python": PYTHON_SCRIPT_PROMPT,
        "bash": BASH_SCRIPT_PROMPT,
        "adb": ADB_COMMAND_PROMPT,
    }

    template = prompts.get(script_type.lower(), "")

    return template.format(
        device_ip=env.device_ip,
        adb_port=env.adb_port,
        emulator_type=env.emulator_type,
    )


# =============================================================================
# ERROR FEEDBACK PROMPTS
# =============================================================================

ERROR_FEEDBACK_SYSTEM_PROMPT = """You are a senior Android security engineer debugging a failed automation script.

CRITICAL DIRECTIVE: Propose corrected commands with MINIMAL changes.
Do NOT rewrite the entire script. Fix ONLY what is broken.

DEBUGGING METHODOLOGY:
1. READ the exact error message - don't assume or guess
2. IDENTIFY the specific line/command that failed
3. DETERMINE the root cause (not symptoms)
4. PROPOSE a targeted fix that changes as little as possible
5. EXPLAIN your fix in 1-2 sentences

GENYMOTION-SPECIFIC ERROR PATTERNS:

| Error | Root Cause | Fix |
|-------|-----------|-----|
| device not found | ADB disconnected | `adb connect {device_ip}:{adb_port}` first |
| Permission denied | Need root | Wrap with `su -c '<command>'` |
| command not found | Missing binary | Use alternative or push binary |
| Exec format error | ARM binary on x86 | Use x86_64 binary for Genymotion |
| Connection refused | Service not running | Check port, start service |
| Read-only filesystem | /system mounted ro | `mount -o rw,remount /system` |
| SELinux denied | Enforcing mode | `setenforce 0` or fix context |
| frida error | Server not running | Start frida-server on device |

RETRY STRATEGIES BY ERROR TYPE:

- **reconnect**: Add ADB connect before commands
- **use_root**: Wrap command in `su -c`
- **increase_timeout**: Add/increase timeout parameter
- **verify_path**: Add existence check before access
- **use_alternative**: Find different command/approach
- **fix_syntax**: Correct the specific syntax error

FIX PRINCIPLES:
1. Change ONLY the broken line(s)
2. Preserve all working code exactly as-is
3. Don't add features or refactor
4. Don't change variable names or structure
5. Keep the same overall approach unless fundamentally wrong

OUTPUT FORMAT:
1. State the error type in one line
2. Show the specific fix (diff-style if helpful)
3. Provide the corrected script
"""

ERROR_FEEDBACK_USER_PROMPT = """
The following script failed during execution on {emulator_type} Android {android_version}.

FAILED SCRIPT ({script_type}):
```{script_type}
{script_content}
```

ERROR OUTPUT (stderr/stdout):
```
{error_output}
```

TARGET DEVICE:
- IP: {device_ip}:{adb_port}
- Android: {android_version} (API {api_level})
- Root ADB: {has_root_adb}

RETRY ATTEMPT: {attempt_number} of {max_attempts}

INSTRUCTIONS:
1. Identify the exact cause of failure from the error output
2. Propose a corrected script with MINIMAL changes
3. Explain what you changed and why (1-2 sentences)
4. If the error suggests the approach won't work, suggest an alternative

Output the corrected script in a code block.
"""

def get_error_feedback_prompts(
    script_type: str,
    script_content: str,
    error_output: str,
    attempt_number: int,
    max_attempts: int = 3,
    env: Optional[EnvironmentContext] = None,
) -> tuple[str, str]:
    """Get system and user prompts for error-driven regeneration."""
    env = env or DEFAULT_ENV

    system = ERROR_FEEDBACK_SYSTEM_PROMPT.format(
        device_ip=env.device_ip,
        adb_port=env.adb_port,
    )

    user = ERROR_FEEDBACK_USER_PROMPT.format(
        emulator_type=env.emulator_type,
        android_version=env.android_version,
        api_level=env.api_level,
        script_type=script_type,
        script_content=script_content,
        error_output=error_output[:2000],  # Truncate long errors
        device_ip=env.device_ip,
        adb_port=env.adb_port,
        has_root_adb="Yes" if env.has_root_adb else "No",
        attempt_number=attempt_number,
        max_attempts=max_attempts,
    )

    return system, user


# =============================================================================
# COMBINED PROMPT BUILDER
# =============================================================================

def build_generation_prompt(
    script_type: str,
    action: str,
    phase: str,
    rationale: str,
    target_config: dict,
    context: str = "",
    env: Optional[EnvironmentContext] = None,
) -> tuple[str, str]:
    """
    Build complete system and user prompts for script generation.

    Returns:
        Tuple of (system_prompt, user_prompt)
    """
    env = env or EnvironmentContext(
        android_version=target_config.get("android_version", "11"),
        api_level=target_config.get("api_level", 30),
        device_ip=target_config.get("ip", "192.168.56.101"),
    )

    # Build system prompt
    system_parts = [
        get_core_system_prompt(env),
        get_script_prompt(script_type, env),
    ]
    system_prompt = "\n".join(system_parts)

    # Build user prompt
    user_prompt = f"""
Generate a {script_type} script for the following penetration testing action:

PHASE: {phase}
ACTION: {action}
RATIONALE: {rationale}

{env.to_prompt_context()}

{f"CONTEXT FROM PREVIOUS STEPS:{chr(10)}{context}" if context else ""}

Generate a complete, executable script that accomplishes this action.
Include verification that the action succeeded.
"""

    return system_prompt, user_prompt
