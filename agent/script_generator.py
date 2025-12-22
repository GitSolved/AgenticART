"""
Script Generator

The bridge between LLM intelligence and executable automation.
Converts Planner outputs into runnable Python/Bash scripts.

This is the key innovation from the "Breaking Android with AI" paper:
PentestGPT guidance -> Script Generator -> Executable Scripts
"""

import os
import re
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from enum import Enum

from .llm_client import LLMClient, BaseLLMClient
from .planner import PlanStep
from .prompts.system_prompts import (
    EnvironmentContext,
    get_core_system_prompt,
    get_script_prompt,
    get_error_feedback_prompts,
    build_generation_prompt,
)


# Known valid tools for Android pentesting
# Reference: TOOLS.md
VALID_ANDROID_TOOLS = {
    # Android SDK
    "adb", "fastboot", "aapt", "aapt2", "apksigner", "zipalign",
    # Android shell commands
    "pm", "am", "dumpsys", "getprop", "setprop", "logcat", "content",
    "settings", "input", "screencap", "screenrecord", "wm", "svc",
    # Dynamic analysis
    "frida", "frida-ps", "frida-trace", "frida-ls-devices", "objection",
    # Static analysis
    "apktool", "jadx", "dex2jar", "jd-gui", "androguard",
    # Security frameworks
    "drozer", "mobsf",
    # Network tools
    "nmap", "netcat", "nc", "curl", "wget", "tcpdump", "wireshark",
    "mitmproxy", "mitmdump", "mitmweb", "burpsuite", "zap",
    # Database
    "sqlite3", "sqlcipher",
    # Exploit development
    "ropper", "checksec", "readelf", "objdump", "gdb", "r2", "radare2",
    # Root tools
    "su", "magisk", "supersu",
    # Shell utilities
    "busybox", "python", "python3", "bash", "sh", "zsh",
    "grep", "awk", "sed", "cat", "ls", "cd", "echo", "find", "head", "tail",
    "chmod", "chown", "mount", "umount", "ps", "kill", "top", "id", "whoami",
    "base64", "xxd", "strings", "file", "tar", "gzip", "unzip",
}

# Patterns that indicate hallucinated/placeholder paths
HALLUCINATED_PATH_PATTERNS = [
    r"/path/to/",
    r"/your/",
    r"/example/",
    r"<.*?>",  # <placeholder> style
    r"\$\{.*\}",  # ${VARIABLE} not resolved
    r"C:\\",  # Windows paths on Android/Linux
    r"\\Users\\",
]

# Patterns indicating environment-specific commands
ARCHITECTURE_INDICATORS = {
    "arm64": ["arm64-v8a", "aarch64"],
    "arm": ["armeabi-v7a", "armeabi"],
    "x86": ["x86", "i686"],
    "x86_64": ["x86_64"],
}


class ScriptType(Enum):
    BASH = "bash"
    PYTHON = "python"
    ADB = "adb"


@dataclass
class QualityMetrics:
    """Quality metrics for generated scripts."""
    hallucinated_tools: list[str] = None
    hallucinated_paths: list[str] = None
    environment_mismatches: list[str] = None
    intrusive_commands: list[str] = None
    validation_passed: bool = True

    def __post_init__(self):
        self.hallucinated_tools = self.hallucinated_tools or []
        self.hallucinated_paths = self.hallucinated_paths or []
        self.environment_mismatches = self.environment_mismatches or []
        self.intrusive_commands = self.intrusive_commands or []

    @property
    def has_issues(self) -> bool:
        return bool(
            self.hallucinated_tools or
            self.hallucinated_paths or
            self.environment_mismatches or
            self.intrusive_commands
        )

    def to_dict(self) -> dict:
        return {
            "hallucinated_tools": self.hallucinated_tools,
            "hallucinated_paths": self.hallucinated_paths,
            "environment_mismatches": self.environment_mismatches,
            "intrusive_commands": self.intrusive_commands,
            "validation_passed": self.validation_passed,
        }


@dataclass
class GeneratedScript:
    """A generated automation script."""
    name: str
    script_type: ScriptType
    content: str
    description: str
    source_step: PlanStep
    file_path: Optional[str] = None
    checksum: Optional[str] = None
    validated: bool = False
    quality_metrics: Optional[QualityMetrics] = None


class ScriptGenerator:
    """
    Converts penetration testing plans into executable scripts.

    Flow:
    1. Receive PlanStep from Planner
    2. Generate appropriate script (bash/python/adb)
    3. Validate script for safety
    4. Save to scripts/generated/
    5. Return script for review/execution
    """

    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        output_dir: str = "scripts/generated",
    ):
        self.llm = llm_client or LLMClient.create()
        self.output_dir = output_dir
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        """Create output directory if it doesn't exist."""
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(
        self,
        step: PlanStep,
        target_config: dict,
        script_type: ScriptType = ScriptType.PYTHON,
    ) -> GeneratedScript:
        """
        Generate an executable script from a plan step.

        Args:
            step: The PlanStep to convert
            target_config: Target device configuration
            script_type: Type of script to generate

        Returns:
            GeneratedScript ready for validation and execution
        """
        # Use enhanced prompts with Genymotion context
        system_prompt, generation_prompt = build_generation_prompt(
            script_type=script_type.value,
            action=step.action,
            phase=step.phase.value,
            rationale=step.rationale,
            target_config=target_config,
            context=getattr(step, 'context', ''),
        )

        response = self.llm.complete(generation_prompt, system=system_prompt)
        script_content = self._extract_code(response.content, script_type)

        script = GeneratedScript(
            name=self._generate_script_name(step),
            script_type=script_type,
            content=script_content,
            description=step.action,
            source_step=step,
        )

        return script

    def _get_system_prompt(
        self,
        script_type: ScriptType,
        target_config: Optional[dict] = None
    ) -> str:
        """
        Get system prompt for script generation.

        Uses centralized prompts from agent/prompts/system_prompts.py
        with Genymotion-specific context and root ADB assumptions.
        """
        # Build environment context from target config
        env = EnvironmentContext(
            android_version=target_config.get("android_version", "11") if target_config else "11",
            api_level=target_config.get("api_level", 30) if target_config else 30,
            device_ip=target_config.get("ip", "192.168.56.101") if target_config else "192.168.56.101",
            has_root_adb=target_config.get("has_root_adb", True) if target_config else True,
        )

        # Combine core prompt with script-type-specific additions
        core = get_core_system_prompt(env)
        script_specific = get_script_prompt(script_type.value, env)

        return core + "\n" + script_specific

    def _extract_code(self, response: str, script_type: ScriptType) -> str:
        """Extract code block from LLM response."""
        # Try to find fenced code block
        patterns = [
            rf"```{script_type.value}\n(.*?)```",
            rf"```\n(.*?)```",
            r"```python\n(.*?)```",
            r"```bash\n(.*?)```",
        ]

        for pattern in patterns:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                return match.group(1).strip()

        # If no code block, return cleaned response
        return response.strip()

    def _generate_script_name(self, step: PlanStep) -> str:
        """Generate unique script name."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        phase = step.phase.value
        action_slug = re.sub(r"[^a-z0-9]+", "_", step.action.lower())[:30]
        return f"{phase}_{action_slug}_{timestamp}"

    def validate(self, script: GeneratedScript) -> tuple[bool, list[str]]:
        """
        Validate a generated script for safety.

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []

        # Check for dangerous patterns
        dangerous_patterns = [
            (r"rm\s+-rf\s+/", "Dangerous recursive delete from root"),
            (r"dd\s+if=/dev/zero", "Disk wipe command detected"),
            (r"mkfs\.", "Filesystem format command detected"),
            (r">\s*/dev/sd", "Direct device write detected"),
            (r"chmod\s+777\s+/", "Overly permissive chmod on root"),
        ]

        for pattern, message in dangerous_patterns:
            if re.search(pattern, script.content):
                issues.append(f"BLOCKED: {message}")

        # Check for required safety elements
        if script.script_type == ScriptType.PYTHON:
            if "try:" not in script.content:
                issues.append("WARNING: No try/except error handling")
            if "logging" not in script.content and "print" not in script.content:
                issues.append("WARNING: No logging/output")

        elif script.script_type == ScriptType.BASH:
            if "set -e" not in script.content:
                issues.append("WARNING: Missing 'set -e' for error handling")

        script.validated = len([i for i in issues if i.startswith("BLOCKED")]) == 0
        return script.validated, issues

    def check_quality(
        self,
        script: GeneratedScript,
        target_config: Optional[dict] = None,
    ) -> QualityMetrics:
        """
        Perform comprehensive quality checks for LLM-generated scripts.

        Detects:
        - Hallucinated tools (tools that don't exist)
        - Hallucinated paths (placeholder paths)
        - Environment mismatches (wrong architecture, etc.)
        - Intrusive commands (beyond basic dangerous patterns)

        Args:
            script: The generated script to check
            target_config: Target device config for environment matching

        Returns:
            QualityMetrics with all detected issues
        """
        metrics = QualityMetrics()

        # Check for hallucinated tools
        metrics.hallucinated_tools = self._detect_hallucinated_tools(script.content)

        # Check for hallucinated paths
        metrics.hallucinated_paths = self._detect_hallucinated_paths(script.content)

        # Check for environment mismatches
        if target_config:
            metrics.environment_mismatches = self._detect_environment_mismatches(
                script.content, target_config
            )

        # Check for intrusive commands
        metrics.intrusive_commands = self._detect_intrusive_commands(script.content)

        # Set overall validation status
        metrics.validation_passed = not metrics.has_issues

        # Attach metrics to script
        script.quality_metrics = metrics

        return metrics

    def _detect_hallucinated_tools(self, content: str) -> list[str]:
        """
        Detect tools referenced in script that may not exist.

        Focuses on shell command invocations, not Python code constructs.
        """
        hallucinated = []

        # Common Python/programming words to ignore
        ignore_words = {
            # Python keywords and builtins
            "if", "for", "while", "then", "else", "do", "done", "in", "case",
            "esac", "fi", "def", "class", "import", "from", "return", "try",
            "except", "with", "as", "and", "or", "not", "none", "true", "false",
            # Common variable/function names
            "run", "command", "result", "output", "error", "status", "data",
            "config", "path", "name", "value", "args", "kwargs", "self", "cls",
            "device_ip", "adb_path", "target", "host", "port", "timeout",
            "target_device_ip", "logging", "subprocess", "main", "print",
            # Common module names
            "os", "sys", "re", "json", "time", "datetime", "typing", "dataclass",
        }

        # Patterns that indicate actual shell command execution
        shell_command_patterns = [
            # Bash: commands after pipe or semicolon in shell strings
            r"shell\s+['\"]?([a-z][a-z0-9_-]+)",  # adb shell <cmd>
            r"\|\s*([a-z][a-z0-9_-]+)\s",  # After pipe
            r"&&\s*([a-z][a-z0-9_-]+)\s",  # After &&
            # Python subprocess with command list
            r"subprocess\.run\(\[['\"]([a-z][a-z0-9_-]+)['\"]",
            r"Popen\(\[['\"]([a-z][a-z0-9_-]+)['\"]",
            # Shell strings in Python
            r"shell=True.*?['\"]([a-z][a-z0-9_-]+)\s",
        ]

        for pattern in shell_command_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                tool = match.group(1).lower()
                if tool not in VALID_ANDROID_TOOLS and tool not in ignore_words:
                    if len(tool) > 2 and tool not in hallucinated:
                        hallucinated.append(tool)

        return hallucinated

    def _detect_hallucinated_paths(self, content: str) -> list[str]:
        """
        Detect placeholder or clearly fake paths in generated scripts.
        """
        hallucinated = []

        for pattern in HALLUCINATED_PATH_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # Get more context around the match
                full_match = re.search(rf"['\"]?[^\s'\"]*{re.escape(match)}[^\s'\"]*['\"]?", content)
                if full_match:
                    path = full_match.group(0)
                    if path not in hallucinated:
                        hallucinated.append(path)

        return hallucinated

    def _detect_environment_mismatches(
        self, content: str, target_config: dict
    ) -> list[str]:
        """
        Detect commands that may not work on the target environment.
        """
        mismatches = []

        target_arch = target_config.get("architecture", "").lower()

        # Check architecture-specific commands
        for arch, indicators in ARCHITECTURE_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in content.lower():
                    if target_arch and arch not in target_arch:
                        mismatches.append(
                            f"Script references {arch} but target is {target_arch}"
                        )
                        break

        # Check for Android version-specific features
        try:
            target_api = int(target_config.get("api_level", 0))
            if target_api >= 30 and "/sdcard/" in content:
                mismatches.append("Direct /sdcard access may be restricted on API 30+")
        except ValueError:
            pass

        return mismatches

    def _detect_intrusive_commands(self, content: str) -> list[str]:
        """
        Detect potentially intrusive or destructive commands beyond basic checks.
        """
        intrusive = []

        intrusive_patterns = [
            # Network attacks
            (r"arpspoof", "ARP spoofing detected"),
            (r"ettercap", "Network interception tool detected"),
            (r"bettercap", "Network attack framework detected"),
            (r"mitmproxy", "MITM proxy detected - ensure authorized"),

            # System modifications
            (r"flash_image", "Flash image command - very destructive"),
            (r"fastboot\s+flash", "Fastboot flash detected - verify target"),
            (r"dd\s+of=/dev/", "Direct device write detected"),
            (r"wipe\s+data", "Data wipe command detected"),
            (r"factory.*reset", "Factory reset command detected"),

            # Persistence mechanisms
            (r"/system/bin/.*\.so", "System library modification"),
            (r"pm\s+install.*-r", "Force reinstall detected"),
            (r"setenforce\s+0", "SELinux disable detected"),

            # Data exfiltration indicators
            (r"curl.*-F.*file=", "File upload via curl"),
            (r"nc\s+-e\s+/bin", "Netcat reverse shell"),
            (r"base64.*\|.*curl", "Encoded data exfiltration"),

            # Credential access
            (r"/data/system/.*\.key", "Keystore access"),
            (r"accounts\.db", "Account database access"),
            (r"locksettings\.db", "Lock settings access"),
        ]

        for pattern, message in intrusive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                intrusive.append(message)

        return intrusive

    def validate_with_quality(
        self,
        script: GeneratedScript,
        target_config: Optional[dict] = None,
    ) -> tuple[bool, list[str], QualityMetrics]:
        """
        Combined validation and quality check.

        Returns:
            Tuple of (is_valid, issues, quality_metrics)
        """
        # Run basic validation
        is_valid, issues = self.validate(script)

        # Run quality checks
        metrics = self.check_quality(script, target_config)

        # Add quality issues to validation issues
        for tool in metrics.hallucinated_tools:
            issues.append(f"HALLUCINATION: Unknown tool '{tool}'")

        for path in metrics.hallucinated_paths:
            issues.append(f"HALLUCINATION: Placeholder path '{path}'")

        for mismatch in metrics.environment_mismatches:
            issues.append(f"ENV_MISMATCH: {mismatch}")

        for intrusive in metrics.intrusive_commands:
            issues.append(f"INTRUSIVE: {intrusive}")

        # Block if hallucinations detected
        if metrics.hallucinated_tools or metrics.hallucinated_paths:
            is_valid = False
            script.validated = False

        return is_valid, issues, metrics

    def save(self, script: GeneratedScript) -> str:
        """
        Save script to file.

        Returns:
            Path to saved script
        """
        extension = {
            ScriptType.PYTHON: ".py",
            ScriptType.BASH: ".sh",
            ScriptType.ADB: ".adb",
        }

        filename = f"{script.name}{extension[script.script_type]}"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w") as f:
            f.write(script.content)

        # Make executable for bash scripts
        if script.script_type == ScriptType.BASH:
            os.chmod(filepath, 0o755)

        script.file_path = filepath
        script.checksum = hashlib.md5(script.content.encode()).hexdigest()

        return filepath

    def generate_from_prompt(
        self,
        prompt: str,
        target_config: dict,
        script_type: ScriptType = ScriptType.PYTHON,
    ) -> GeneratedScript:
        """
        Generate script directly from a natural language prompt.
        This mimics the paper's web application flow.

        Args:
            prompt: Natural language description from PentestGPT
            target_config: Target device configuration
            script_type: Type of script to generate

        Returns:
            GeneratedScript ready for validation
        """
        # Create a synthetic PlanStep from the prompt
        from .planner import PentestPhase

        step = PlanStep(
            phase=PentestPhase.EXPLOITATION,  # Default phase
            action=prompt,
            command=None,
            rationale="Generated from natural language prompt",
            risk_level="medium",
        )

        return self.generate(step, target_config, script_type)

    def regenerate_with_feedback(
        self,
        failed_script: GeneratedScript,
        error_output: str,
        target_config: dict,
        attempt_number: int = 1,
    ) -> GeneratedScript:
        """
        Regenerate a script based on execution failure feedback.

        This implements the paper's iterative feedback loop:
        1. Previous script failed with specific error
        2. Feed error back to LLM
        3. LLM generates corrected version
        4. Retry execution

        Args:
            failed_script: The script that failed
            error_output: stdout/stderr from failed execution
            target_config: Target device configuration
            attempt_number: Which retry attempt this is

        Returns:
            New GeneratedScript with corrections applied
        """
        # Build environment context from target config
        env = EnvironmentContext(
            android_version=target_config.get("android_version", "11"),
            api_level=target_config.get("api_level", 30),
            device_ip=target_config.get("ip", "192.168.56.101"),
            has_root_adb=target_config.get("has_root_adb", True),
        )

        # Use enhanced error feedback prompts with Genymotion context
        system_prompt, regeneration_prompt = get_error_feedback_prompts(
            script_type=failed_script.script_type.value,
            script_content=failed_script.content,
            error_output=error_output,
            attempt_number=attempt_number,
            max_attempts=3,
            env=env,
        )

        response = self.llm.complete(regeneration_prompt, system=system_prompt)
        script_content = self._extract_code(response.content, failed_script.script_type)

        # Create new script with retry suffix
        new_name = f"{failed_script.name}_retry{attempt_number}"

        corrected_script = GeneratedScript(
            name=new_name,
            script_type=failed_script.script_type,
            content=script_content,
            description=f"{failed_script.description} (retry {attempt_number})",
            source_step=failed_script.source_step,
        )

        return corrected_script

    def extract_error_context(self, output: str) -> dict:
        """
        Extract structured error information from execution output.

        Enhanced for Genymotion Android emulator environment with
        specific error patterns and actionable fix suggestions.

        Returns:
            Dict with error_type, error_message, suggestions, retry_strategy, and severity
        """
        # Comprehensive error patterns - order matters (most specific first)
        error_patterns = {
            # === ADB/Device Errors ===
            "device_offline": {
                "pattern": r"device .* not found|device not found|offline|no devices|emulators found|cannot connect|device unauthorized",
                "severity": "high",
                "retry_strategy": "reconnect",
            },
            "adb_server_error": {
                "pattern": r"adb server|daemon not running|cannot start|server failed",
                "severity": "high",
                "retry_strategy": "restart_adb",
            },
            "device_unauthorized": {
                "pattern": r"unauthorized|authorization|RSA key",
                "severity": "medium",
                "retry_strategy": "reauthorize",
            },

            # === Permission/Access Errors ===
            "permission_denied": {
                "pattern": r"Permission denied|EACCES|not permitted|Operation not permitted",
                "severity": "medium",
                "retry_strategy": "use_root",
            },
            "selinux_denied": {
                "pattern": r"avc:\s*denied|SELinux|selinux",
                "severity": "medium",
                "retry_strategy": "selinux_permissive",
            },
            "root_required": {
                "pattern": r"must be root|requires root|need root|su: not found",
                "severity": "high",
                "retry_strategy": "check_root",
            },

            # === File/Path Errors ===
            "file_not_found": {
                "pattern": r"No such file|ENOENT|file not found|does not exist|cannot open",
                "severity": "medium",
                "retry_strategy": "verify_path",
            },
            "path_not_directory": {
                "pattern": r"Not a directory|ENOTDIR|is a file",
                "severity": "low",
                "retry_strategy": "fix_path",
            },
            "read_only_fs": {
                "pattern": r"Read-only file system|EROFS|cannot write",
                "severity": "medium",
                "retry_strategy": "remount_rw",
            },

            # === Network Errors ===
            "connection_refused": {
                "pattern": r"Connection refused|ECONNREFUSED|connect failed|refused",
                "severity": "medium",
                "retry_strategy": "check_service",
            },
            "connection_timeout": {
                "pattern": r"timed out|ETIMEDOUT|timeout expired|Connection timed out",
                "severity": "medium",
                "retry_strategy": "increase_timeout",
            },
            "network_unreachable": {
                "pattern": r"Network unreachable|ENETUNREACH|No route to host",
                "severity": "high",
                "retry_strategy": "check_network",
            },

            # === Command/Binary Errors ===
            "command_not_found": {
                "pattern": r"command not found|not recognized|: not found|executable file not found",
                "severity": "medium",
                "retry_strategy": "check_binary",
            },
            "binary_arch_mismatch": {
                "pattern": r"cannot execute|Exec format error|ENOEXEC|wrong architecture|arm.*x86|x86.*arm",
                "severity": "high",
                "retry_strategy": "use_correct_arch",
            },
            "busybox_missing": {
                "pattern": r"busybox|applet not found",
                "severity": "low",
                "retry_strategy": "use_alternative",
            },

            # === Python/Script Errors ===
            "syntax_error": {
                "pattern": r"SyntaxError|syntax error|unexpected token|invalid syntax",
                "severity": "high",
                "retry_strategy": "fix_syntax",
            },
            "import_error": {
                "pattern": r"ImportError|ModuleNotFoundError|No module named",
                "severity": "medium",
                "retry_strategy": "install_module",
            },
            "type_error": {
                "pattern": r"TypeError|type error|expected.*got|incompatible type",
                "severity": "medium",
                "retry_strategy": "fix_types",
            },
            "attribute_error": {
                "pattern": r"AttributeError|has no attribute|object has no",
                "severity": "medium",
                "retry_strategy": "check_api",
            },

            # === Android-Specific Errors ===
            "package_not_found": {
                "pattern": r"package.*not found|Unknown package|Package .* not installed",
                "severity": "medium",
                "retry_strategy": "verify_package",
            },
            "activity_not_found": {
                "pattern": r"Activity.*not found|Unable to resolve|does not exist|ActivityNotFoundException",
                "severity": "medium",
                "retry_strategy": "check_manifest",
            },
            "content_provider_error": {
                "pattern": r"content provider|ContentProvider|Unknown URI|failed to query",
                "severity": "medium",
                "retry_strategy": "check_uri",
            },
            "frida_error": {
                "pattern": r"frida|Failed to attach|Unable to find|spawn.*failed",
                "severity": "medium",
                "retry_strategy": "check_frida",
            },

            # === Genymotion-Specific Errors ===
            "genymotion_network": {
                "pattern": r"192\.168\.56\.|vboxnet|bridge.*failed",
                "severity": "high",
                "retry_strategy": "check_genymotion_network",
            },
        }

        # Detailed suggestions for each error type
        suggestions_map = {
            "device_offline": [
                "Reconnect ADB: adb connect 192.168.56.101:5555",
                "Restart ADB server: adb kill-server && adb start-server",
                "Verify Genymotion emulator is running",
                "Check: Settings > Developer Options > ADB over network",
            ],
            "adb_server_error": [
                "Kill and restart ADB: adb kill-server && adb start-server",
                "Check if another process is using ADB port",
                "Verify ADB binary is in PATH",
            ],
            "device_unauthorized": [
                "Accept RSA key prompt on device",
                "Revoke authorizations: adb kill-server && rm ~/.android/adbkey*",
                "Re-enable USB debugging on device",
            ],
            "permission_denied": [
                "Use root: adb shell su -c '<command>'",
                "Check file permissions: ls -la <path>",
                "Remount if needed: mount -o rw,remount /system",
            ],
            "selinux_denied": [
                "Set permissive: adb shell su -c 'setenforce 0'",
                "Check context: ls -Z <file>",
                "May need custom SELinux policy",
            ],
            "root_required": [
                "Verify root: adb shell su -c 'id'",
                "Check Magisk: adb shell magisk -v",
                "Re-root device if needed",
            ],
            "file_not_found": [
                "Verify path exists: adb shell ls -la <parent_dir>",
                "Check for typos in path",
                "Path may differ on this Android version",
            ],
            "read_only_fs": [
                "Remount as rw: adb shell su -c 'mount -o rw,remount /system'",
                "Use /data/local/tmp/ for writable storage",
                "Check if Magisk systemless mode is active",
            ],
            "connection_refused": [
                "Verify target service is running",
                "Check port: adb shell netstat -tlnp | grep <port>",
                "Firewall may be blocking connection",
            ],
            "connection_timeout": [
                "Increase timeout value in script",
                "Check network: adb shell ping -c 3 <host>",
                "Genymotion network may need bridge mode",
            ],
            "command_not_found": [
                "Check if binary exists: which <command> or type <command>",
                "Genymotion has limited busybox - use alternatives",
                "Push binary to device: adb push <binary> /data/local/tmp/",
            ],
            "binary_arch_mismatch": [
                "Genymotion is x86_64 - use x86 binaries, not ARM",
                "Check binary: file <binary>",
                "Download correct architecture version",
            ],
            "import_error": [
                "Install missing module: pip install <module>",
                "Check virtual environment is activated",
                "Verify Python version compatibility",
            ],
            "package_not_found": [
                "List packages: adb shell pm list packages | grep <name>",
                "Package name may differ from app name",
                "Check if app is installed for current user",
            ],
            "activity_not_found": [
                "Dump manifest: adb shell pm dump <package> | grep Activity",
                "Activity may not be exported",
                "Check for typos in component name",
            ],
            "frida_error": [
                "Verify frida-server is running on device",
                "Match frida-server version to frida-tools",
                "Try spawn mode: frida -U -f <package> --no-pause",
            ],
            "genymotion_network": [
                "Check Genymotion network settings (NAT vs Bridge)",
                "Verify vboxnet0 interface exists: ifconfig vboxnet0",
                "Restart Genymotion if network is broken",
            ],
        }

        error_info = {
            "error_type": "unknown",
            "error_message": output[:500] if output else "No output",
            "suggestions": [],
            "retry_strategy": "generic_retry",
            "severity": "unknown",
            "raw_output": output[:1000] if output else "",
        }

        for error_type, config in error_patterns.items():
            if re.search(config["pattern"], output, re.IGNORECASE):
                error_info["error_type"] = error_type
                error_info["severity"] = config["severity"]
                error_info["retry_strategy"] = config["retry_strategy"]
                error_info["suggestions"] = suggestions_map.get(error_type, [
                    "Review the error message carefully",
                    "Check command syntax and parameters",
                    "Verify target device state",
                ])
                break

        # Add generic suggestions if no specific match
        if error_info["error_type"] == "unknown":
            error_info["suggestions"] = [
                "Review the full error output for clues",
                "Check if command works manually via adb shell",
                "Verify device connectivity: adb devices",
                "Try simpler version of the command first",
            ]

        return error_info
