"""
Kali Linux Executor (VulnBot-style)

Connects to a Kali Linux container/VM via SSH or Docker exec
to run penetration testing tools.

Architecture:
┌─────────────────┐     SSH/Docker      ┌─────────────────┐
│   Python App    │────────────────────▶│   Kali Linux    │
│   (Orchestrator)│                     │   (Tools)       │
│                 │◀────────────────────│                 │
│                 │     stdout/stderr   │   nmap, msf,    │
└─────────────────┘                     │   redis-cli...  │
                                        └─────────────────┘
"""

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ExecutorType(Enum):
    """Available executor backends."""
    DOCKER_EXEC = "docker"     # docker exec into running container
    SSH = "ssh"                # SSH via Paramiko
    LOCAL = "local"            # Direct local execution (if tools installed)


@dataclass
class ExecutionResult:
    """Result from command execution."""
    command: str
    stdout: str
    stderr: str
    return_code: int
    success: bool
    executor_type: ExecutorType
    duration_ms: Optional[float] = None

    @property
    def output(self) -> str:
        """Combined stdout + stderr."""
        return self.stdout + ("\n" + self.stderr if self.stderr else "")

    def is_truncated(self, max_chars: int = 8000) -> bool:
        """Check if output exceeds threshold (VulnBot uses 8000)."""
        return len(self.output) > max_chars


class BaseExecutor(ABC):
    """Abstract base class for command executors."""

    @abstractmethod
    def execute(self, command: str, timeout: int = 300) -> ExecutionResult:
        """Execute a command and return result."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if executor backend is available."""
        pass

    @abstractmethod
    def get_shell(self) -> Optional[str]:
        """Get interactive shell (for complex operations)."""
        pass


class DockerExecutor(BaseExecutor):
    """
    Execute commands inside a Docker container.

    Requires a running Kali container with pentest tools.
    """

    def __init__(
        self,
        container_name: str = "kali-pentest",
        shell: str = "/bin/bash",
    ):
        self.container = container_name
        self.shell = shell

    def is_available(self) -> bool:
        """Check if Docker and container are available."""
        try:
            result = subprocess.run(
                ["docker", "inspect", self.container],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def execute(self, command: str, timeout: int = 300) -> ExecutionResult:
        """Execute command in Docker container."""
        import time
        start = time.time()

        try:
            result = subprocess.run(
                [
                    "docker", "exec", self.container,
                    self.shell, "-c", command
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            duration = (time.time() - start) * 1000

            return ExecutionResult(
                command=command,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                success=result.returncode == 0,
                executor_type=ExecutorType.DOCKER_EXEC,
                duration_ms=duration,
            )

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                return_code=-1,
                success=False,
                executor_type=ExecutorType.DOCKER_EXEC,
            )

    def get_shell(self) -> Optional[str]:
        """Return docker exec command for interactive shell."""
        return f"docker exec -it {self.container} {self.shell}"


class SSHExecutor(BaseExecutor):
    """
    Execute commands via SSH (VulnBot's approach).

    Uses Paramiko for SSH connections to Kali Linux.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 2222,
        username: str = "kali",
        password: str = "kali",
        key_file: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self._client = None

    def _get_client(self):
        """Get or create SSH client."""
        if self._client is None:
            try:
                import paramiko
            except ImportError:
                raise ImportError("paramiko required for SSH executor: pip install paramiko")

            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if self.key_file:
                self._client.connect(
                    self.host, self.port, self.username,
                    key_filename=self.key_file,
                )
            else:
                self._client.connect(
                    self.host, self.port, self.username, self.password,
                )

        return self._client

    def is_available(self) -> bool:
        """Check if SSH connection can be established."""
        try:
            client = self._get_client()
            return client.get_transport().is_active()
        except Exception:
            return False

    def execute(self, command: str, timeout: int = 300) -> ExecutionResult:
        """Execute command via SSH."""
        import time
        start = time.time()

        try:
            client = self._get_client()
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)

            stdout_text = stdout.read().decode()
            stderr_text = stderr.read().decode()
            return_code = stdout.channel.recv_exit_status()

            duration = (time.time() - start) * 1000

            return ExecutionResult(
                command=command,
                stdout=stdout_text,
                stderr=stderr_text,
                return_code=return_code,
                success=return_code == 0,
                executor_type=ExecutorType.SSH,
                duration_ms=duration,
            )

        except Exception as e:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-1,
                success=False,
                executor_type=ExecutorType.SSH,
            )

    def get_shell(self) -> Optional[str]:
        """Return SSH command for interactive shell."""
        return f"ssh -p {self.port} {self.username}@{self.host}"

    def close(self) -> None:
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None


class LocalExecutor(BaseExecutor):
    """
    Execute commands locally (if tools are installed on host).

    Use this if you have pentest tools installed directly on macOS/Linux.
    """

    def __init__(self, shell: str = "/bin/bash"):
        self.shell = shell

    def is_available(self) -> bool:
        """Local executor is always available."""
        return True

    def execute(self, command: str, timeout: int = 300) -> ExecutionResult:
        """Execute command locally."""
        import time
        start = time.time()

        try:
            result = subprocess.run(
                [self.shell, "-c", command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            duration = (time.time() - start) * 1000

            return ExecutionResult(
                command=command,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                success=result.returncode == 0,
                executor_type=ExecutorType.LOCAL,
                duration_ms=duration,
            )

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                return_code=-1,
                success=False,
                executor_type=ExecutorType.LOCAL,
            )

    def get_shell(self) -> Optional[str]:
        """Return local shell."""
        return self.shell


class KaliExecutor:
    """
    High-level executor that wraps the available backends.

    Automatically selects the best available executor:
    1. Docker (if kali container running)
    2. SSH (if Kali VM accessible)
    3. Local (fallback)
    """

    def __init__(
        self,
        docker_container: str = "kali-pentest",
        ssh_host: str = "localhost",
        ssh_port: int = 2222,
        ssh_user: str = "kali",
        ssh_password: str = "kali",
        prefer: Optional[ExecutorType] = None,
    ):
        self.executors = {
            ExecutorType.DOCKER_EXEC: DockerExecutor(docker_container),
            ExecutorType.SSH: SSHExecutor(ssh_host, ssh_port, ssh_user, ssh_password),
            ExecutorType.LOCAL: LocalExecutor(),
        }
        self.prefer = prefer
        self._active_executor: Optional[BaseExecutor] = None

    def get_executor(self) -> BaseExecutor:
        """Get the best available executor."""
        if self._active_executor:
            return self._active_executor

        # If preference specified, try that first
        if self.prefer:
            executor = self.executors.get(self.prefer)
            if executor and executor.is_available():
                self._active_executor = executor
                return executor

        # Otherwise, try in order: Docker → SSH → Local
        for executor_type in [ExecutorType.DOCKER_EXEC, ExecutorType.SSH, ExecutorType.LOCAL]:
            executor = self.executors[executor_type]
            if executor.is_available():
                self._active_executor = executor
                return executor

        # Fallback to local
        self._active_executor = self.executors[ExecutorType.LOCAL]
        return self._active_executor

    def execute(self, command: str, timeout: int = 300) -> ExecutionResult:
        """Execute command using best available backend."""
        executor = self.get_executor()
        return executor.execute(command, timeout)

    def execute_script(self, script_content: str, timeout: int = 600) -> ExecutionResult:
        """
        Execute a multi-line script.

        Writes script to temp file in container, then executes.
        """
        import base64

        # Encode script to avoid escaping issues
        encoded = base64.b64encode(script_content.encode()).decode()

        # Write and execute script
        wrapper = f"""
        SCRIPT=$(echo "{encoded}" | base64 -d)
        TMPFILE=$(mktemp)
        echo "$SCRIPT" > "$TMPFILE"
        chmod +x "$TMPFILE"
        "$TMPFILE"
        rm -f "$TMPFILE"
        """

        return self.execute(wrapper, timeout)

    def check_tool(self, tool_name: str) -> bool:
        """Check if a specific tool is available."""
        result = self.execute(f"which {tool_name}")
        return result.success

    def list_available_tools(self) -> list[str]:
        """List common pentest tools that are available."""
        tools = [
            "nmap", "masscan", "redis-cli", "adb",
            "msfconsole", "msfvenom", "sqlmap",
            "frida", "objection", "jadx", "apktool",
            "hydra", "john", "hashcat", "gobuster",
            "nikto", "wfuzz", "ffuf", "burpsuite",
        ]

        available = []
        for tool in tools:
            if self.check_tool(tool):
                available.append(tool)

        return available

    @property
    def executor_type(self) -> ExecutorType:
        """Get the type of active executor."""
        executor = self.get_executor()
        if isinstance(executor, DockerExecutor):
            return ExecutorType.DOCKER_EXEC
        elif isinstance(executor, SSHExecutor):
            return ExecutorType.SSH
        else:
            return ExecutorType.LOCAL
