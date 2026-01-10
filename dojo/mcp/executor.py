#!/usr/bin/env python3
"""
MCP Executor: Bridges Praxis Verification to MCP Server Tools.

The MCPExecutor manages MCP server lifecycle and routes verification
tasks to the appropriate server based on tool type and challenge category.

Architecture:
    PraxisRunner → MCPExecutor → MCP Servers (JADX, Apktool, etc.)
                              ↓
                         Tool Results
                              ↓
                    Verification Validation

Usage:
    executor = MCPExecutor()
    await executor.initialize()

    result = await executor.execute_tool(
        server_id="jadx",
        tool_name="search_code",
        tool_args={"apk_path": "app.apk", "pattern": "crypto"}
    )
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from dojo.mcp.config import MCPConfig, load_config

logger = logging.getLogger(__name__)


# Tool name to server ID mapping
TOOL_TO_SERVER: dict[str, str] = {
    # JADX tools
    "decompile": "jadx",
    "search_code": "jadx",
    "get_class": "jadx",
    "list_classes": "jadx",
    "get_method": "jadx",
    "find_security_patterns": "jadx",

    # Apktool tools
    "decode": "apktool",
    "get_manifest": "apktool",
    "get_smali": "apktool",
    "search_smali": "apktool",
    "get_strings": "apktool",
    "list_resources": "apktool",
    "get_resource": "apktool",
    "build": "apktool",
    "find_security_issues": "apktool",

    # ADB tools (fallback)
    "adb_shell": "adb",
    "get_package_info": "adb",

    # Future: MobSF tools
    "mobsf_scan": "mobsf",
    "mobsf_upload": "mobsf",

    # Future: Frida tools
    "frida_attach": "frida",
    "frida_spawn": "frida",
    "frida_script": "frida",
}


@dataclass
class ToolResult:
    """Result of an MCP tool execution."""

    tool_name: str
    server_id: str
    success: bool
    output: Any
    execution_time_ms: int
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool_name,
            "server": self.server_id,
            "success": self.success,
            "output": self.output,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error,
        }


@dataclass
class MCPExecutor:
    """
    Manages MCP server execution for Praxis verification tasks.

    Handles:
    - Server lifecycle management
    - Tool routing to appropriate servers
    - Health checking and fallbacks
    - Result aggregation
    """

    config: MCPConfig = field(default_factory=load_config)
    _servers: dict[str, Any] = field(default_factory=dict)
    _initialized: bool = False
    workspace_dir: Optional[Path] = None

    async def initialize(self, required_servers: Optional[list[str]] = None) -> None:
        """
        Initialize required MCP servers.

        Args:
            required_servers: List of server IDs to initialize.
                            If None, initializes all available local servers.
        """
        if self._initialized:
            return

        # Set up workspace
        self.workspace_dir = self.config.get_workspace_dir()
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        # Determine which servers to initialize
        if required_servers is None:
            # Default: all enabled local servers
            required_servers = [
                s for s in self.config.servers
                if self.config.servers[s].enabled
                and self.config.servers[s].tier == "local"
            ]

        # Check availability and create instances
        for server_id in required_servers:
            if not self.config.is_server_available(server_id):
                met, missing = self.config.servers[server_id].check_requirements()
                logger.warning(
                    f"Server '{server_id}' not available: {missing}"
                )
                continue

            try:
                server = self.config.create_server_instance(server_id)
                self._servers[server_id] = server
                logger.info(f"Initialized MCP server: {server_id}")
            except Exception as e:
                logger.error(f"Failed to initialize server '{server_id}': {e}")

        self._initialized = True
        logger.info(
            f"MCPExecutor ready with servers: {list(self._servers.keys())}"
        )

    async def shutdown(self) -> None:
        """Shutdown all MCP servers."""
        for server_id, server in self._servers.items():
            try:
                # FastMCP servers may need cleanup
                if hasattr(server, "shutdown"):
                    await server.shutdown()
                logger.info(f"Shutdown server: {server_id}")
            except Exception as e:
                logger.warning(f"Error shutting down {server_id}: {e}")

        self._servers.clear()
        self._initialized = False

    def get_server_for_tool(self, tool_name: str) -> Optional[str]:
        """Get the server ID that provides a given tool."""
        return TOOL_TO_SERVER.get(tool_name)

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available via an initialized server."""
        server_id = self.get_server_for_tool(tool_name)
        if not server_id:
            return False
        return server_id in self._servers or server_id == "adb"

    async def execute_tool(
        self,
        tool_name: str,
        tool_args: dict,
        server_id: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Execute an MCP tool and return the result.

        Args:
            tool_name: Name of the tool to execute
            tool_args: Arguments to pass to the tool
            server_id: Specific server to use (auto-detected if None)
            timeout: Execution timeout in seconds

        Returns:
            ToolResult with execution outcome
        """
        start_time = time.time()

        # Determine server
        if server_id is None:
            server_id = self.get_server_for_tool(tool_name)

        if not server_id:
            return ToolResult(
                tool_name=tool_name,
                server_id="unknown",
                success=False,
                output=None,
                execution_time_ms=0,
                error=f"No server found for tool '{tool_name}'",
            )

        try:
            # Route to appropriate execution method
            if server_id == "adb":
                output = await self._execute_adb_tool(tool_name, tool_args, timeout)
            elif server_id in self._servers:
                output = await self._execute_mcp_tool(
                    server_id, tool_name, tool_args, timeout
                )
            else:
                return ToolResult(
                    tool_name=tool_name,
                    server_id=server_id,
                    success=False,
                    output=None,
                    execution_time_ms=0,
                    error=f"Server '{server_id}' not initialized",
                )

            execution_time = int((time.time() - start_time) * 1000)

            # Check for error in output
            success = True
            error = None
            if isinstance(output, dict):
                if "error" in output:
                    success = False
                    error = output["error"]
                elif output.get("exit_code", 0) != 0:
                    success = False
                    error = output.get("stderr", "Non-zero exit code")

            return ToolResult(
                tool_name=tool_name,
                server_id=server_id,
                success=success,
                output=output,
                execution_time_ms=execution_time,
                error=error,
            )

        except asyncio.TimeoutError:
            execution_time = int((time.time() - start_time) * 1000)
            return ToolResult(
                tool_name=tool_name,
                server_id=server_id,
                success=False,
                output=None,
                execution_time_ms=execution_time,
                error=f"Execution timed out after {timeout}s",
            )
        except Exception as e:
            execution_time = int((time.time() - start_time) * 1000)
            logger.exception(f"Error executing {tool_name}")
            return ToolResult(
                tool_name=tool_name,
                server_id=server_id,
                success=False,
                output=None,
                execution_time_ms=execution_time,
                error=str(e),
            )

    async def _execute_mcp_tool(
        self,
        server_id: str,
        tool_name: str,
        tool_args: dict,
        timeout: int,
    ) -> Any:
        """Execute a tool via MCP server."""
        server = self._servers[server_id]

        # FastMCP provides _tool_manager for accessing registered tools
        tool_manager = getattr(server, "_tool_manager", None)

        if tool_manager is None:
            return {"error": f"Server '{server_id}' has no tool manager"}

        # Get the tool from the manager (internal dict is _tools)
        tools = tool_manager._tools
        tool = tools.get(tool_name)

        if tool is None:
            available = list(tools.keys())
            return {
                "error": f"Tool '{tool_name}' not found on server '{server_id}'",
                "available_tools": available,
            }

        # Execute the tool function with timeout
        result = await asyncio.wait_for(
            self._call_tool_function(tool.fn, tool_args),
            timeout=timeout,
        )

        return result

    async def _call_tool_function(self, func: Any, args: dict) -> Any:
        """Call a tool function, handling both sync and async."""
        if asyncio.iscoroutinefunction(func):
            return await func(**args)
        else:
            # Run sync function in executor to not block
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: func(**args))

    async def _execute_adb_tool(
        self,
        tool_name: str,
        tool_args: dict,
        timeout: int,
    ) -> dict:
        """Execute an ADB-based tool via subprocess (uses execFile-style args)."""

        if tool_name == "adb_shell":
            command = tool_args.get("command", "echo 'no command'")
            # Split command safely for execFile-style execution
            cmd_parts = command.split() if isinstance(command, str) else command
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "adb", "shell", *cmd_parts,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=timeout,
            )
            stdout, stderr = await result.communicate()
            return {
                "exit_code": result.returncode,
                "stdout": stdout.decode(),
                "stderr": stderr.decode(),
            }

        elif tool_name == "get_package_info":
            package = tool_args.get("package_name", "")
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "adb", "shell", "dumpsys", "package", package,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=timeout,
            )
            stdout, stderr = await result.communicate()
            return {
                "output": stdout.decode(),
                "exit_code": result.returncode,
            }

        else:
            return {"error": f"Unknown ADB tool: {tool_name}"}

    # -------------------------------------------------------------------------
    # Verification Task Execution
    # -------------------------------------------------------------------------

    async def execute_verification_task(
        self,
        task_instruction: str,
        mcp_tool_call: dict,
        validation_rule: Optional[dict] = None,
    ) -> dict:
        """
        Execute a verification task and validate the result.

        This is the primary interface used by PraxisRunner.

        Args:
            task_instruction: Human-readable task description
            mcp_tool_call: Dict with "tool" key and tool arguments
            validation_rule: Optional validation rule for the output

        Returns:
            Dict with execution results and validation status
        """
        tool_name = mcp_tool_call.get("tool", "adb_shell")
        tool_args = {k: v for k, v in mcp_tool_call.items() if k != "tool"}

        # Execute the tool
        result = await self.execute_tool(tool_name, tool_args)

        # Validate if rule provided
        validated = None
        if validation_rule and result.success:
            validated = self._validate_result(result.output, validation_rule)

        return {
            "instruction": task_instruction,
            "tool_result": result.to_dict(),
            "validated": validated,
            "passed": result.success and (validated is None or validated),
        }

    def _validate_result(self, output: Any, rule: dict) -> bool:
        """Validate tool output against a rule."""
        import re as regex_module

        rule_type = rule.get("type", "")

        if rule_type == "output_contains":
            expected = rule.get("expected", "")
            output_str = self._extract_output_string(output)
            return expected.lower() in output_str.lower()

        elif rule_type == "regex":
            pattern = rule.get("pattern", "")
            output_str = self._extract_output_string(output)
            return bool(regex_module.search(pattern, output_str))

        elif rule_type == "exit_code":
            expected = rule.get("expected", 0)
            if isinstance(output, dict):
                return output.get("exit_code") == expected
            return False

        elif rule_type == "json_path":
            import json
            path = rule.get("path", "")
            expected = rule.get("expected")
            try:
                data = output if isinstance(output, dict) else json.loads(str(output))
                for key in path.split("."):
                    data = data[key]
                return data == expected
            except (KeyError, json.JSONDecodeError, TypeError):
                return False

        elif rule_type == "contains_any":
            # Check if output contains any of the expected values
            expected_list = rule.get("expected", [])
            output_str = self._extract_output_string(output)
            return any(exp.lower() in output_str.lower() for exp in expected_list)

        elif rule_type == "not_contains":
            # Check output does NOT contain certain strings
            forbidden = rule.get("forbidden", [])
            output_str = self._extract_output_string(output)
            return not any(f.lower() in output_str.lower() for f in forbidden)

        return True  # Unknown rule type = pass

    def _extract_output_string(self, output: Any) -> str:
        """Extract string content from various output formats."""
        if isinstance(output, str):
            return output
        elif isinstance(output, dict):
            # Try common keys
            for key in ["stdout", "output", "content", "result", "code"]:
                if key in output:
                    return str(output[key])
            return str(output)
        else:
            return str(output)

    # -------------------------------------------------------------------------
    # Batch Execution
    # -------------------------------------------------------------------------

    async def execute_verification_batch(
        self,
        tasks: list[dict],
        parallel: bool = False,
    ) -> list[dict]:
        """
        Execute multiple verification tasks.

        Args:
            tasks: List of task dicts with instruction, mcp_tool_call, validation_rule
            parallel: Whether to run tasks in parallel

        Returns:
            List of execution results
        """
        if parallel:
            coroutines = [
                self.execute_verification_task(
                    task["instruction"],
                    task["mcp_tool_call"],
                    task.get("validation_rule"),
                )
                for task in tasks
            ]
            return await asyncio.gather(*coroutines)
        else:
            results = []
            for task in tasks:
                result = await self.execute_verification_task(
                    task["instruction"],
                    task["mcp_tool_call"],
                    task.get("validation_rule"),
                )
                results.append(result)
            return results

    # -------------------------------------------------------------------------
    # Health Check
    # -------------------------------------------------------------------------

    async def health_check(self) -> dict[str, bool]:
        """
        Check health of all initialized servers.

        Returns:
            Dict mapping server_id to health status
        """
        import shutil

        health = {}

        for server_id in self._servers:
            try:
                # Try a simple operation
                if server_id == "jadx":
                    health[server_id] = shutil.which("jadx") is not None
                elif server_id == "apktool":
                    health[server_id] = shutil.which("apktool") is not None
                else:
                    health[server_id] = True
            except Exception:
                health[server_id] = False

        return health

    def get_available_tools(self) -> list[str]:
        """Get list of all available tools across initialized servers."""
        tools = []
        for server_id in self._servers:
            server_config = self.config.servers.get(server_id)
            if server_config:
                tools.extend(t.name for t in server_config.tools)

        # Add ADB tools which are always available
        tools.extend(["adb_shell", "get_package_info"])
        return tools

    def get_status(self) -> dict:
        """Get executor status summary."""
        return {
            "initialized": self._initialized,
            "servers": list(self._servers.keys()),
            "available_tools": self.get_available_tools(),
            "workspace_dir": str(self.workspace_dir) if self.workspace_dir else None,
        }


# Convenience function for quick execution
async def quick_execute(tool_name: str, tool_args: dict) -> ToolResult:
    """
    Quick one-off tool execution.

    Usage:
        result = await quick_execute("search_code", {
            "apk_path": "app.apk",
            "pattern": "crypto"
        })
    """
    executor = MCPExecutor()
    await executor.initialize()
    try:
        return await executor.execute_tool(tool_name, tool_args)
    finally:
        await executor.shutdown()
