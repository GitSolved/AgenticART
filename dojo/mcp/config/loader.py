#!/usr/bin/env python3
"""
MCP Server Configuration Loader.

Loads and validates MCP server configuration for the Praxis Runner.
Handles server lifecycle management and health checking.

Usage:
    from dojo.mcp.config.loader import MCPConfig, load_config

    config = load_config()
    jadx_config = config.get_server("jadx")

    # Check if server is available
    if config.is_server_available("jadx"):
        server = config.create_server_instance("jadx")
"""

from __future__ import annotations

import importlib
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

logger = logging.getLogger(__name__)

# Default config path
DEFAULT_CONFIG_PATH = Path(__file__).parent / "mcp_servers.yaml"


@dataclass
class ToolConfig:
    """Configuration for a single MCP tool."""

    name: str
    description: str
    security_relevant: bool = False


@dataclass
class ServerConfig:
    """Configuration for a single MCP server."""

    name: str
    description: str
    tier: str  # local | docker | device
    module: Optional[str] = None
    factory: Optional[str] = None
    transport: str = "stdio"
    port: Optional[int] = None
    enabled: bool = True

    # Requirements
    requirements: dict = field(default_factory=dict)

    # Resource limits
    resources: dict = field(default_factory=dict)

    # Docker configuration
    docker: dict = field(default_factory=dict)

    # Available tools
    tools: list[ToolConfig] = field(default_factory=list)

    # Challenge types this server supports
    challenge_types: list[str] = field(default_factory=list)

    def check_requirements(self) -> tuple[bool, list[str]]:
        """
        Check if server requirements are met.

        Returns:
            Tuple of (all_met, list_of_missing_requirements)
        """
        missing = []

        # Check binary requirement
        if binary := self.requirements.get("binary"):
            if not shutil.which(binary):
                hint = self.requirements.get("install_hint", f"Install {binary}")
                missing.append(f"Binary '{binary}' not found. {hint}")

        # Check device requirement
        if self.requirements.get("device_required"):
            # Check ADB connection
            try:
                result = subprocess.run(
                    ["adb", "devices"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if "device" not in result.stdout.split("\n", 1)[-1]:
                    missing.append("No Android device connected via ADB")
            except (subprocess.SubprocessError, FileNotFoundError):
                missing.append("ADB not available or no device connected")

        # Check Frida server requirement
        if self.requirements.get("frida_server"):
            try:
                result = subprocess.run(
                    ["frida-ps", "-U"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode != 0:
                    missing.append("Frida server not running on device")
            except (subprocess.SubprocessError, FileNotFoundError):
                missing.append("Frida not installed or device not connected")

        return len(missing) == 0, missing


@dataclass
class MCPConfig:
    """Complete MCP server configuration."""

    version: str
    name: str
    global_config: dict
    servers: dict[str, ServerConfig]
    server_groups: dict[str, dict]
    verification_requirements: dict[str, dict]
    health_checks: dict

    def get_server(self, server_id: str) -> Optional[ServerConfig]:
        """Get server configuration by ID."""
        return self.servers.get(server_id)

    def get_enabled_servers(self) -> list[ServerConfig]:
        """Get all enabled server configurations."""
        return [s for s in self.servers.values() if s.enabled]

    def get_servers_for_tier(self, tier: str) -> list[ServerConfig]:
        """Get all servers for a specific tier."""
        return [
            s for s in self.servers.values() if s.enabled and s.tier == tier
        ]

    def get_servers_for_challenge_type(
        self, challenge_type: str
    ) -> list[ServerConfig]:
        """Get servers that support a specific challenge type."""
        return [
            s
            for s in self.servers.values()
            if s.enabled and challenge_type in s.challenge_types
        ]

    def get_servers_for_group(self, group_name: str) -> list[ServerConfig]:
        """Get all servers in a named group."""
        group = self.server_groups.get(group_name, {})
        server_ids = group.get("servers", [])
        return [
            self.servers[sid]
            for sid in server_ids
            if sid in self.servers and self.servers[sid].enabled
        ]

    def get_verification_servers(
        self, task_prefix: str
    ) -> tuple[list[str], list[str]]:
        """
        Get required and optional servers for verification task prefix.

        Args:
            task_prefix: Prefix like "white", "grey", "black", "dynamic"

        Returns:
            Tuple of (required_server_ids, optional_server_ids)
        """
        reqs = self.verification_requirements.get(task_prefix, {})
        return reqs.get("required", []), reqs.get("optional", [])

    def is_server_available(self, server_id: str) -> bool:
        """Check if a server is available and requirements are met."""
        server = self.servers.get(server_id)
        if not server or not server.enabled:
            return False

        met, _ = server.check_requirements()
        return met

    def check_all_servers(self) -> dict[str, tuple[bool, list[str]]]:
        """
        Check requirements for all enabled servers.

        Returns:
            Dict mapping server_id to (available, missing_requirements)
        """
        results = {}
        for server_id, server in self.servers.items():
            if server.enabled:
                results[server_id] = server.check_requirements()
        return results

    def create_server_instance(self, server_id: str) -> Any:
        """
        Create an MCP server instance.

        Args:
            server_id: ID of the server to create

        Returns:
            MCP server instance (FastMCP)

        Raises:
            ValueError: If server not found or not available
        """
        server = self.servers.get(server_id)
        if not server:
            raise ValueError(f"Server '{server_id}' not found in configuration")

        if not server.enabled:
            raise ValueError(f"Server '{server_id}' is not enabled")

        if server.tier == "local" and server.module and server.factory:
            # Import and call factory function
            module = importlib.import_module(server.module)
            factory: Callable = getattr(module, server.factory)
            return factory()

        elif server.tier == "docker":
            raise NotImplementedError(
                f"Docker server '{server_id}' creation not yet implemented"
            )

        elif server.tier == "device":
            raise NotImplementedError(
                f"Device server '{server_id}' creation not yet implemented"
            )

        else:
            raise ValueError(f"Unknown server tier: {server.tier}")

    def get_workspace_dir(self) -> Path:
        """Get the workspace directory, expanding environment variables."""
        workspace = self.global_config.get(
            "workspace_dir", "/tmp/agenticart"
        )
        # Expand environment variables
        workspace = os.path.expandvars(workspace)
        return Path(workspace)


def load_config(config_path: Optional[Path] = None) -> MCPConfig:
    """
    Load MCP server configuration from YAML file.

    Args:
        config_path: Path to config file. Uses default if not specified.

    Returns:
        MCPConfig instance
    """
    config_path = config_path or DEFAULT_CONFIG_PATH

    with open(config_path) as f:
        raw_config = yaml.safe_load(f)

    # Parse servers
    servers = {}
    for server_id, server_data in raw_config.get("servers", {}).items():
        # Parse tools
        tools = [
            ToolConfig(
                name=t["name"],
                description=t.get("description", ""),
                security_relevant=t.get("security_relevant", False),
            )
            for t in server_data.get("tools", [])
        ]

        servers[server_id] = ServerConfig(
            name=server_data.get("name", server_id),
            description=server_data.get("description", ""),
            tier=server_data.get("tier", "local"),
            module=server_data.get("module"),
            factory=server_data.get("factory"),
            transport=server_data.get("transport", "stdio"),
            port=server_data.get("port"),
            enabled=server_data.get("enabled", True),
            requirements=server_data.get("requirements", {}),
            resources=server_data.get("resources", {}),
            docker=server_data.get("docker", {}),
            tools=tools,
            challenge_types=server_data.get("challenge_types", []),
        )

    return MCPConfig(
        version=raw_config.get("version", "1.0"),
        name=raw_config.get("name", "MCP Configuration"),
        global_config=raw_config.get("global", {}),
        servers=servers,
        server_groups=raw_config.get("server_groups", {}),
        verification_requirements=raw_config.get("verification_requirements", {}),
        health_checks=raw_config.get("health_checks", {}),
    )


def get_available_servers() -> list[str]:
    """Get list of currently available server IDs."""
    config = load_config()
    return [
        server_id
        for server_id in config.servers
        if config.is_server_available(server_id)
    ]


def print_server_status():
    """Print status of all configured servers."""
    config = load_config()
    results = config.check_all_servers()

    print(f"\n{'='*60}")
    print(f"MCP Server Status - {config.name} v{config.version}")
    print(f"{'='*60}\n")

    for server_id, (available, missing) in results.items():
        server = config.servers[server_id]
        status = "AVAILABLE" if available else "UNAVAILABLE"
        status_icon = "\u2705" if available else "\u274c"

        print(f"{status_icon} {server.name} ({server_id})")
        print(f"   Tier: {server.tier} | Transport: {server.transport}")
        print(f"   Status: {status}")

        if missing:
            for msg in missing:
                print(f"   - {msg}")

        print()


if __name__ == "__main__":
    print_server_status()
