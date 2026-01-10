"""
MCP (Model Context Protocol) Integration for AgenticART.

This package provides MCP servers and configuration for Android security
research tools, enabling the Praxis architecture:

    V2 Reasoning -> V1 Verification via MCP -> Calibration Signal -> DPO

Modules:
    - servers: MCP server implementations (JADX, Apktool, etc.)
    - config: Server configuration and lifecycle management
    - executor: Bridges PraxisRunner to MCP servers

Usage:
    from dojo.mcp import MCPExecutor

    executor = MCPExecutor()
    await executor.initialize()
    result = await executor.execute_tool("search_code", {"apk_path": "app.apk", "pattern": "crypto"})
"""

from dojo.mcp.config import (
    MCPConfig,
    ServerConfig,
    get_available_servers,
    load_config,
)
from dojo.mcp.executor import (
    MCPExecutor,
    ToolResult,
    quick_execute,
)
from dojo.mcp.servers import (
    create_apktool_server,
    create_jadx_server,
)

__all__ = [
    # Configuration
    "MCPConfig",
    "ServerConfig",
    "load_config",
    "get_available_servers",
    # Server factories
    "create_jadx_server",
    "create_apktool_server",
    # Executor
    "MCPExecutor",
    "ToolResult",
    "quick_execute",
]
