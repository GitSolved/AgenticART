"""
MCP Servers for Android Security Research Tools.

This package provides MCP (Model Context Protocol) wrappers for common
Android security research tools, enabling AI agents to perform:

- Static Analysis: JADX, Apktool, MobSF, Ghidra
- Dynamic Analysis: Frida, Objection, Drozer

Each server exposes tool-specific functionality through a standardized
MCP interface, allowing challenges to specify verification tasks that
the Praxis Runner can execute.
"""

from dojo.mcp.servers.apktool_server import create_apktool_server
from dojo.mcp.servers.jadx_server import create_jadx_server

__all__ = [
    "create_jadx_server",
    "create_apktool_server",
]
