"""
Model Context Protocol (MCP) Integration Alias for AAMARVA ADK (Python)

Re-exports all symbols from mcp_server for backward-compatibility.
"""

from .mcp_server import (
    AamarvaMcpServer,
    create_aamarva_mcp_server,
    McpToolDefinition,
    run_mcp_server,
)

__all__ = [
    "AamarvaMcpServer",
    "create_aamarva_mcp_server",
    "McpToolDefinition",
    "run_mcp_server",
]
