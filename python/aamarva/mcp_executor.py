"""
MCP Tool Argument Validator & Gateway Fail-Closed Guard (Python)

Direct external MCP server invocation from the ADK is strictly prohibited.
All tool executions must pass through the Three-Party Mandatory MCP Adapter Gateway
(AAMARVA relay -> RFC 9180 P-256 HPKE local decryption -> /gateway/mcp PoP redemption).
"""

from typing import Dict, Any, Optional
from .errors import AamarvaError, AamarvaValidationError


def validate_tool_arguments(
    tool_id: str,
    args: Optional[Dict[str, Any]] = None,
    schema: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Validates tool arguments against the tool input schema.
    """
    if not schema or not isinstance(schema, dict):
        return

    req = schema.get("required")
    args = args or {}
    if isinstance(req, list):
        for req_key in req:
            if req_key not in args or args[req_key] is None:
                raise AamarvaValidationError(
                    f'Missing required argument "{req_key}" for tool "{tool_id}".',
                    code="INVALID_TOOL_ARGUMENTS",
                )


def invoke_external_mcp_tool(
    server_url: str = "",
    tool_id: str = "",
    args: Optional[Dict[str, Any]] = None,
    auth: Optional[Dict[str, Any]] = None,
    input_schema: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    Direct external MCP execution is disabled in the AAMARVA ADK.
    Raises GATEWAY_EXECUTION_REQUIRED unconditionally.
    """
    raise AamarvaError(
        "Direct external MCP tool invocation is disabled in the AAMARVA ADK. "
        "All FLOOR tool executions must route through the Mandatory MCP Adapter Gateway (POST /gateway/mcp).",
        code="GATEWAY_EXECUTION_REQUIRED",
    )
