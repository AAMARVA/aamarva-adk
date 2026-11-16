"""
External MCP Execution Engine for AAMARVA FLOOR Tool Governance (Python)

Establishes genuine connection to authorized MCP servers, validates schema,
injects credentials securely without leaks, and returns verified execution results.
"""

import json
import urllib.request
import urllib.error
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
    server_url: str,
    tool_id: str,
    args: Optional[Dict[str, Any]] = None,
    auth: Optional[Dict[str, Any]] = None,
    input_schema: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    Executes an external MCP tool over HTTP JSON-RPC after authorization approval.
    """
    if not server_url or not isinstance(server_url, str) or not server_url.strip():
        raise AamarvaError(
            "Cannot invoke MCP tool: valid MCP serverUrl is required.",
            code="FLOOR_EXECUTION_FAILED",
        )

    args = args or {}
    validate_tool_arguments(tool_id, args, input_schema)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream, */*",
    }

    if auth and isinstance(auth, dict):
        auth_type = auth.get("type")
        token = auth.get("token") or (auth.get("headerValue") if auth_type == "bearer" else None)
        if token or auth_type == "bearer":
            tok = token or auth.get("headerValue")
            if tok:
                headers["Authorization"] = f"Bearer {tok}"
        elif auth.get("apiKey") or auth_type == "apiKey":
            header_name = auth.get("headerName") or "X-API-Key"
            key_val = auth.get("apiKey") or auth.get("headerValue")
            if key_val:
                headers[header_name] = str(key_val)
        elif auth.get("headerName") and auth.get("headerValue"):
            headers[auth["headerName"]] = str(auth["headerValue"])

        custom_headers = auth.get("headers")
        if isinstance(custom_headers, dict):
            for k, v in custom_headers.items():
                if isinstance(v, str):
                    headers[k] = v

    json_rpc_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_id,
            "arguments": args,
        },
    }

    req_data = json.dumps(json_rpc_payload).encode("utf-8")
    req = urllib.request.Request(
        server_url.strip(),
        data=req_data,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status_code = resp.getcode()
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as http_err:
        raise AamarvaError(
            f"MCP server rejected invocation with HTTP status {http_err.code}.",
            code="MCP_INVOCATION_FAILED",
        )
    except Exception as net_err:
        raise AamarvaError(
            f"Failed to reach MCP server at endpoint: {str(net_err)}",
            code="MCP_SERVER_UNREACHABLE",
        )

    try:
        result_json = json.loads(body)
    except Exception as parse_err:
        raise AamarvaError(
            "MCP server returned malformed non-JSON response.",
            code="MCP_INVOCATION_FAILED",
        )

    if not isinstance(result_json, dict):
        raise AamarvaError(
            "MCP server returned non-dictionary response.",
            code="MCP_INVOCATION_FAILED",
        )

    if "error" in result_json and result_json["error"]:
        err_obj = result_json["error"]
        err_msg = (
            err_obj.get("message")
            if isinstance(err_obj, dict)
            else str(err_obj)
        ) or "Unknown MCP tool error"
        raise AamarvaError(
            f"External MCP tool execution error: {err_msg}",
            code="MCP_TOOL_ERROR",
        )

    if "result" in result_json:
        return result_json["result"]
    if "data" in result_json:
        return result_json["data"]
    return result_json
