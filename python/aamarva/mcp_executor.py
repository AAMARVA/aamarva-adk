"""
MCP Gateway Executor for AAMARVA ADK (Python).

Decrypts Core-relayed MCP Gateway token envelopes locally using the Agent's
P-256 private key and dispatches authenticated JSON-RPC 2.0 requests to the
Gateway /mcp endpoint using the decrypted bearer token.
"""

import json
import uuid
import urllib.parse
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, Callable

from .crypto import decrypt_gateway_token_envelope, load_local_private_key_pem
from .errors import AamarvaError, AamarvaValidationError


def normalize_gateway_mcp_url(raw_gateway_url: str) -> str:
    if not isinstance(raw_gateway_url, str) or not raw_gateway_url.strip():
        raise AamarvaValidationError("gateway_url is required for MCP Gateway execution.")

    parsed = urllib.parse.urlparse(raw_gateway_url.strip())
    if not parsed.scheme or not parsed.netloc:
        raise AamarvaValidationError(f'Invalid gateway_url: "{raw_gateway_url}".')

    if parsed.username or parsed.password:
        raise AamarvaValidationError("gateway_url must not contain embedded user credentials.")

    host = (parsed.hostname or "").lower()
    is_localhost = host in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_localhost):
        raise AamarvaValidationError(
            f'Unsupported gateway_url protocol "{parsed.scheme}": HTTPS is required (HTTP allowed only for localhost).'
        )

    trimmed_path = parsed.path.rstrip("/")
    new_path = trimmed_path if trimmed_path.endswith("/mcp") else f"{trimmed_path}/mcp"
    return urllib.parse.urlunparse(parsed._replace(path=new_path))


def _parse_mcp_response_body(raw_text: str, content_type: str) -> Dict[str, Any]:
    ct = (content_type or "").lower()
    if "text/event-stream" in ct:
        candidates = []
        for line in raw_text.splitlines():
            if line.startswith("data:"):
                val = line[5:].strip()
                if val:
                    candidates.append(val)
        if not candidates:
            raise AamarvaError(
                "Gateway /mcp SSE response did not contain a JSON-RPC data payload.",
                code="GATEWAY_MCP_CALL_FAILED",
            )
        return json.loads(candidates[-1])

    if not raw_text or not raw_text.strip():
        return {}
    return json.loads(raw_text)


def execute_gateway_mcp_tool(
    gateway_url: str,
    token_envelope: Dict[str, Any],
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    expected_agent_id: str = "",
    expected_account_id: str = "",
    expected_token_id: Optional[str] = None,
    expected_gateway_id: Optional[str] = None,
    expected_mcp_server_id: Optional[str] = None,
    private_key: Any = None,
    key_epoch: Optional[int] = None,
    timeout_ms: int = 15000,
    headers: Optional[Dict[str, str]] = None,
    transport_fn: Optional[Callable[[str, Dict[str, str], bytes, float], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    clean_tool = tool_name.strip() if isinstance(tool_name, str) else ""
    if not clean_tool:
        raise AamarvaValidationError("tool_name is required for MCP Gateway execution.")
    if arguments is not None and not isinstance(arguments, dict):
        raise AamarvaValidationError("arguments must be a dictionary.")

    mcp_url = normalize_gateway_mcp_url(gateway_url)

    exp_agent = expected_agent_id.strip() if isinstance(expected_agent_id, str) else ""
    exp_account = expected_account_id.strip() if isinstance(expected_account_id, str) else ""
    if not exp_agent or not exp_account:
        raise AamarvaError(
            "expected_agent_id and expected_account_id are required for Gateway token decryption.",
            code="GATEWAY_CONTEXT_INVALID",
        )

    resolved_priv = private_key if private_key is not None else load_local_private_key_pem(exp_agent, epoch=key_epoch)

    decrypted = decrypt_gateway_token_envelope(
        envelope=token_envelope,
        recipient_private_key=resolved_priv,
        expected_agent_id=exp_agent,
        expected_account_id=exp_account,
        expected_token_id=expected_token_id,
        expected_gateway_id=expected_gateway_id,
        expected_mcp_server_id=expected_mcp_server_id,
        tool_name=clean_tool,
    )

    rpc_payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {
            "name": clean_tool,
            "arguments": arguments or {},
        },
    }
    body_bytes = json.dumps(rpc_payload).encode("utf-8")

    req_headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if headers:
        req_headers.update(headers)
    req_headers["Authorization"] = f"Bearer {decrypted['token']}"

    timeout_sec = max(0.1, timeout_ms / 1000.0)

    if transport_fn is not None:
        resp = transport_fn(mcp_url, req_headers, body_bytes, timeout_sec)
        status = int(resp.get("status", 200))
        ct = str(resp.get("content_type", "application/json"))
        raw_text = resp.get("body", "")
        if isinstance(raw_text, (dict, list)):
            parsed = raw_text
        else:
            parsed = _parse_mcp_response_body(str(raw_text), ct)
    else:
        req = urllib.request.Request(mcp_url, data=body_bytes, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as res:
                status = res.getcode() or 200
                ct = res.headers.get("Content-Type", "application/json")
                raw_text = res.read().decode("utf-8")
                parsed = _parse_mcp_response_body(raw_text, ct)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            try:
                err_json = json.loads(err_body)
                err_msg = (
                    err_json.get("error", {}).get("message")
                    if isinstance(err_json.get("error"), dict)
                    else err_json.get("message") or f"Gateway /mcp HTTP {e.code}"
                )
            except Exception:
                err_msg = f"Gateway /mcp HTTP {e.code}"
            raise AamarvaError(
                str(err_msg),
                code="GATEWAY_ACCESS_DENIED" if e.code in (401, 403) else "GATEWAY_MCP_CALL_FAILED",
                status_code=e.code,
            )
        except urllib.error.URLError as e:
            raise AamarvaError(f"Gateway /mcp invocation failed: {str(e.reason)}", code="GATEWAY_MCP_CALL_FAILED")

    if status >= 400:
        err_msg = (
            parsed.get("error", {}).get("message")
            if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict)
            else parsed.get("message") if isinstance(parsed, dict) else f"Gateway /mcp HTTP {status}"
        )
        raise AamarvaError(
            str(err_msg or f"Gateway /mcp HTTP {status}"),
            code="GATEWAY_ACCESS_DENIED" if status in (401, 403) else "GATEWAY_MCP_CALL_FAILED",
            status_code=status,
        )

    if isinstance(parsed, dict) and parsed.get("error"):
        err_obj = parsed["error"]
        rpc_msg = err_obj.get("message") if isinstance(err_obj, dict) and err_obj.get("message") else str(err_obj)
        raise AamarvaError(f"Gateway /mcp JSON-RPC error: {rpc_msg}", code="GATEWAY_MCP_CALL_FAILED")

    result_val = parsed.get("result") if isinstance(parsed, dict) and "result" in parsed else parsed
    return {
        "toolName": clean_tool,
        "gatewayId": decrypted["gatewayId"],
        "mcpServerId": decrypted["mcpServerId"],
        "tokenId": decrypted["tokenId"],
        "result": result_val,
        "raw": parsed,
    }
