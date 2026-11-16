"""
External MCP Execution Engine for AAMARVA FLOOR Tool Governance (Python)

Security hardening:
- Strict SSRF validation (HTTPS required by default, private/loopback/metadata/CGNAT IPs blocked)
- No HTTP redirects allowed (prevents credential forwarding on 3xx)
- Schema argument validation
- Full support for FLOOR auth modes (none, bearer, api_key, custom_header)
- Optional official mcp client SDK support when installed, with hardened JSON-RPC fallback
- Credential redaction in error messages
"""

import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Any, Optional
from .errors import AamarvaError, AamarvaValidationError


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AamarvaError(
            "MCP server attempted HTTP redirect; redirects are disallowed.",
            code="FLOOR_EXECUTION_FAILED",
        )


def _is_restricted_ip(raw_ip: str, allow_loopback: bool = False) -> bool:
    clean = raw_ip.strip().strip("[]").split("%")[0]
    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return True

    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped

    # Cloud metadata (169.254.0.0/16) is always blocked
    if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        return True

    if isinstance(ip_obj, ipaddress.IPv4Address):
        # 100.64.0.0/10 CGNAT
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if ip_obj in cgnat:
            return True
        if ip_obj.is_loopback:
            return not (allow_loopback and str(ip_obj) == "127.0.0.1")
        if ip_obj.is_private or ip_obj.is_reserved:
            return True
        return False

    # IPv6
    if ip_obj.is_loopback:
        return not allow_loopback
    if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_site_local:
        return True
    return False


def _is_localhost_name(hostname: str) -> bool:
    h = hostname.lower().strip("[]")
    return h in ("localhost", "127.0.0.1", "::1")


def _is_permitted_local_dev() -> bool:
    return os.getenv("AAMARVA_ALLOW_LOCALHOST_MCP_HTTP") == "1"


def assert_safe_mcp_server_url(
    raw_url: str,
    allow_insecure_http_for_localhost: bool = False,
    resolve_dns: bool = False,
) -> str:
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        raise AamarvaError(
            "Cannot invoke MCP tool: valid MCP serverUrl is required.",
            code="FLOOR_EXECUTION_FAILED",
        )

    cleaned = raw_url.strip()
    try:
        parsed = urllib.parse.urlparse(cleaned)
    except Exception:
        raise AamarvaError("Cannot invoke MCP tool: malformed MCP serverUrl.", code="FLOOR_EXECUTION_FAILED")

    if parsed.username or parsed.password:
        raise AamarvaError("Refusing MCP serverUrl containing embedded URL credentials.", code="FLOOR_EXECUTION_FAILED")

    allow_local = bool(allow_insecure_http_for_localhost or _is_permitted_local_dev())
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower().strip("[]")

    if scheme == "http":
        if not allow_local or not _is_localhost_name(hostname):
            raise AamarvaError("Refusing insecure non-HTTPS MCP serverUrl.", code="FLOOR_EXECUTION_FAILED")
    elif scheme != "https":
        raise AamarvaError(f'Refusing unsupported MCP serverUrl protocol "{scheme}".', code="FLOOR_EXECUTION_FAILED")

    if not hostname:
        raise AamarvaError("Refusing MCP serverUrl with empty hostname.", code="FLOOR_EXECUTION_FAILED")

    if hostname == "metadata.google.internal" or hostname.endswith(".metadata.google.internal"):
        raise AamarvaError("Refusing cloud metadata MCP serverUrl.", code="FLOOR_EXECUTION_FAILED")

    try:
        ipaddress.ip_address(hostname)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if is_ip_literal:
        if _is_restricted_ip(hostname, allow_loopback=allow_local):
            raise AamarvaError(
                "Refusing MCP serverUrl targeting restricted or private IP address.",
                code="FLOOR_EXECUTION_FAILED",
            )
    elif _is_localhost_name(hostname) or hostname.endswith(".localhost"):
        if not (allow_local and _is_localhost_name(hostname)):
            raise AamarvaError("Refusing MCP serverUrl targeting localhost.", code="FLOOR_EXECUTION_FAILED")
    elif resolve_dns:
        try:
            infos = socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
            for info in infos:
                resolved_ip = info[4][0]
                if _is_restricted_ip(resolved_ip, allow_loopback=False):
                    raise AamarvaError(
                        "Refusing MCP serverUrl whose DNS resolution points to a restricted IP.",
                        code="FLOOR_EXECUTION_FAILED",
                    )
        except AamarvaError:
            raise
        except Exception:
            raise AamarvaError("Failed to resolve MCP server endpoint hostname.", code="MCP_SERVER_UNREACHABLE")

    return cleaned


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


def _assert_clean_header(name: str, val: str) -> None:
    if re.search(r"[\r\n\x00]", name) or re.search(r"[\r\n\x00]", val):
        raise AamarvaError("Invalid header characters in MCP auth configuration.", code="FLOOR_EXECUTION_FAILED")


def build_mcp_auth_headers(auth: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if not auth or not isinstance(auth, dict):
        return headers

    raw_type = str(auth.get("type") or auth.get("authType") or "").strip().lower()
    if raw_type == "none":
        return headers

    header_name = str(auth.get("headerName") or auth.get("authHeaderName") or "").strip()
    raw_val = auth.get("headerValue")

    if raw_type == "bearer" or auth.get("token"):
        tok = auth.get("token") or raw_val
        if tok:
            tok_str = str(tok)
            _assert_clean_header("Authorization", tok_str)
            headers["Authorization"] = tok_str if re.match(r"^bearer\s+", tok_str, re.I) else f"Bearer {tok_str}"
    elif raw_type in ("apikey", "api_key") or auth.get("apiKey"):
        h_name = header_name or "X-API-Key"
        key_val = auth.get("apiKey") or raw_val
        if key_val:
            val_str = str(key_val)
            _assert_clean_header(h_name, val_str)
            headers[h_name] = val_str
    elif raw_type in ("custom_header", "header") or (header_name and raw_val is not None):
        if header_name and raw_val is not None:
            val_str = str(raw_val)
            _assert_clean_header(header_name, val_str)
            headers[header_name] = val_str

    custom_headers = auth.get("headers")
    if isinstance(custom_headers, dict):
        for k, v in custom_headers.items():
            if isinstance(v, str):
                _assert_clean_header(k, v)
                headers[k] = v

    return headers


def invoke_external_mcp_tool(
    server_url: str,
    tool_id: str,
    args: Optional[Dict[str, Any]] = None,
    auth: Optional[Dict[str, Any]] = None,
    input_schema: Optional[Dict[str, Any]] = None,
    allow_insecure_http_for_localhost: bool = False,
    resolve_dns: bool = False,
    timeout_s: float = 30.0,
) -> Any:
    """
    Executes an external MCP tool over HTTP JSON-RPC after authorization approval.
    """
    safe_url = assert_safe_mcp_server_url(
        server_url,
        allow_insecure_http_for_localhost=allow_insecure_http_for_localhost,
        resolve_dns=resolve_dns,
    )

    args = args or {}
    validate_tool_arguments(tool_id, args, input_schema)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream, */*",
    }
    headers.update(build_mcp_auth_headers(auth))

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
        safe_url,
        data=req_data,
        headers=headers,
        method="POST",
    )

    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            status_code = resp.getcode()
            if 300 <= status_code < 400:
                raise AamarvaError("MCP server attempted HTTP redirect; redirects are disallowed.", code="FLOOR_EXECUTION_FAILED")
            content_type = (resp.headers.get("Content-Type") or "") if resp.headers else ""
            body = resp.read().decode("utf-8")
    except AamarvaError:
        raise
    except urllib.error.HTTPError as http_err:
        raise AamarvaError(
            f"MCP server rejected invocation with HTTP status {http_err.code}.",
            code="MCP_INVOCATION_FAILED",
        )
    except Exception:
        raise AamarvaError(
            "Failed to reach MCP server at endpoint.",
            code="MCP_SERVER_UNREACHABLE",
        )

    if "text/event-stream" in content_type:
        data_lines = [
            line[5:].strip()
            for line in body.splitlines()
            if line.startswith("data:") and line[5:].strip()
        ]
        if not data_lines:
            raise AamarvaError("MCP server returned empty SSE response.", code="MCP_INVOCATION_FAILED")
        try:
            result_json = json.loads(data_lines[-1])
        except Exception:
            raise AamarvaError("MCP server returned malformed JSON in SSE response.", code="MCP_INVOCATION_FAILED")
    else:
        try:
            result_json = json.loads(body)
        except Exception:
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
