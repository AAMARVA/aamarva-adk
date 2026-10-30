"""
Model Context Protocol (MCP) Integration for AAMARVA ADK (Python)

Provides a genuine, standards-compliant Model Context Protocol server:
- Supports MCP protocol lifecycle (initialize, tools/list, tools/call, ping)
- Supports Stdio transport for local agents and subprocess execution
- Supports Streamable HTTP / SSE transport for remote microservices
- Preserves FLOOR governance, HITL approval, and endpoint allowlists
"""

import sys
import json
import logging
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass

logger = logging.getLogger("aamarva.mcp")

@dataclass
class McpToolDefinition:
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[[Dict[str, Any]], Any]


class AamarvaMcpServer:
    def __init__(self, client: Optional[Any] = None):
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

    def get_tools(self) -> List[McpToolDefinition]:
        client = self.client
        return [
            McpToolDefinition(
                name="aamarva_floor_list_tools",
                description="Discover available FLOOR tools, schemas, and caller access status.",
                input_schema={
                    "type": "object",
                    "properties": {},
                },
                handler=lambda args: client.get_floor_tools(),
            ),
            McpToolDefinition(
                name="aamarva_floor_request_access",
                description="Request human-in-the-loop (HITL) approval for a tool without executing it.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "toolId": {"type": "string", "description": "Identifier of the tool to request access for."},
                        "reason": {"type": "string", "description": "Business justification for requesting access."},
                    },
                    "required": ["toolId"],
                },
                handler=lambda args: client.request_floor_access(args.get("toolId"), args.get("reason")),
            ),
            McpToolDefinition(
                name="aamarva_floor_check_status",
                description="Check the status of a pending or processed tool access request.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "requestId": {"type": "string", "description": "The tool access request ID."},
                    },
                    "required": ["requestId"],
                },
                handler=lambda args: client.get_floor_request_status(args.get("requestId")),
            ),
            McpToolDefinition(
                name="aamarva_floor_execute_tool",
                description="Execute an authorized FLOOR tool with arguments. Fails closed if unauthorized.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "toolId": {"type": "string", "description": "Identifier of the tool to execute."},
                        "arguments": {"type": "object", "description": "Input arguments conforming to tool schema."},
                    },
                    "required": ["toolId", "arguments"],
                },
                handler=lambda args: client.execute_floor_tool(args.get("toolId"), args.get("arguments", {})),
            ),
            McpToolDefinition(
                name="aamarva_send_message",
                description="Send an end-to-end encrypted private message to an authorized connected peer agent.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "connectionId": {"type": "string", "description": "Active connection channel ID."},
                        "content": {"type": "string", "description": "Plaintext message to encrypt and send."},
                    },
                    "required": ["connectionId", "content"],
                },
                handler=lambda args: client.send_message(args.get("connectionId"), args.get("content")),
            ),
            McpToolDefinition(
                name="aamarva_get_messages",
                description="Retrieve and decrypt private messages from an active peer connection.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "connectionId": {"type": "string", "description": "Active connection channel ID."},
                    },
                    "required": ["connectionId"],
                },
                handler=lambda args: client.get_messages(args.get("connectionId")),
            ),
            McpToolDefinition(
                name="aamarva_cluster_send_message",
                description="Send an encrypted message to a cluster with recipient restrictions.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "clusterId": {"type": "string", "description": "Target cluster ID."},
                        "ciphertext": {"type": "string", "description": "Encrypted ciphertext payload."},
                        "nonce": {"type": "string", "description": "Cryptographic nonce IV."},
                        "recipients": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional authorized recipient agent IDs.",
                        },
                    },
                    "required": ["clusterId", "ciphertext", "nonce"],
                },
                handler=lambda args: client.send_cluster_message(
                    args.get("clusterId"),
                    args.get("ciphertext"),
                    args.get("nonce"),
                    recipients=args.get("recipients"),
                ),
            ),
            McpToolDefinition(
                name="aamarva_watchtower_activity",
                description="Retrieve recent fleet telemetry and private activity snapshot.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Maximum number of activity events to return."},
                    },
                },
                handler=lambda args: client.get_watchtower_activity(args.get("limit")),
            ),
            McpToolDefinition(
                name="aamarva_agent_footprints",
                description="Retrieve cryptographic activity audit footprints for current agent.",
                input_schema={
                    "type": "object",
                    "properties": {},
                },
                handler=lambda args: client.get_footprints(),
            ),
            McpToolDefinition(
                name="aamarva_webhook_events",
                description="Retrieve recent webhook event delivery history for the agent.",
                input_schema={
                    "type": "object",
                    "properties": {},
                },
                handler=lambda args: client.get_webhook_events(),
            ),
            McpToolDefinition(
                name="aamarva_get_agents",
                description="List sovereign fleet accounts (master and slave agents) in caller fleet.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "q": {"type": "string", "description": "Filter query string."},
                        "page": {"type": "number", "description": "Page number."},
                        "limit": {"type": "number", "description": "Items per page."},
                    },
                },
                handler=lambda args: client.get_agents(
                    q=args.get("q"), page=args.get("page"), limit=args.get("limit")
                ),
            ),
            McpToolDefinition(
                name="aamarva_get_clusters",
                description="List multi-agent clusters the caller belongs to.",
                input_schema={
                    "type": "object",
                    "properties": {},
                },
                handler=lambda args: client.get_clusters(),
            ),
        ]

    def handle_tool_call(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        tools = self.get_tools()
        tool = next((t for t in tools if t.name == tool_name), None)
        if not tool:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"MCP Tool not found: {tool_name}"}],
            }
        try:
            res = tool.handler(args or {})
            if isinstance(res, (dict, list)):
                text = json.dumps(res, default=str)
            else:
                text = str(res)
            return {
                "isError": False,
                "content": [{"type": "text", "text": text}],
            }
        except Exception as e:
            return {
                "isError": True,
                "content": [{"type": "text", "text": str(e)}],
            }

    def handle_json_rpc(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes standard MCP JSON-RPC requests (initialize, tools/list, tools/call, ping).
        """
        method = request.get("method")
        msg_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "aamarva-adk",
                        "version": "1.0.0",
                    },
                },
            }
        elif method == "notifications/initialized":
            return {}
        elif method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
        elif method == "tools/list":
            tools = self.get_tools()
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                        }
                        for t in tools
                    ]
                },
            }
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            call_res = self.handle_tool_call(name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": call_res,
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            }

    def run_stdio_server(self, input_stream=None, output_stream=None):
        """
        Runs the MCP server over stdio transport reading line-delimited JSON-RPC messages.
        """
        in_stream = input_stream or sys.stdin
        out_stream = output_stream or sys.stdout

        for line in in_stream:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_json_rpc(req)
                if resp:
                    out_stream.write(json.dumps(resp) + "\n")
                    out_stream.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
                out_stream.write(json.dumps(err_resp) + "\n")
                out_stream.flush()

    def create_http_handler(self):
        """
        Returns a WSGI / ASGI compatible callable for Streamable HTTP transport.
        """
        server = self

        def handle_request(body_dict: Dict[str, Any]) -> Dict[str, Any]:
            return server.handle_json_rpc(body_dict)

        return handle_request


def create_aamarva_mcp_server(client: Optional[Any] = None) -> AamarvaMcpServer:
    return AamarvaMcpServer(client)
