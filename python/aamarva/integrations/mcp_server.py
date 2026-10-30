"""
Model Context Protocol (MCP) Integration for AAMARVA ADK (Python)

Provides a genuine, standards-compliant Model Context Protocol server using
the official 'mcp' Python SDK:
- Stdio transport for local agents and subprocess execution
- Streamable HTTP / Server-Sent Events (SSE) transport using SseServerTransport
- Full 12 AAMARVA sovereign fleet capabilities (FLOOR, messaging, clusters, Watchtower, footprints, webhooks, agents, clusters)
"""

import asyncio
from typing import Optional, Any, List, Dict
from dataclasses import dataclass

try:
    from mcp.server import Server, NotificationOptions
    from mcp.server.models import InitializationOptions
    import mcp.types as types
    from mcp.server.stdio import stdio_server
    from mcp.server.sse import SseServerTransport
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    Server = object
    NotificationOptions = None
    InitializationOptions = None
    types = None
    stdio_server = None
    SseServerTransport = None


@dataclass
class McpToolDefinition:
    name: str
    description: str
    input_schema: Dict[str, Any]


class AamarvaMcpServer:
    """
    Official MCP Server exposing all AAMARVA sovereign fleet tools.
    Supports stdio and official SseServerTransport for Streamable HTTP.
    """
    def __init__(self, client: Optional[Any] = None):
        if not HAS_MCP:
            raise ImportError(
                "Model Context Protocol (MCP) dependencies not found. "
                "Please install 'mcp' via 'pip install aamarva[mcp]' to use this integration."
            )
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

        self.server = Server("aamarva-adk")
        self._setup_handlers()

    def get_initialization_options(self) -> Any:
        return InitializationOptions(
            server_name="aamarva-adk",
            server_version="2.0.0",
            capabilities=self.server.get_capabilities(
                notification_options=NotificationOptions(),
                experimental_capabilities={},
            ),
        )

    def _setup_handlers(self):
        @self.server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            """List available AAMARVA tools."""
            return [
                types.Tool(
                    name="aamarva_floor_list_tools",
                    description="Discover available FLOOR tools, schemas, and caller access status.",
                    inputSchema={"type": "object", "properties": {}},
                ),
                types.Tool(
                    name="aamarva_floor_request_access",
                    description="Request human-in-the-loop (HITL) approval for a tool without executing it.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "toolId": {"type": "string", "description": "Identifier of the tool to request access for."},
                            "reason": {"type": "string", "description": "Business justification for requesting access."},
                        },
                        "required": ["toolId"],
                    },
                ),
                types.Tool(
                    name="aamarva_floor_check_status",
                    description="Check the status of a pending or processed tool access request.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "requestId": {"type": "string", "description": "The tool access request ID."},
                        },
                        "required": ["requestId"],
                    },
                ),
                types.Tool(
                    name="aamarva_floor_execute_tool",
                    description="Execute an authorized FLOOR tool with arguments. Fails closed if unauthorized.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "toolId": {"type": "string", "description": "Identifier of the tool to execute."},
                            "arguments": {"type": "object", "description": "Input arguments conforming to tool schema."},
                        },
                        "required": ["toolId", "arguments"],
                    },
                ),
                types.Tool(
                    name="aamarva_send_message",
                    description="Send an end-to-end encrypted private message to an authorized connected peer agent.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connectionId": {"type": "string", "description": "Active connection channel ID."},
                            "content": {"type": "string", "description": "Plaintext message to encrypt and send."},
                        },
                        "required": ["connectionId", "content"],
                    },
                ),
                types.Tool(
                    name="aamarva_get_messages",
                    description="Retrieve and decrypt private messages from an active peer connection.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connectionId": {"type": "string", "description": "Active connection channel ID."},
                        },
                        "required": ["connectionId"],
                    },
                ),
                types.Tool(
                    name="aamarva_cluster_send_message",
                    description="Send an encrypted message to a cluster with recipient restrictions.",
                    inputSchema={
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
                ),
                types.Tool(
                    name="aamarva_watchtower_activity",
                    description="Retrieve recent fleet telemetry and private activity snapshot.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {"type": "number", "description": "Maximum number of activity events to return."},
                        },
                    },
                ),
                types.Tool(
                    name="aamarva_agent_footprints",
                    description="Retrieve cryptographic activity audit footprints for current agent.",
                    inputSchema={"type": "object", "properties": {}},
                ),
                types.Tool(
                    name="aamarva_webhook_events",
                    description="Retrieve recent webhook event delivery history for the agent.",
                    inputSchema={"type": "object", "properties": {}},
                ),
                types.Tool(
                    name="aamarva_get_agents",
                    description="List sovereign fleet accounts (master and slave agents) in caller fleet.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "q": {"type": "string", "description": "Filter query string."},
                            "page": {"type": "number", "description": "Page number."},
                            "limit": {"type": "number", "description": "Items per page."},
                        },
                    },
                ),
                types.Tool(
                    name="aamarva_get_clusters",
                    description="List multi-agent clusters the caller belongs to.",
                    inputSchema={"type": "object", "properties": {}},
                ),
            ]

        @self.server.call_tool()
        async def handle_call_tool(
            name: str, arguments: dict | None
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            """Handle tool execution requests with fail-closed security."""
            args = arguments or {}
            try:
                if name == "aamarva_floor_list_tools":
                    res = self.client.get_floor_tools()
                elif name == "aamarva_floor_request_access":
                    res = self.client.request_floor_access(args.get("toolId"), args.get("reason"))
                elif name == "aamarva_floor_check_status":
                    res = self.client.get_floor_request_status(args.get("requestId"))
                elif name == "aamarva_floor_execute_tool":
                    res = self.client.execute_floor_tool(args.get("toolId"), args.get("arguments", {}))
                elif name == "aamarva_send_message":
                    res = self.client.send_message(args.get("connectionId"), args.get("content"))
                elif name == "aamarva_get_messages":
                    res = self.client.get_messages(args.get("connectionId"))
                elif name == "aamarva_cluster_send_message":
                    res = self.client.send_cluster_message(
                        args.get("clusterId"),
                        args.get("ciphertext"),
                        args.get("nonce"),
                        recipients=args.get("recipients"),
                    )
                elif name == "aamarva_watchtower_activity":
                    res = self.client.get_watchtower_activity(args.get("limit"))
                elif name == "aamarva_agent_footprints":
                    res = self.client.get_footprints()
                elif name == "aamarva_webhook_events":
                    res = self.client.get_webhook_events()
                elif name == "aamarva_get_agents":
                    res = self.client.get_agents(
                        q=args.get("q"), page=args.get("page"), limit=args.get("limit")
                    )
                elif name == "aamarva_get_clusters":
                    res = self.client.get_clusters()
                else:
                    raise ValueError(f"Unknown tool: {name}")

                import json
                return [types.TextContent(type="text", text=json.dumps(res, default=str))]
            except Exception as e:
                return [types.TextContent(type="text", text=f"Error: {str(e)}")]

    async def run_stdio(self):
        """Run the server using official stdio transport."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.get_initialization_options(),
            )

    def create_sse_transport(self, endpoint: str = "/messages") -> Any:
        """
        Creates an official SseServerTransport from the Python MCP SDK.
        """
        return SseServerTransport(endpoint)

    def create_starlette_app(self, endpoint: str = "/messages"):
        """
        Creates an official Starlette ASGI application for Streamable HTTP transport
        using SseServerTransport from the Python MCP SDK.
        """
        try:
            from starlette.applications import Starlette
            from starlette.routing import Route
        except ImportError:
            raise ImportError(
                "Starlette is required for the MCP HTTP/SSE transport. "
                "Please install 'starlette' via 'pip install aamarva[mcp]'."
            )

        sse = SseServerTransport(endpoint)

        async def handle_sse(request):
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await self.server.run(
                    streams[0], streams[1], self.get_initialization_options()
                )

        async def handle_messages(request):
            await sse.handle_post_message(request.scope, request.receive, request._send)

        return Starlette(
            routes=[
                Route("/sse", endpoint=handle_sse),
                Route(endpoint, endpoint=handle_messages, methods=["POST"]),
            ]
        )

    def create_http_handler(self, endpoint: str = "/messages"):
        """
        Returns the official Starlette application or an ASGI handler for Streamable HTTP transport.
        """
        return self.create_starlette_app(endpoint)


def create_aamarva_mcp_server(client: Optional[Any] = None) -> AamarvaMcpServer:
    return AamarvaMcpServer(client)


def run_mcp_server():
    """Entry point for the MCP stdio server."""
    server = AamarvaMcpServer()
    asyncio.run(server.run_stdio())


__all__ = [
    "AamarvaMcpServer",
    "create_aamarva_mcp_server",
    "McpToolDefinition",
    "run_mcp_server",
]
