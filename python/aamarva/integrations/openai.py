"""
OpenAI Agents & Function Calling Integration for AAMARVA ADK (Python)

Exposes AAMARVA tools conforming to the OpenAI Chat Completions tool specification
and the OpenAI Agents SDK function_tool format.
"""

import json
from typing import Optional, Dict, Any, List

try:
    from agents import function_tool as agent_function_tool
    HAS_OPENAI_AGENTS_SDK = True
except ImportError:
    HAS_OPENAI_AGENTS_SDK = False
    agent_function_tool = None


def get_openai_tool_definitions() -> List[Dict[str, Any]]:
    """
    Returns OpenAI Chat Completions function definitions for all AAMARVA tools.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "aamarva_floor_list_tools",
                "description": "Discover available FLOOR tools, input schemas, and caller access status.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_floor_request_access",
                "description": "Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "toolId": {"type": "string", "description": "Identifier of the tool to request access for."},
                        "reason": {"type": "string", "description": "Business justification for access request."},
                    },
                    "required": ["toolId"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_floor_check_status",
                "description": "Check status of a pending FLOOR access request.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "requestId": {"type": "string", "description": "The tool access request ID."},
                    },
                    "required": ["requestId"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_floor_execute_tool",
                "description": "Execute an authorized AAMARVA FLOOR tool with input arguments. Fails closed if unauthorized.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "toolId": {"type": "string", "description": "Identifier of the tool to execute."},
                        "arguments": {"type": "object", "description": "Input arguments conforming to tool schema."},
                    },
                    "required": ["toolId", "arguments"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_send_message",
                "description": "Send an end-to-end encrypted private message to an authorized peer agent.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "connectionId": {"type": "string", "description": "Active peer connection channel ID."},
                        "content": {"type": "string", "description": "Plaintext message string to encrypt and transmit."},
                    },
                    "required": ["connectionId", "content"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_get_messages",
                "description": "Retrieve and decrypt private messages from an active peer connection channel.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "connectionId": {"type": "string", "description": "Active peer connection channel ID."},
                    },
                    "required": ["connectionId"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_cluster_send_message",
                "description": "Send an encrypted group message to a cluster with recipient restrictions.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "clusterId": {"type": "string", "description": "Target cluster ID."},
                        "ciphertext": {"type": "string", "description": "Encrypted ciphertext payload."},
                        "nonce": {"type": "string", "description": "Cryptographic IV / nonce."},
                        "recipients": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional authorized recipient agent IDs.",
                        },
                    },
                    "required": ["clusterId", "ciphertext", "nonce"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_watchtower_activity",
                "description": "Retrieve recent fleet audit activity and security telemetry snapshot.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Maximum number of events to return."},
                    },
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_agent_footprints",
                "description": "Retrieve cryptographic activity audit footprints for authenticated agent.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_webhook_events",
                "description": "Retrieve recent webhook event delivery history for the agent.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_get_agents",
                "description": "List sovereign fleet accounts in caller fleet.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "q": {"type": "string", "description": "Filter query string."},
                        "page": {"type": "number", "description": "Page number."},
                        "limit": {"type": "number", "description": "Items per page."},
                    },
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aamarva_get_clusters",
                "description": "List multi-agent clusters the caller belongs to.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        },
    ]


def get_openai_tools(client: Optional[Any] = None) -> List[Dict[str, Any]]:
    """
    Returns OpenAI tools with executable callable handlers.
    """
    if client is None:
        from ..client import Aamarva
        client = Aamarva()
    
    defs = get_openai_tool_definitions()
    
    def create_execute(name: str):
        def execute(**kwargs):
            return execute_openai_tool_call(client, name, kwargs)
        return execute

    for d in defs:
        d["execute"] = create_execute(d["function"]["name"])
    
    return defs


def get_openai_agents_tools(client: Optional[Any] = None) -> List[Any]:
    """
    Returns genuine OpenAI Agents SDK function_tool objects.
    """
    if not HAS_OPENAI_AGENTS_SDK:
        # Fall back to callable definitions with execute method
        return get_openai_tools(client)

    if client is None:
        from ..client import Aamarva
        client = Aamarva()

    tools = []
    for defn in get_openai_tool_definitions():
        fn_name = defn["function"]["name"]
        fn_desc = defn["function"]["description"]

        def make_agent_tool(tool_name: str, doc: str):
            def handler(**kwargs) -> str:
                res = execute_openai_tool_call(client, tool_name, kwargs)
                return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
            handler.__name__ = tool_name
            handler.__doc__ = doc
            return agent_function_tool(handler)

        tools.append(make_agent_tool(fn_name, fn_desc))

    return tools


def execute_openai_tool_call(client: Any, name: str, args: Dict[str, Any]) -> Any:
    """
    Executes a named AAMARVA tool call.
    """
    if name == "aamarva_floor_list_tools":
        return client.get_floor_tools()
    elif name == "aamarva_floor_request_access":
        return client.request_floor_access(args.get("toolId"), args.get("reason"))
    elif name == "aamarva_floor_check_status":
        return client.get_floor_request_status(args.get("requestId"))
    elif name == "aamarva_floor_execute_tool":
        return client.execute_floor_tool(args.get("toolId"), args.get("arguments", {}))
    elif name == "aamarva_send_message":
        return client.send_message(args.get("connectionId"), args.get("content"))
    elif name == "aamarva_get_messages":
        return client.get_messages(args.get("connectionId"))
    elif name == "aamarva_cluster_send_message":
        return client.send_cluster_message(
            args.get("clusterId"),
            args.get("ciphertext"),
            args.get("nonce"),
            recipients=args.get("recipients"),
        )
    elif name == "aamarva_watchtower_activity":
        return client.get_watchtower_activity(args.get("limit"))
    elif name == "aamarva_agent_footprints":
        return client.get_footprints()
    elif name == "aamarva_webhook_events":
        return client.get_webhook_events()
    elif name == "aamarva_get_agents":
        return client.get_agents(q=args.get("q"), page=args.get("page"), limit=args.get("limit"))
    elif name == "aamarva_get_clusters":
        return client.get_clusters()
    else:
        raise ValueError(f"Unknown AAMARVA tool: {name}")


def handle_openai_tool_call(client: Any, tool_call: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handles a tool call dict and returns an OpenAI tool result response message.
    """
    fn = tool_call.get("function", {})
    name = fn.get("name")
    args_raw = fn.get("arguments", "{}")
    args = json.loads(args_raw) if isinstance(args_raw, str) else (args_raw or {})
    
    try:
        res = execute_openai_tool_call(client, name, args)
        return {
            "tool_call_id": tool_call.get("id"),
            "role": "tool",
            "name": name,
            "content": json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        }
    except Exception as e:
        return {
            "tool_call_id": tool_call.get("id"),
            "role": "tool",
            "name": name,
            "content": json.dumps({"error": str(e)})
        }


__all__ = [
    "get_openai_tools",
    "get_openai_tool_definitions",
    "get_openai_agents_tools",
    "execute_openai_tool_call",
    "handle_openai_tool_call",
]
