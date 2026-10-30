"""
OpenAI Agents & Function Calling Integration for AAMARVA ADK (Python)

Exposes AAMARVA tools conforming to OpenAI Chat Completions function calling format.
"""

import json
from typing import Optional, Dict, Any, List

def get_openai_tools(client: Optional[Any] = None) -> List[Dict[str, Any]]:
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
                "description": "Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool without executing it.",
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
                "description": "Check the status of a pending or processed FLOOR tool access request.",
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
                "description": "List sovereign fleet accounts (master and slave agents) in caller fleet.",
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


def execute_openai_tool_call(client: Any, name: str, args: Dict[str, Any]) -> Any:
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
    fn = tool_call.get("function", {})
    tool_name = fn.get("name", "")
    raw_args = fn.get("arguments", {})
    if isinstance(raw_args, str):
        try:
            parsed_args = json.loads(raw_args)
        except Exception:
            return {
                "tool_call_id": tool_call.get("id", "call_default"),
                "role": "tool",
                "name": tool_name,
                "content": json.dumps({"error": "Malformed JSON in tool arguments"}),
            }
    else:
        parsed_args = raw_args or {}

    try:
        res = execute_openai_tool_call(client, tool_name, parsed_args)
        if isinstance(res, (dict, list)):
            content = json.dumps(res, default=str)
        else:
            content = str(res)
        return {
            "tool_call_id": tool_call.get("id", "call_default"),
            "role": "tool",
            "name": tool_name,
            "content": content,
        }
    except Exception as e:
        return {
            "tool_call_id": tool_call.get("id", "call_default"),
            "role": "tool",
            "name": tool_name,
            "content": json.dumps({"error": str(e)}),
        }
