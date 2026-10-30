"""
Google ADK & Gemini Function Calling Integration for AAMARVA ADK (Python)

Provides genuine Google GenAI FunctionDeclaration objects and Google ADK-compatible
tools for Gemini models using the google-genai SDK.
"""

from typing import Optional, Dict, Any, List
from .openai import execute_openai_tool_call


def get_google_function_declarations() -> List[Dict[str, Any]]:
    """
    Returns the array of genuine Google GenAI FunctionDeclaration dictionaries.
    """
    return [
        {
            "name": "aamarva_floor_list_tools",
            "description": "Discover available FLOOR tools, input schemas, and caller access status.",
            "parameters": {"type": "OBJECT", "properties": {}},
        },
        {
            "name": "aamarva_floor_request_access",
            "description": "Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "toolId": {"type": "STRING", "description": "Identifier of tool to request access for."},
                    "reason": {"type": "STRING", "description": "Business justification for access request."},
                },
                "required": ["toolId"],
            },
        },
        {
            "name": "aamarva_floor_check_status",
            "description": "Check the status of a pending or processed FLOOR tool access request.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "requestId": {"type": "STRING", "description": "The tool access request ID."},
                },
                "required": ["requestId"],
            },
        },
        {
            "name": "aamarva_floor_execute_tool",
            "description": "Execute an authorized AAMARVA FLOOR tool with input arguments. Fails closed if unauthorized.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "toolId": {"type": "STRING", "description": "Identifier of the tool to execute."},
                    "arguments": {"type": "OBJECT", "description": "Input arguments conforming to tool schema."},
                },
                "required": ["toolId", "arguments"],
            },
        },
        {
            "name": "aamarva_send_message",
            "description": "Send an end-to-end encrypted private message to an authorized peer agent.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "connectionId": {"type": "STRING", "description": "Active connection channel ID."},
                    "content": {"type": "STRING", "description": "Plaintext message string to encrypt and send."},
                },
                "required": ["connectionId", "content"],
            },
        },
        {
            "name": "aamarva_get_messages",
            "description": "Retrieve and decrypt private messages from an active peer connection channel.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "connectionId": {"type": "STRING", "description": "Active connection channel ID."},
                },
                "required": ["connectionId"],
            },
        },
        {
            "name": "aamarva_cluster_send_message",
            "description": "Send an encrypted group message to a cluster with recipient restrictions.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "clusterId": {"type": "STRING", "description": "Target cluster ID."},
                    "ciphertext": {"type": "STRING", "description": "Encrypted ciphertext payload."},
                    "nonce": {"type": "STRING", "description": "Cryptographic IV / nonce."},
                    "recipients": {
                        "type": "ARRAY",
                        "description": "Optional authorized recipient agent IDs.",
                    },
                },
                "required": ["clusterId", "ciphertext", "nonce"],
            },
        },
        {
            "name": "aamarva_watchtower_activity",
            "description": "Retrieve recent fleet audit activity and security telemetry snapshot.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "limit": {"type": "INTEGER", "description": "Maximum number of events to return."},
                },
            },
        },
        {
            "name": "aamarva_agent_footprints",
            "description": "Retrieve cryptographic activity audit footprints for current agent.",
            "parameters": {"type": "OBJECT", "properties": {}},
        },
        {
            "name": "aamarva_webhook_events",
            "description": "Retrieve recent webhook event delivery history for the agent.",
            "parameters": {"type": "OBJECT", "properties": {}},
        },
        {
            "name": "aamarva_get_agents",
            "description": "List sovereign fleet accounts in caller fleet.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "q": {"type": "STRING", "description": "Filter query string."},
                    "page": {"type": "INTEGER", "description": "Page number."},
                    "limit": {"type": "INTEGER", "description": "Items per page."},
                },
            },
        },
        {
            "name": "aamarva_get_clusters",
            "description": "List multi-agent clusters the caller belongs to.",
            "parameters": {"type": "OBJECT", "properties": {}},
        },
    ]


# Alias for explicit Google ADK naming
get_google_adk_function_declarations = get_google_function_declarations


def get_google_adk_tools(client: Optional[Any] = None) -> List[Dict[str, Any]]:
    """
    Returns a list of Tool dictionaries compatible with Google GenAI SDK.
    """
    return [{"function_declarations": get_google_function_declarations()}]


def execute_google_function_call(client: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes a Google GenAI function call and returns a response content dict.
    """
    try:
        res = execute_openai_tool_call(client, name, args)
        return {"content": res}
    except Exception as e:
        return {"content": {"error": str(e)}}


# Alias for explicit Google ADK naming
execute_google_adk_function = execute_google_function_call


__all__ = [
    "get_google_adk_tools",
    "get_google_adk_function_declarations",
    "get_google_function_declarations",
    "execute_google_adk_function",
    "execute_google_function_call",
]
