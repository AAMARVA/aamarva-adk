"""
LangGraph Integration for AAMARVA ADK (Python)

Provides LangGraph-compatible tool node runners that process tool calls
against AAMARVA sovereign fleet capabilities.
"""

import json
from typing import Optional, Dict, Any, List
from .openai import execute_openai_tool_call


def execute_langgraph_action(client: Any, action: Dict[str, Any]) -> Dict[str, str]:
    tool_name = action.get("tool", "")
    tool_input = action.get("toolInput", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except Exception:
            tool_input = {"input": tool_input}

    try:
        res = execute_openai_tool_call(client, tool_name, tool_input)
        if isinstance(res, (dict, list)):
            output = json.dumps(res, default=str)
        else:
            output = str(res)
        return {"output": output}
    except Exception as e:
        return {"output": json.dumps({"error": str(e)})}


def create_langgraph_tool_node(client: Optional[Any] = None):
    if client is None:
        from ..client import Aamarva
        client = Aamarva()

    def tool_node(state: Dict[str, Any]) -> Dict[str, Any]:
        messages = state.get("messages", [])
        if not messages:
            return {"messages": []}

        last_message = messages[-1]
        tool_calls = getattr(last_message, "tool_calls", None)
        if tool_calls is None and isinstance(last_message, dict):
            tool_calls = last_message.get("tool_calls", [])

        if not tool_calls:
            return {"messages": []}

        tool_messages = []
        for call in tool_calls:
            call_id = call.get("id") if isinstance(call, dict) else getattr(call, "id", None)
            name = call.get("name") if isinstance(call, dict) else getattr(call, "name", None)
            args = call.get("args") if isinstance(call, dict) else getattr(call, "args", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"input": args}

            try:
                res = execute_openai_tool_call(client, name, args or {})
                text = json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
            except Exception as e:
                text = json.dumps({"error": str(e)})

            tool_messages.append({
                "tool_call_id": call_id or "call_default",
                "name": name,
                "content": text,
            })

        return {"messages": tool_messages}

    return tool_node
