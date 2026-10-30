"""
LangGraph Integration for AAMARVA ADK (Python)

Provides genuine LangGraph-compatible ToolNode integration for sovereign fleet capabilities.
"""

from typing import Optional, Any
from .langchain import get_langchain_tools

try:
    from langgraph.prebuilt import ToolNode
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False


def create_langgraph_tool_node(client: Optional[Any] = None) -> Any:
    """
    Creates a genuine LangGraph ToolNode containing all AAMARVA tools.
    """
    if not HAS_LANGGRAPH:
        raise ImportError(
            "LangGraph dependencies not found. Please install 'langgraph' via 'pip install aamarva[langgraph]' to use this integration."
        )

    tools = get_langchain_tools(client)
    return ToolNode(tools)


def execute_langgraph_action(client: Any, action: dict) -> dict:
    """
    Executes an action against the AAMARVA client and returns LangGraph-formatted output.
    """
    from .openai import execute_openai_tool_call
    tool_name = action.get("tool", "")
    tool_input = action.get("toolInput", {})
    if isinstance(tool_input, str):
        import json
        try:
            tool_input = json.loads(tool_input)
        except Exception:
            tool_input = {"input": tool_input}

    res = execute_openai_tool_call(client, tool_name, tool_input)
    import json
    return {
        "output": json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
    }


__all__ = [
    "create_langgraph_tool_node",
    "execute_langgraph_action",
]
