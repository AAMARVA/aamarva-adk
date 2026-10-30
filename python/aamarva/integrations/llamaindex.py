"""
LlamaIndex Integration for AAMARVA ADK (Python)

Provides genuine LlamaIndex FunctionTool instances exposing AAMARVA tools.
"""

from typing import Optional, List, Any
from .openai import get_openai_tool_definitions, execute_openai_tool_call

try:
    from llama_index.core.tools import FunctionTool
    HAS_LLAMAINDEX = True
except ImportError:
    HAS_LLAMAINDEX = False
    FunctionTool = object


class AamarvaLlamaIndexTool:
    """
    AAMARVA LlamaIndex tool adapter.
    """
    @classmethod
    def from_client(cls, client: Optional[Any] = None) -> List[Any]:
        return get_llamaindex_tools(client)


def get_llamaindex_tools(client: Optional[Any] = None) -> List[Any]:
    """
    Returns an array of genuine LlamaIndex FunctionTool instances.
    """
    if not HAS_LLAMAINDEX:
        raise ImportError(
            "LlamaIndex dependencies not found. Please install 'llama-index-core' via 'pip install aamarva[llamaindex]'."
        )

    if client is None:
        from ..client import Aamarva
        client = Aamarva()

    tool_defs = get_openai_tool_definitions()
    tools = []

    for item in tool_defs:
        fn_def = item["function"]
        name = fn_def["name"]
        description = fn_def["description"]

        def create_func(tool_name: str):
            def func(**kwargs):
                return execute_openai_tool_call(client, tool_name, kwargs)
            func.__name__ = tool_name
            func.__doc__ = description
            return func

        tool = FunctionTool.from_defaults(
            fn=create_func(name),
            name=name,
            description=description,
        )
        tools.append(tool)

    return tools


def execute_llamaindex_tool(client: Any, name: str, args: dict) -> Any:
    """
    Executes a LlamaIndex tool by name.
    """
    return execute_openai_tool_call(client, name, args)


__all__ = [
    "AamarvaLlamaIndexTool",
    "get_llamaindex_tools",
    "execute_llamaindex_tool",
]
