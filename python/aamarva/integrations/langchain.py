"""
LangChain Integration for AAMARVA ADK (Python)

Provides genuine LangChain StructuredTool instances exposing AAMARVA
sovereign fleet capabilities and FLOOR governance.
"""

from typing import Optional, List, Any, Callable
from .openai import get_openai_tools, execute_openai_tool_call

try:
    from langchain_core.tools import StructuredTool, BaseTool
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    StructuredTool = object
    BaseTool = object


class AamarvaLangChainTool(StructuredTool if HAS_LANGCHAIN else object):
    """
    AAMARVA LangChain StructuredTool implementation.
    """
    @classmethod
    def create(cls, name: str, description: str, handler: Callable[..., Any]):
        if not HAS_LANGCHAIN:
            raise ImportError(
                "LangChain dependencies not found. Please install 'langchain-core' via 'pip install aamarva[langchain]' to use this integration."
            )
        return StructuredTool.from_function(
            func=handler,
            name=name,
            description=description,
        )


def get_langchain_tools(client: Optional[Any] = None) -> List[Any]:
    """
    Returns an array of genuine LangChain StructuredTool instances.
    """
    if not HAS_LANGCHAIN:
        raise ImportError(
            "LangChain dependencies not found. Please install 'langchain-core' via 'pip install aamarva[langchain]' to use this integration."
        )

    if client is None:
        from ..client import Aamarva
        client = Aamarva()

    openai_tools = get_openai_tools(client)
    tools = []

    for item in openai_tools:
        fn_def = item["function"]
        name = fn_def["name"]
        description = fn_def["description"]

        def create_handler(tool_name: str):
            def handler(**kwargs):
                return execute_openai_tool_call(client, tool_name, kwargs)
            return handler

        tool = StructuredTool.from_function(
            func=create_handler(name),
            name=name,
            description=description,
        )
        tools.append(tool)

    return tools


def execute_langchain_tool(client: Any, name: str, input_args: Any) -> str:
    """
    Executes a LangChain tool by name.
    """
    tools = get_langchain_tools(client)
    tool = next((t for t in tools if t.name == name), None)
    if not tool:
        raise ValueError(f"LangChain tool not found: {name}")
    
    if isinstance(input_args, dict):
        return tool.invoke(input_args)
    return tool.invoke({"input": input_args})


__all__ = [
    "AamarvaLangChainTool",
    "get_langchain_tools",
    "execute_langchain_tool",
]
