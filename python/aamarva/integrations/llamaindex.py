"""
LlamaIndex Integration for AAMARVA ADK (Python)

Provides LlamaIndex FunctionTool instances exposing AAMARVA sovereign fleet tools.
"""

from typing import Optional, Dict, Any, List, Callable
from .openai import get_openai_tools, execute_openai_tool_call


class LlamaIndexToolMetadata:
    def __init__(self, name: str, description: str, parameters: Dict[str, Any]):
        self.name = name
        self.description = description
        self.parameters = parameters


class AamarvaLlamaIndexTool:
    def __init__(self, name: str, description: str, parameters: Dict[str, Any], fn: Callable):
        self.metadata = LlamaIndexToolMetadata(name, description, parameters)
        self.fn = fn

    def __call__(self, *args, **kwargs):
        return self.call(*args, **kwargs)

    def call(self, *args, **kwargs):
        if args and isinstance(args[0], dict):
            kwargs.update(args[0])
        return self.fn(**kwargs)


def get_llamaindex_tools(client: Optional[Any] = None) -> List[Any]:
    if client is None:
        from ..client import Aamarva
        client = Aamarva()

    openai_tools = get_openai_tools(client)
    tools = []

    for item in openai_tools:
        fn = item["function"]
        name = fn["name"]
        description = fn["description"]
        params = fn["parameters"]

        def make_func(tool_name: str):
            return lambda **kwargs: execute_openai_tool_call(client, tool_name, kwargs)

        func = make_func(name)
        func.__name__ = name
        func.__doc__ = description

        tool = AamarvaLlamaIndexTool(
            name=name,
            description=description,
            parameters=params,
            fn=func,
        )
        tools.append(tool)

    return tools


def execute_llamaindex_tool(client: Any, name: str, args: Dict[str, Any]) -> Any:
    return execute_openai_tool_call(client, name, args)
