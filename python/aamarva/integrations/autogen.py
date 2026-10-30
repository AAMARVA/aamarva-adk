"""
AutoGen Integration for AAMARVA ADK (Python)

Provides AutoGen tool wrappers and multi-agent registration helpers.
"""

from typing import Optional, Dict, Any, List, Callable
from .openai import get_openai_tools, execute_openai_tool_call


def get_autogen_tools(client: Optional[Any] = None) -> List[Dict[str, Any]]:
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

        tools.append({
            "name": name,
            "description": description,
            "parameters": params,
            "function": func,
        })

    return tools


def register_autogen_tools(
    caller_agent: Any,
    executor_agent: Optional[Any] = None,
    client: Optional[Any] = None,
) -> None:
    """
    Registers all AAMARVA tools with AutoGen ConversableAgent instances
    using the standard register_for_llm and register_for_execution APIs.
    """
    tools = get_autogen_tools(client)

    for tool in tools:
        name = tool["name"]
        description = tool["description"]
        func = tool["function"]

        # If standard AutoGen registration APIs are available:
        if hasattr(caller_agent, "register_for_llm"):
            caller_agent.register_for_llm(name=name, description=description)(func)

        exec_target = executor_agent or caller_agent
        if hasattr(exec_target, "register_for_execution"):
            exec_target.register_for_execution(name=name)(func)
        elif hasattr(exec_target, "register_function"):
            exec_target.register_function(name=name, func=func, description=description)
