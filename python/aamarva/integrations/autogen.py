"""
AutoGen Integration for AAMARVA ADK (Python)

Provides genuine AutoGen-compatible tool implementations:
- Modern AutoGen (autogen-agentchat >= 0.4.0, autogen-core >= 0.4.0):
  Uses autogen_core.tools.FunctionTool objects and annotated functions.
- Legacy AutoGen (pyautogen <= 0.2.x):
  Provides register_legacy_autogen_tools for ConversableAgent.
"""

from typing import Optional, Dict, Any, List, Callable
from .openai import get_openai_tools, execute_openai_tool_call

try:
    from autogen_core.tools import FunctionTool as ModernFunctionTool
    HAS_AUTOGEN_MODERN = True
except ImportError:
    HAS_AUTOGEN_MODERN = False
    ModernFunctionTool = None


def get_autogen_agentchat_tools(client: Optional[Any] = None) -> List[Any]:
    """
    Returns native FunctionTool instances for modern AutoGen (autogen-agentchat >= 0.4.0).
    These tools can be passed directly to AssistantAgent(tools=[...]).
    """
    if not HAS_AUTOGEN_MODERN:
        raise ImportError(
            "Modern AutoGen dependencies not found. Please install 'autogen-agentchat>=0.4.0' and "
            "'autogen-core>=0.4.0' via 'pip install aamarva[autogen]'."
        )

    if client is None:
        from ..client import Aamarva
        client = Aamarva()

    openai_tools = get_openai_tools(client)
    tools = []

    for item in openai_tools:
        fn = item["function"]
        name = fn["name"]
        description = fn["description"]

        def make_func(tool_name: str):
            async def func(**kwargs) -> str:
                res = execute_openai_tool_call(client, tool_name, kwargs)
                import json
                return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
            return func

        func = make_func(name)
        func.__name__ = name
        func.__doc__ = description

        tools.append(ModernFunctionTool(func, description=description, name=name))

    return tools


def get_autogen_tools(client: Optional[Any] = None) -> List[Any]:
    """
    Returns tools for AutoGen. If modern AutoGen (>=0.4.0) is installed, returns
    FunctionTool instances. Otherwise returns schema-annotated callables.
    """
    if HAS_AUTOGEN_MODERN:
        return get_autogen_agentchat_tools(client)

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
            def func(**kwargs):
                return execute_openai_tool_call(client, tool_name, kwargs)
            return func

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
    agent_or_caller: Any,
    executor_agent: Optional[Any] = None,
    client: Optional[Any] = None,
) -> None:
    """
    Registers AAMARVA tools onto an AutoGen agent.
    Supports modern AutoGen agents (via agent.register_tool or agent._tools)
    as well as legacy ConversableAgent (via register_for_llm / register_for_execution).
    """
    if hasattr(agent_or_caller, "register_tool"):
        # Modern AutoGen agent interface
        tools = get_autogen_tools(client)
        for tool in tools:
            agent_or_caller.register_tool(tool)
    else:
        # Fall back to legacy registration
        register_legacy_autogen_tools(agent_or_caller, executor_agent, client)


def register_legacy_autogen_tools(
    caller_agent: Any,
    executor_agent: Optional[Any] = None,
    client: Optional[Any] = None,
) -> None:
    """
    Registers tools on legacy AutoGen 0.2.x ConversableAgent instances.
    """
    tools = get_autogen_tools(client)

    for tool in tools:
        name = tool["name"] if isinstance(tool, dict) else getattr(tool, "name", str(tool))
        description = tool["description"] if isinstance(tool, dict) else getattr(tool, "description", "")
        func = tool["function"] if isinstance(tool, dict) else getattr(tool, "func", tool)

        if hasattr(caller_agent, "register_for_llm"):
            caller_agent.register_for_llm(name=name, description=description)(func)

        exec_target = executor_agent or caller_agent
        if hasattr(exec_target, "register_for_execution"):
            exec_target.register_for_execution(name=name)(func)
        elif hasattr(exec_target, "register_function"):
            exec_target.register_function(name=name, func=func, description=description)


__all__ = [
    "get_autogen_tools",
    "get_autogen_agentchat_tools",
    "register_autogen_tools",
    "register_legacy_autogen_tools",
]
