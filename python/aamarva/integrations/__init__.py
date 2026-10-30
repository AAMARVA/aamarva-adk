"""
AAMARVA ADK - Python Framework Integrations

Provides native framework integrations for:
- Model Context Protocol (MCP) Server & Transports
- OpenAI Agents SDK & Chat Completions
- LangChain Tools
- LangGraph Tool Nodes
- CrewAI BaseTools
- AutoGen (Modern 0.4+ and Legacy)
- Google ADK (Gemini) Function Declarations & Tools
- Agno Toolkits
- LlamaIndex FunctionTools

All integrations are lazily loaded to ensure importing this module never fails
when optional framework dependencies are missing.
"""

from typing import Any

__all__ = [
    # MCP
    "AamarvaMcpServer",
    "create_aamarva_mcp_server",
    "McpToolDefinition",
    "run_mcp_server",
    # OpenAI
    "get_openai_tools",
    "get_openai_tool_definitions",
    "get_openai_agents_tools",
    "execute_openai_tool_call",
    "handle_openai_tool_call",
    # LangChain
    "AamarvaLangChainTool",
    "get_langchain_tools",
    "execute_langchain_tool",
    # LangGraph
    "create_langgraph_tool_node",
    "execute_langgraph_action",
    # CrewAI
    "AamarvaFloorTool",
    "AamarvaMessagingTool",
    "AamarvaClusterTool",
    "AamarvaWatchtowerTool",
    "get_crewai_tools",
    # AutoGen
    "get_autogen_tools",
    "get_autogen_agentchat_tools",
    "register_autogen_tools",
    "register_legacy_autogen_tools",
    # Google ADK
    "get_google_adk_tools",
    "get_google_adk_function_declarations",
    "get_google_function_declarations",
    "execute_google_adk_function",
    "execute_google_function_call",
    # Agno
    "AamarvaAgnoToolkit",
    "AamarvaToolkit",
    "get_agno_tools",
    # LlamaIndex
    "AamarvaLlamaIndexTool",
    "get_llamaindex_tools",
    "execute_llamaindex_tool",
]


def __getattr__(name: str) -> Any:
    if name in ("AamarvaMcpServer", "create_aamarva_mcp_server", "McpToolDefinition", "run_mcp_server"):
        from . import mcp_server
        return getattr(mcp_server, name)
    elif name in ("get_openai_tools", "get_openai_tool_definitions", "get_openai_agents_tools", "execute_openai_tool_call", "handle_openai_tool_call"):
        from . import openai
        return getattr(openai, name)
    elif name in ("AamarvaLangChainTool", "get_langchain_tools", "execute_langchain_tool"):
        from . import langchain
        return getattr(langchain, name)
    elif name in ("create_langgraph_tool_node", "execute_langgraph_action"):
        from . import langgraph
        return getattr(langgraph, name)
    elif name in ("AamarvaFloorTool", "AamarvaMessagingTool", "AamarvaClusterTool", "AamarvaWatchtowerTool", "get_crewai_tools"):
        from . import crewai
        return getattr(crewai, name)
    elif name in ("get_autogen_tools", "get_autogen_agentchat_tools", "register_autogen_tools", "register_legacy_autogen_tools"):
        from . import autogen
        return getattr(autogen, name)
    elif name in ("get_google_adk_tools", "get_google_adk_function_declarations", "get_google_function_declarations", "execute_google_adk_function", "execute_google_function_call"):
        from . import google_adk
        return getattr(google_adk, name)
    elif name in ("AamarvaAgnoToolkit", "AamarvaToolkit", "get_agno_tools"):
        from . import agno
        return getattr(agno, name)
    elif name in ("AamarvaLlamaIndexTool", "get_llamaindex_tools", "execute_llamaindex_tool"):
        from . import llamaindex
        return getattr(llamaindex, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
