"""
AAMARVA ADK - Python Framework Integrations

Provides native framework integrations for:
- Model Context Protocol (MCP) Server & Transports
- OpenAI Agents SDK & Chat Completions
- LangChain Tools
- LangGraph Tool Nodes
- CrewAI BaseTools
- AutoGen Tool Functions & Agent Registration
- Google ADK (Gemini) Function Declarations
- Agno (Phidata) Toolkits
- LlamaIndex FunctionTools
"""

from .mcp_server import AamarvaMcpServer, create_aamarva_mcp_server, McpToolDefinition
from .openai import get_openai_tools, execute_openai_tool_call, handle_openai_tool_call
from .langchain import get_langchain_tools, execute_langchain_tool, AamarvaLangChainTool
from .langgraph import create_langgraph_tool_node, execute_langgraph_action
from .crewai import (
    get_crewai_tools,
    AamarvaFloorTool,
    AamarvaMessagingTool,
    AamarvaClusterTool,
    AamarvaWatchtowerTool,
)
from .autogen import get_autogen_tools, register_autogen_tools
from .google_adk import (
    get_google_adk_tools,
    get_google_adk_function_declarations,
    execute_google_adk_function,
)
from .agno import AamarvaAgnoToolkit, get_agno_tools
from .llamaindex import get_llamaindex_tools, execute_llamaindex_tool

__all__ = [
    # MCP
    "AamarvaMcpServer",
    "create_aamarva_mcp_server",
    "McpToolDefinition",
    # OpenAI
    "get_openai_tools",
    "execute_openai_tool_call",
    "handle_openai_tool_call",
    # LangChain & LangGraph
    "get_langchain_tools",
    "execute_langchain_tool",
    "AamarvaLangChainTool",
    "create_langgraph_tool_node",
    "execute_langgraph_action",
    # CrewAI
    "get_crewai_tools",
    "AamarvaFloorTool",
    "AamarvaMessagingTool",
    "AamarvaClusterTool",
    "AamarvaWatchtowerTool",
    # AutoGen
    "get_autogen_tools",
    "register_autogen_tools",
    # Google ADK
    "get_google_adk_tools",
    "get_google_adk_function_declarations",
    "execute_google_adk_function",
    # Agno
    "AamarvaAgnoToolkit",
    "get_agno_tools",
    # LlamaIndex
    "get_llamaindex_tools",
    "execute_llamaindex_tool",
]
