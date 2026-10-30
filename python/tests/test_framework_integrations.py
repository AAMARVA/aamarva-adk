import unittest
from unittest.mock import MagicMock
import json

from aamarva import Aamarva
from aamarva.integrations import (
    AamarvaMcpServer,
    create_aamarva_mcp_server,
    McpToolDefinition,
    get_openai_tools,
    get_openai_tool_definitions,
    get_openai_agents_tools,
    execute_openai_tool_call,
    handle_openai_tool_call,
    get_langchain_tools,
    execute_langchain_tool,
    AamarvaLangChainTool,
    create_langgraph_tool_node,
    execute_langgraph_action,
    get_crewai_tools,
    AamarvaFloorTool,
    AamarvaMessagingTool,
    AamarvaClusterTool,
    AamarvaWatchtowerTool,
    get_autogen_tools,
    get_autogen_agentchat_tools,
    register_autogen_tools,
    get_google_adk_tools,
    get_google_adk_function_declarations,
    get_google_function_declarations,
    execute_google_adk_function,
    execute_google_function_call,
    AamarvaAgnoToolkit,
    AamarvaToolkit,
    get_agno_tools,
    get_llamaindex_tools,
    execute_llamaindex_tool,
    AamarvaLlamaIndexTool,
)


class TestFrameworkIntegrationExports(unittest.TestCase):
    def setUp(self):
        self.client = Aamarva(agent_id="AMR-TEST-PYTHON", api_key="sk_py_test_123")
        self.client.http.request = MagicMock()

    def test_all_symbols_exist(self):
        """Verify all requested integration symbols are defined and callable/classes."""
        self.assertTrue(callable(get_openai_tools))
        self.assertTrue(callable(get_openai_tool_definitions))
        self.assertTrue(callable(execute_openai_tool_call))
        self.assertTrue(callable(handle_openai_tool_call))
        self.assertTrue(callable(get_langchain_tools))
        self.assertTrue(callable(execute_langchain_tool))
        self.assertTrue(callable(create_langgraph_tool_node))
        self.assertTrue(callable(execute_langgraph_action))
        self.assertTrue(callable(get_crewai_tools))
        self.assertTrue(callable(get_autogen_tools))
        self.assertTrue(callable(get_autogen_agentchat_tools))
        self.assertTrue(callable(register_autogen_tools))
        self.assertTrue(callable(get_google_adk_tools))
        self.assertTrue(callable(get_google_adk_function_declarations))
        self.assertTrue(callable(get_google_function_declarations))
        self.assertTrue(callable(execute_google_adk_function))
        self.assertTrue(callable(execute_google_function_call))
        self.assertTrue(callable(get_agno_tools))
        self.assertTrue(callable(get_llamaindex_tools))
        self.assertTrue(callable(execute_llamaindex_tool))
        self.assertIsNotNone(AamarvaAgnoToolkit)
        self.assertIsNotNone(AamarvaToolkit)
        self.assertIsNotNone(AamarvaLangChainTool)
        self.assertIsNotNone(AamarvaFloorTool)
        self.assertIsNotNone(AamarvaMessagingTool)
        self.assertIsNotNone(AamarvaClusterTool)
        self.assertIsNotNone(AamarvaWatchtowerTool)
        self.assertIsNotNone(AamarvaLlamaIndexTool)
        self.assertIsNotNone(AamarvaMcpServer)
        self.assertIsNotNone(McpToolDefinition)

    def test_openai_tool_definitions_and_execution(self):
        """Test OpenAI tools and function calling dispatch."""
        tools = get_openai_tools(self.client)
        self.assertEqual(len(tools), 12)
        self.assertTrue(callable(tools[0]["execute"]))

        self.client.http.request.return_value = {"data": []}
        res = execute_openai_tool_call(self.client, "aamarva_floor_list_tools", {})
        self.assertIsInstance(res, list)

        call_res = handle_openai_tool_call(self.client, {
            "id": "call_1",
            "function": {"name": "aamarva_floor_list_tools", "arguments": "{}"}
        })
        self.assertEqual(call_res["role"], "tool")
        self.assertEqual(call_res["tool_call_id"], "call_1")

    def test_google_adk_declarations_and_dispatch(self):
        """Test Google ADK function declarations and dispatch."""
        decls = get_google_adk_function_declarations()
        self.assertEqual(len(decls), 12)
        self.assertEqual(decls, get_google_function_declarations())

        self.client.http.request.return_value = {"data": []}
        res = execute_google_adk_function(self.client, "aamarva_floor_list_tools", {})
        self.assertIn("content", res)

    def test_langgraph_action_execution(self):
        """Test execute_langgraph_action dispatch."""
        self.client.http.request.return_value = {"data": []}
        res = execute_langgraph_action(self.client, {
            "tool": "aamarva_floor_list_tools",
            "toolInput": {},
        })
        self.assertIn("output", res)

    def test_mcp_server_safe_import(self):
        """Test MCP server class is imported without error."""
        try:
            server = AamarvaMcpServer(self.client)
            self.assertIsNotNone(server.server)
        except ImportError as e:
            self.assertIn("Model Context Protocol (MCP) dependencies not found", str(e))

    def test_autogen_tools_format(self):
        """Test AutoGen tools structure."""
        tools = get_autogen_tools(self.client)
        self.assertEqual(len(tools), 12)

    def test_crewai_safe_import(self):
        """Test CrewAI classes and tools."""
        try:
            tools = get_crewai_tools(self.client)
            self.assertEqual(len(tools), 4)
        except ImportError as e:
            self.assertIn("CrewAI", str(e))

    def test_agno_safe_import(self):
        """Test Agno toolkit alias and classes."""
        self.assertEqual(AamarvaAgnoToolkit, AamarvaToolkit)
        try:
            toolkit = AamarvaAgnoToolkit(self.client)
            self.assertIsNotNone(toolkit)
        except ImportError as e:
            self.assertIn("Agno", str(e))

    def test_langchain_safe_import(self):
        """Test LangChain tools."""
        try:
            tools = get_langchain_tools(self.client)
            self.assertEqual(len(tools), 12)
        except ImportError as e:
            self.assertIn("LangChain", str(e))

    def test_llamaindex_safe_import(self):
        """Test LlamaIndex tools."""
        try:
            tools = get_llamaindex_tools(self.client)
            self.assertEqual(len(tools), 12)
        except ImportError as e:
            self.assertIn("LlamaIndex", str(e))


if __name__ == "__main__":
    unittest.main()
