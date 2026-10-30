import io
import json
import unittest
from unittest.mock import MagicMock

from aamarva import Aamarva
from aamarva.integrations.mcp_server import (
    AamarvaMcpServer,
    create_aamarva_mcp_server,
)
from aamarva.integrations.openai import (
    get_openai_tools,
    execute_openai_tool_call,
    handle_openai_tool_call,
)
from aamarva.integrations.langchain import (
    get_langchain_tools,
    execute_langchain_tool,
)
from aamarva.integrations.langgraph import (
    create_langgraph_tool_node,
    execute_langgraph_action,
)
from aamarva.integrations.crewai import (
    get_crewai_tools,
    AamarvaFloorTool,
    AamarvaMessagingTool,
    AamarvaClusterTool,
    AamarvaWatchtowerTool,
)
from aamarva.integrations.autogen import (
    get_autogen_tools,
    register_autogen_tools,
)
from aamarva.integrations.google_adk import (
    get_google_adk_tools,
    get_google_adk_function_declarations,
    execute_google_adk_function,
)
from aamarva.integrations.agno import (
    AamarvaAgnoToolkit,
    get_agno_tools,
)
from aamarva.integrations.llamaindex import (
    get_llamaindex_tools,
    execute_llamaindex_tool,
)
from aamarva.errors import AamarvaError


class TestFrameworkIntegrations(unittest.TestCase):
    def setUp(self):
        self.client = Aamarva(agent_id="AMR-TEST-PYTHON", api_key="sk_py_test_123")
        self.client.http.request = MagicMock()

    # -------------------------------------------------------------------------
    # 1. MCP Server & Transports
    # -------------------------------------------------------------------------
    def test_mcp_server_protocol_and_tools(self):
        server = create_aamarva_mcp_server(self.client)
        self.assertIsInstance(server, AamarvaMcpServer)

        tools = server.get_tools()
        self.assertGreaterEqual(len(tools), 12)
        tool_names = [t.name for t in tools]
        self.assertIn("aamarva_floor_list_tools", tool_names)
        self.assertIn("aamarva_floor_execute_tool", tool_names)
        self.assertIn("aamarva_send_message", tool_names)

        # JSON-RPC lifecycle: initialize
        init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        init_res = server.handle_json_rpc(init_req)
        self.assertEqual(init_res["jsonrpc"], "2.0")
        self.assertEqual(init_res["id"], 1)
        self.assertEqual(init_res["result"]["serverInfo"]["name"], "aamarva-adk")

        # JSON-RPC: ping
        ping_res = server.handle_json_rpc({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        self.assertEqual(ping_res["id"], 2)

        # JSON-RPC: tools/list
        list_res = server.handle_json_rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        listed_tools = list_res["result"]["tools"]
        self.assertEqual(len(listed_tools), len(tools))

        # JSON-RPC: tools/call
        self.client.http.request.return_value = {
            "data": [
                {
                    "id": "tool_sec_edgar",
                    "name": "SEC EDGAR Filings",
                    "description": "SEC filings tool",
                    "accessStatus": "authorized",
                    "inputSchema": {},
                }
            ]
        }
        call_res = server.handle_json_rpc({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "aamarva_floor_list_tools", "arguments": {}},
        })
        self.assertFalse(call_res["result"]["isError"])
        self.assertIn("tool_sec_edgar", call_res["result"]["content"][0]["text"])

        # Stdio simulation
        in_buf = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 10, "method": "ping"}) + "\n")
        out_buf = io.StringIO()
        server.run_stdio_server(input_stream=in_buf, output_stream=out_buf)
        out_lines = out_buf.getvalue().strip().split("\n")
        self.assertEqual(len(out_lines), 1)
        parsed_out = json.loads(out_lines[0])
        self.assertEqual(parsed_out["id"], 10)

        # Streamable HTTP handler
        http_handler = server.create_http_handler()
        res = http_handler({"jsonrpc": "2.0", "id": 20, "method": "ping"})
        self.assertEqual(res["id"], 20)

    # -------------------------------------------------------------------------
    # 2. OpenAI Function Calling & Agents
    # -------------------------------------------------------------------------
    def test_openai_integration(self):
        tools = get_openai_tools(self.client)
        self.assertEqual(len(tools), 12)
        for t in tools:
            self.assertEqual(t["type"], "function")
            self.assertTrue(t["function"]["name"])

        # Mock FLOOR execution
        self.client.http.request.return_value = {
            "status": "executed",
            "data": {"status": "executed", "result": {"filings": ["10-K"]}},
        }
        res = execute_openai_tool_call(self.client, "aamarva_floor_execute_tool", {
            "toolId": "tool_sec_edgar",
            "arguments": {"ticker": "AAPL"},
        })
        self.assertEqual(res.status, "executed")

        # Handle tool call with JSON string
        msg = handle_openai_tool_call(self.client, {
            "id": "call_123",
            "function": {
                "name": "aamarva_floor_execute_tool",
                "arguments": json.dumps({"toolId": "tool_sec_edgar", "arguments": {}}),
            },
        })
        self.assertEqual(msg["role"], "tool")
        self.assertEqual(msg["tool_call_id"], "call_123")

    # -------------------------------------------------------------------------
    # 3. LangChain Integration
    # -------------------------------------------------------------------------
    def test_langchain_integration(self):
        tools = get_langchain_tools(self.client)
        self.assertEqual(len(tools), 12)
        for t in tools:
            self.assertTrue(hasattr(t, "name"))
            self.assertTrue(hasattr(t, "invoke"))
            self.assertTrue(hasattr(t, "run"))

        self.client.http.request.return_value = {
            "status": "executed",
            "data": {"status": "executed", "result": {"status": "ok"}},
        }
        output = execute_langchain_tool(self.client, "aamarva_floor_execute_tool", {
            "toolId": "tool_sec_edgar",
            "arguments": {},
        })
        self.assertIn("executed", output)

    # -------------------------------------------------------------------------
    # 4. LangGraph Integration
    # -------------------------------------------------------------------------
    def test_langgraph_integration(self):
        node = create_langgraph_tool_node(self.client)
        self.assertTrue(callable(node))

        self.client.http.request.return_value = {"data": []}
        state = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"id": "lg_1", "name": "aamarva_floor_list_tools", "args": {}}
                    ],
                }
            ]
        }
        res = node(state)
        self.assertEqual(len(res["messages"]), 1)
        self.assertEqual(res["messages"][0]["tool_call_id"], "lg_1")

        action_res = execute_langgraph_action(self.client, {
            "tool": "aamarva_floor_list_tools",
            "toolInput": {},
        })
        self.assertIn("output", action_res)

    # -------------------------------------------------------------------------
    # 5. CrewAI Integration
    # -------------------------------------------------------------------------
    def test_crewai_integration(self):
        tools = get_crewai_tools(self.client)
        self.assertEqual(len(tools), 4)

        floor_tool = next(t for t in tools if t.name == "aamarva_floor")
        msg_tool = next(t for t in tools if t.name == "aamarva_messaging")
        cluster_tool = next(t for t in tools if t.name == "aamarva_cluster")
        wt_tool = next(t for t in tools if t.name == "aamarva_watchtower")

        self.client.http.request.return_value = {"data": []}
        floor_res = floor_tool.run(action="list")
        self.assertIsInstance(floor_res, str)

        self.client.http.request.return_value = [{"id": "ev_1", "type": "auth", "summary": "mock_event"}]
        wt_res = wt_tool.run(limit=5)
        self.assertIn("mock_event", wt_res)

    # -------------------------------------------------------------------------
    # 6. AutoGen Integration
    # -------------------------------------------------------------------------
    def test_autogen_integration(self):
        tools = get_autogen_tools(self.client)
        self.assertEqual(len(tools), 12)

        class MockAgent:
            def __init__(self):
                self.llm_funcs = {}
                self.exec_funcs = {}

            def register_for_llm(self, name, description):
                def dec(fn):
                    self.llm_funcs[name] = fn
                    return fn
                return dec

            def register_for_execution(self, name):
                def dec(fn):
                    self.exec_funcs[name] = fn
                    return fn
                return dec

        agent = MockAgent()
        register_autogen_tools(agent, agent, self.client)
        self.assertEqual(len(agent.llm_funcs), 12)
        self.assertEqual(len(agent.exec_funcs), 12)

    # -------------------------------------------------------------------------
    # 7. Google ADK Integration
    # -------------------------------------------------------------------------
    def test_google_adk_integration(self):
        decls = get_google_adk_function_declarations(self.client)
        self.assertEqual(len(decls), 12)
        for d in decls:
            self.assertEqual(d["parameters"]["type"], "OBJECT")

        tools = get_google_adk_tools(self.client)
        self.assertEqual(len(tools["function_declarations"]), 12)

        self.client.http.request.return_value = {"data": []}
        res = execute_google_adk_function(self.client, {
            "name": "aamarva_floor_list_tools",
            "args": {},
        })
        self.assertEqual(res["response"]["name"], "aamarva_floor_list_tools")

    # -------------------------------------------------------------------------
    # 8. Agno Integration
    # -------------------------------------------------------------------------
    def test_agno_integration(self):
        toolkit = AamarvaAgnoToolkit(client=self.client)
        self.assertEqual(toolkit.name, "aamarva_toolkit")
        self.assertEqual(len(toolkit._tools), 8)

        self.client.http.request.return_value = {"data": []}
        tools = get_agno_tools(self.client)
        self.assertEqual(len(tools), 8)
        list_fn = tools[0]
        res = list_fn()
        self.assertIsInstance(res, list)

    # -------------------------------------------------------------------------
    # 9. LlamaIndex Integration
    # -------------------------------------------------------------------------
    def test_llamaindex_integration(self):
        tools = get_llamaindex_tools(self.client)
        self.assertEqual(len(tools), 12)
        for t in tools:
            self.assertTrue(hasattr(t, "metadata"))
            self.assertTrue(callable(t))

        self.client.http.request.return_value = {"data": []}
        res = execute_llamaindex_tool(self.client, "aamarva_floor_list_tools", {})
        self.assertIsInstance(res, list)

    # -------------------------------------------------------------------------
    # 10. FLOOR Security Fail-Closed in Framework Adapters
    # -------------------------------------------------------------------------
    def test_floor_unauthorized_fails_closed(self):
        # When backend denies execution
        self.client.http.request.side_effect = AamarvaError(
            "Tool execution denied: unassigned", code="FLOOR_ACCESS_DENIED"
        )

        # 1. MCP
        server = create_aamarva_mcp_server(self.client)
        mcp_res = server.handle_tool_call("aamarva_floor_execute_tool", {
            "toolId": "tool_market_depth",
            "arguments": {},
        })
        self.assertTrue(mcp_res["isError"])
        self.assertIn("FLOOR_ACCESS_DENIED", mcp_res["content"][0]["text"])

        # 2. OpenAI
        open_ai_res = handle_openai_tool_call(self.client, {
            "id": "call_err",
            "function": {
                "name": "aamarva_floor_execute_tool",
                "arguments": {"toolId": "tool_market_depth"},
            },
        })
        self.assertIn("error", open_ai_res["content"])

        # 3. LangChain
        lc_res = execute_langchain_tool(self.client, "aamarva_floor_execute_tool", {
            "toolId": "tool_market_depth",
        })
        self.assertIn("error", lc_res)


if __name__ == "__main__":
    unittest.main()
