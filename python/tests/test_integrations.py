import unittest
from aamarva import Aamarva
from aamarva.integrations import (
    AamarvaIntegrationContract,
    AamarvaBridge,
    LangGraphAamarvaAdapter,
    CrewAiAamarvaAdapter,
    HermesAamarvaAdapter,
    AutoGenAamarvaAdapter,
    AgnoAamarvaToolkit,
    OpenAIAgentsAamarvaAdapter,
    create_langchain_tools,
    create_crewai_tools,
    create_hermes_tools,
    create_autogen_tools,
    create_agno_toolkit,
    create_openai_agent_tools,
)


class TestPythonFrameworkIntegrations(unittest.TestCase):
    def setUp(self):
        self.client = Aamarva(agent_id="test-agent", api_key="test-key")
        self.contract = AamarvaIntegrationContract(aamarva=self.client)

    def test_langgraph_adapter(self):
        tools = create_langchain_tools(self.contract)
        self.assertGreaterEqual(len(tools), 4)
        tool_names = [t["name"] for t in tools]
        self.assertIn("aamarva_discover", tool_names)
        self.assertIn("aamarva_connect", tool_names)
        self.assertIn("aamarva_emit", tool_names)
        self.assertIn("aamarva_intake", tool_names)

    def test_crewai_adapter(self):
        tools = create_crewai_tools(self.contract)
        self.assertGreaterEqual(len(tools), 4)
        tool_names = [t["name"] for t in tools]
        self.assertIn("AamarvaDiscoveryTool", tool_names)
        self.assertIn("AamarvaConnectionTool", tool_names)

    def test_hermes_adapter(self):
        tools = create_hermes_tools(self.contract)
        self.assertGreaterEqual(len(tools), 4)
        tool_names = [t["name"] for t in tools]
        self.assertIn("aamarva_discover", tool_names)
        self.assertIn("aamarva_connect", tool_names)
        self.assertIn("aamarva_emit", tool_names)

        # Check tool execution interface
        disc_tool = next(t for t in tools if t["name"] == "aamarva_discover")
        self.assertIn("parameters", disc_tool)
        self.assertTrue(callable(disc_tool["execute"]))

    def test_autogen_adapter(self):
        func_map = create_autogen_tools(self.contract)
        self.assertIn("aamarva_discover", func_map)
        self.assertIn("aamarva_connect", func_map)
        self.assertTrue(callable(func_map["aamarva_discover"]))

    def test_agno_toolkit(self):
        toolkit = create_agno_toolkit(self.contract)
        self.assertEqual(toolkit.name, "aamarva_toolkit")
        self.assertGreaterEqual(len(toolkit.tools), 4)

    def test_openai_agents_adapter(self):
        tools = create_openai_agent_tools(self.contract)
        self.assertGreaterEqual(len(tools), 5)
        for t in tools:
            self.assertTrue(callable(t))
            self.assertIsNotNone(t.__doc__)


if __name__ == "__main__":
    unittest.main()
