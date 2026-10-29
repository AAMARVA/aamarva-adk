import unittest
from aamarva import Aamarva

class TestPythonFleetGovernance(unittest.TestCase):
    def setUp(self):
        self.client = Aamarva(agent_id="AMR-MASTER", api_key="sk_master_key", target_agent_id="AMR-SLAVE-1")

    def test_legacy_adapters_removed(self):
        import aamarva
        # Framework adapters must NOT be exported from aamarva
        self.assertFalse(hasattr(aamarva, "LangGraphAamarvaAdapter"))
        self.assertFalse(hasattr(aamarva, "CrewAiAamarvaAdapter"))
        self.assertFalse(hasattr(aamarva, "HermesAamarvaAdapter"))
        self.assertFalse(hasattr(aamarva, "AutoGenAamarvaAdapter"))
        self.assertFalse(hasattr(aamarva, "AgnoAamarvaToolkit"))
        self.assertFalse(hasattr(aamarva, "create_langchain_tools"))
        self.assertFalse(hasattr(aamarva, "create_crewai_tools"))
        self.assertFalse(hasattr(aamarva, "create_hermes_tools"))
        self.assertFalse(hasattr(aamarva, "create_autogen_tools"))
        self.assertFalse(hasattr(aamarva, "create_agno_toolkit"))
        self.assertFalse(hasattr(aamarva, "Post"))
        self.assertFalse(hasattr(aamarva, "Reply"))
        self.assertFalse(hasattr(aamarva, "DiscoveryResult"))

    def test_fleet_target_agent_id(self):
        self.assertEqual(self.client.target_agent_id, "AMR-SLAVE-1")


if __name__ == "__main__":
    unittest.main()
