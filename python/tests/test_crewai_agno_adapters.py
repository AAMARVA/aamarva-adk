"""
Unit and Integration Tests for CrewAI and Agno Adapters in AAMARVA ADK (Python)
"""

import unittest
from unittest.mock import MagicMock
import json
import asyncio

from aamarva import Aamarva
from aamarva.errors import AamarvaError
from aamarva.integrations.crewai import (
    AamarvaFloorTool,
    AamarvaMessagingTool,
    AamarvaClusterTool,
    AamarvaWatchtowerTool,
    get_crewai_tools,
    HAS_CREWAI,
)
from aamarva.integrations.agno import (
    AamarvaAgnoToolkit,
    AamarvaToolkit,
    get_agno_tools,
    HAS_AGNO,
)


class TestCrewAiAdapter(unittest.TestCase):
    def setUp(self):
        self.client = Aamarva(agent_id="AMR-TEST-CREWAI", api_key="sk_py_test_123")
        self.client.http.request = MagicMock()

    def test_crewai_missing_dependency_raises_import_error(self):
        if not HAS_CREWAI:
            with self.assertRaises(ImportError) as ctx:
                get_crewai_tools(self.client)
            self.assertIn("CrewAI", str(ctx.exception))

    @unittest.skipUnless(HAS_CREWAI, "CrewAI optional package not installed in current environment")
    def test_crewai_tools_initialization_and_schemas(self):
        tools = get_crewai_tools(self.client)
        self.assertEqual(len(tools), 4)

        floor_tool = tools[0]
        self.assertEqual(floor_tool.name, "aamarva_floor")

        msg_tool = tools[1]
        self.assertEqual(msg_tool.name, "aamarva_messaging")

        cluster_tool = tools[2]
        self.assertEqual(cluster_tool.name, "aamarva_cluster")

        wt_tool = tools[3]
        self.assertEqual(wt_tool.name, "aamarva_watchtower")

    @unittest.skipUnless(HAS_CREWAI, "CrewAI optional package not installed in current environment")
    def test_crewai_floor_tool_sync_and_async_run(self):
        floor_tool = AamarvaFloorTool(client=self.client)

        # 1. Action: list
        self.client.http.request.return_value = {"data": [{"id": "tool_sec_edgar", "name": "SEC Edgar"}]}
        res_list = floor_tool._run(action="list")
        self.assertIn("tool_sec_edgar", res_list)

        # Async run
        res_list_async = asyncio.run(floor_tool._arun(action="list"))
        self.assertIn("tool_sec_edgar", res_list_async)

        # 2. Action: request_access
        self.client.http.request.return_value = {"status": "pending", "requestId": "req_123"}
        res_req = floor_tool._run(action="request_access", tool_id="tool_sec_edgar", reason="Audit")
        self.assertIn("req_123", res_req)

        # 3. Action: check_status
        self.client.http.request.return_value = {"status": "approved", "requestId": "req_123"}
        res_stat = floor_tool._run(action="check_status", request_id="req_123")
        self.assertIn("approved", res_stat)

        # 4. Invalid arguments
        res_err = floor_tool._run(action="request_access")
        self.assertIn("Error: [INVALID_ARGUMENT]", res_err)

    @unittest.skipUnless(HAS_CREWAI, "CrewAI optional package not installed in current environment")
    def test_crewai_floor_permission_denied_handling(self):
        floor_tool = AamarvaFloorTool(client=self.client)
        self.client.http.request.side_effect = AamarvaError(
            "Access denied for tool tool_admin", code="FLOOR_ACCESS_DENIED"
        )
        res = floor_tool._run(action="execute", tool_id="tool_admin", arguments={})
        self.assertIn("Error: [FLOOR_ACCESS_DENIED]", res)

    @unittest.skipUnless(HAS_CREWAI, "CrewAI optional package not installed in current environment")
    def test_crewai_messaging_and_cluster_tools(self):
        msg_tool = AamarvaMessagingTool(client=self.client)

        # Messaging invalid arguments
        res_err = msg_tool._run(action="send")
        self.assertIn("Error: [INVALID_ARGUMENT]", res_err)

        cluster_tool = AamarvaClusterTool(client=self.client)
        self.client.http.request.return_value = {"data": [{"id": "clu_1"}]}
        res_clusters = cluster_tool._run(action="list")
        self.assertIn("clu_1", res_clusters)

    @unittest.skipUnless(HAS_CREWAI, "CrewAI optional package not installed in current environment")
    def test_crewai_watchtower_tool(self):
        wt_tool = AamarvaWatchtowerTool(client=self.client)
        self.client.http.request.return_value = {"data": [{"id": "evt_1", "action": "LOGIN"}]}
        res_wt = wt_tool._run(limit=5)
        self.assertIn("evt_1", res_wt)


class TestAgnoAdapter(unittest.TestCase):
    def setUp(self):
        self.client = Aamarva(agent_id="AMR-TEST-AGNO", api_key="sk_py_test_123")
        self.client.http.request = MagicMock()

    def test_agno_missing_dependency_raises_import_error(self):
        if not HAS_AGNO:
            with self.assertRaises(ImportError) as ctx:
                AamarvaAgnoToolkit(client=self.client)
            self.assertIn("Agno", str(ctx.exception))

    def test_agno_toolkit_alias(self):
        self.assertEqual(AamarvaAgnoToolkit, AamarvaToolkit)

    @unittest.skipUnless(HAS_AGNO, "Agno optional package not installed in current environment")
    def test_agno_toolkit_initialization(self):
        toolkit = AamarvaAgnoToolkit(client=self.client)
        self.assertIsNotNone(toolkit)

        tools_list = get_agno_tools(self.client)
        self.assertTrue(isinstance(tools_list, list))

    @unittest.skipUnless(HAS_AGNO, "Agno optional package not installed in current environment")
    def test_agno_floor_tool_methods(self):
        toolkit = AamarvaAgnoToolkit(client=self.client)

        # 1. FLOOR list tools
        self.client.http.request.return_value = {"data": [{"id": "tool_1"}]}
        res_list = toolkit.aamarva_floor_list_tools()
        self.assertIn("tool_1", res_list)

        # 2. FLOOR request access
        self.client.http.request.return_value = {"status": "pending", "requestId": "req_agno_1"}
        res_req = toolkit.aamarva_floor_request_access("tool_1", "Audit reason")
        self.assertIn("req_agno_1", res_req)

        # 3. FLOOR check status
        self.client.http.request.return_value = {"status": "approved", "requestId": "req_agno_1"}
        res_stat = toolkit.aamarva_floor_check_status("req_agno_1")
        self.assertIn("approved", res_stat)

    @unittest.skipUnless(HAS_AGNO, "Agno optional package not installed in current environment")
    def test_agno_permission_denial_handling(self):
        toolkit = AamarvaAgnoToolkit(client=self.client)
        self.client.http.request.side_effect = AamarvaError(
            "Agent AMR-TEST-AGNO does not have access to tool_restricted", code="FLOOR_ACCESS_DENIED"
        )
        res_err = toolkit.aamarva_floor_execute_tool("tool_restricted", {})
        err_dict = json.loads(res_err)
        self.assertEqual(err_dict["code"], "FLOOR_ACCESS_DENIED")
        self.assertIn("does not have access", err_dict["error"])

    @unittest.skipUnless(HAS_AGNO, "Agno optional package not installed in current environment")
    def test_agno_messaging_and_watchtower(self):
        toolkit = AamarvaAgnoToolkit(client=self.client)

        self.client.http.request.return_value = {"data": [{"id": "evt_agno", "type": "AUTH"}]}
        res_wt = toolkit.aamarva_watchtower_activity(limit=10)
        self.assertIn("evt_agno", res_wt)


if __name__ == "__main__":
    unittest.main()
