"""
CrewAI Integration for AAMARVA ADK (Python)

Provides CrewAI BaseTool implementations for AAMARVA FLOOR governance,
E2EE sovereign messaging, and fleet telemetry.
"""

import json
from typing import Optional, Dict, Any, List

try:
    from crewai.tools import BaseTool as CrewAIBaseTool
except ImportError:
    class CrewAIBaseTool:
        def __init__(self, name: Optional[str] = None, description: Optional[str] = None):
            if name is not None:
                self.name = name
            elif not hasattr(self, "name"):
                self.name = ""
            if description is not None:
                self.description = description
            elif not hasattr(self, "description"):
                self.description = ""

        def run(self, *args, **kwargs) -> str:
            return self._run(*args, **kwargs)

        def _run(self, *args, **kwargs) -> str:
            raise NotImplementedError


class AamarvaFloorTool(CrewAIBaseTool):
    """
    CrewAI Tool for discovering, requesting access, and executing FLOOR tools.
    """
    name: str = "aamarva_floor"
    description: str = (
        "Interact with AAMARVA FLOOR tools. Actions: 'list', 'request_access', 'check_status', 'execute'. "
        "Arguments: action, tool_id (optional), reason (optional), request_id (optional), args (optional)."
    )

    def __init__(self, client: Optional[Any] = None, **kwargs):
        super().__init__(**kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

    def _run(
        self,
        action: str = "list",
        tool_id: Optional[str] = None,
        reason: Optional[str] = None,
        request_id: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> str:
        try:
            if action == "list":
                res = self.client.get_floor_tools()
            elif action == "request_access":
                if not tool_id:
                    return json.dumps({"error": "tool_id required for request_access"})
                res = self.client.request_floor_access(tool_id, reason)
            elif action == "check_status":
                if not request_id:
                    return json.dumps({"error": "request_id required for check_status"})
                res = self.client.get_floor_request_status(request_id)
            elif action == "execute":
                if not tool_id:
                    return json.dumps({"error": "tool_id required for execute"})
                res = self.client.execute_floor_tool(tool_id, args or {})
            else:
                return json.dumps({"error": f"Unknown floor action: {action}"})

            return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        except Exception as e:
            return json.dumps({"error": str(e)})


class AamarvaMessagingTool(CrewAIBaseTool):
    """
    CrewAI Tool for sending and receiving E2EE peer messages.
    """
    name: str = "aamarva_messaging"
    description: str = (
        "Send and receive private encrypted messages across authorized AAMARVA agent connections. "
        "Actions: 'send' (requires connection_id, content), 'get' (requires connection_id)."
    )

    def __init__(self, client: Optional[Any] = None, **kwargs):
        super().__init__(**kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

    def _run(
        self,
        action: str = "get",
        connection_id: Optional[str] = None,
        content: Optional[str] = None,
        **kwargs,
    ) -> str:
        if not connection_id:
            return json.dumps({"error": "connection_id is required"})

        try:
            if action == "send":
                if not content:
                    return json.dumps({"error": "content is required for send action"})
                res = self.client.send_message(connection_id, content)
            elif action == "get":
                res = self.client.get_messages(connection_id)
            else:
                return json.dumps({"error": f"Unknown messaging action: {action}"})

            return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        except Exception as e:
            return json.dumps({"error": str(e)})


class AamarvaClusterTool(CrewAIBaseTool):
    """
    CrewAI Tool for multi-agent cluster communications.
    """
    name: str = "aamarva_cluster"
    description: str = (
        "Interact with AAMARVA multi-agent clusters. "
        "Actions: 'list', 'send' (requires cluster_id, ciphertext, nonce, optional recipients)."
    )

    def __init__(self, client: Optional[Any] = None, **kwargs):
        super().__init__(**kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

    def _run(
        self,
        action: str = "list",
        cluster_id: Optional[str] = None,
        ciphertext: Optional[str] = None,
        nonce: Optional[str] = None,
        recipients: Optional[List[str]] = None,
        **kwargs,
    ) -> str:
        try:
            if action == "list":
                res = self.client.get_clusters()
            elif action == "send":
                if not cluster_id or not ciphertext or not nonce:
                    return json.dumps({"error": "cluster_id, ciphertext, and nonce required for send action"})
                res = self.client.send_cluster_message(cluster_id, ciphertext, nonce, recipients=recipients)
            else:
                return json.dumps({"error": f"Unknown cluster action: {action}"})

            return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        except Exception as e:
            return json.dumps({"error": str(e)})


class AamarvaWatchtowerTool(CrewAIBaseTool):
    """
    CrewAI Tool for fleet security monitoring and telemetry.
    """
    name: str = "aamarva_watchtower"
    description: str = "Retrieve recent fleet activity events and telemetry snapshot from Watchtower."

    def __init__(self, client: Optional[Any] = None, **kwargs):
        super().__init__(**kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

    def _run(self, limit: Optional[int] = 10, **kwargs) -> str:
        try:
            res = self.client.get_watchtower_activity(limit=limit)
            return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        except Exception as e:
            return json.dumps({"error": str(e)})


def get_crewai_tools(client: Optional[Any] = None) -> List[CrewAIBaseTool]:
    if client is None:
        from ..client import Aamarva
        client = Aamarva()

    return [
        AamarvaFloorTool(client=client),
        AamarvaMessagingTool(client=client),
        AamarvaClusterTool(client=client),
        AamarvaWatchtowerTool(client=client),
    ]
