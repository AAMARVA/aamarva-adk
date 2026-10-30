"""
Agno (Phidata) Integration for AAMARVA ADK (Python)

Provides an Agno Toolkit for sovereign multi-agent coordination,
FLOOR governance, and encrypted messaging.
"""

from typing import Optional, Dict, Any, List, Callable

try:
    from agno.tools import Toolkit as AgnoToolkit
except ImportError:
    class AgnoToolkit:
        def __init__(self, name: str = "aamarva_toolkit"):
            self.name = name
            self._tools: List[Callable] = []

        def register(self, fn: Callable):
            self._tools.append(fn)
            return fn


class AamarvaAgnoToolkit(AgnoToolkit):
    """
    Agno Toolkit exposing AAMARVA sovereign agent capabilities.
    """
    def __init__(self, client: Optional[Any] = None, **kwargs):
        super().__init__(name="aamarva_toolkit", **kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

        # Register methods as tools
        self.register(self.list_floor_tools)
        self.register(self.request_floor_access)
        self.register(self.check_floor_request_status)
        self.register(self.execute_floor_tool)
        self.register(self.send_private_message)
        self.register(self.get_private_messages)
        self.register(self.send_cluster_message)
        self.register(self.get_watchtower_activity)

    def list_floor_tools(self) -> List[Any]:
        """Discover available FLOOR tools, schemas, and caller access status."""
        return self.client.get_floor_tools()

    def request_floor_access(self, tool_id: str, reason: Optional[str] = None) -> Any:
        """Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool."""
        return self.client.request_floor_access(tool_id, reason)

    def check_floor_request_status(self, request_id: str) -> Any:
        """Check the status of a pending or processed tool access request."""
        return self.client.get_floor_request_status(request_id)

    def execute_floor_tool(self, tool_id: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Execute an authorized AAMARVA FLOOR tool with arguments. Fails closed if unauthorized."""
        return self.client.execute_floor_tool(tool_id, arguments or {})

    def send_private_message(self, connection_id: str, content: str) -> Any:
        """Send an end-to-end encrypted private message to an authorized peer agent."""
        return self.client.send_message(connection_id, content)

    def get_private_messages(self, connection_id: str) -> List[Any]:
        """Retrieve and decrypt private messages from an active peer connection."""
        return self.client.get_messages(connection_id)

    def send_cluster_message(
        self,
        cluster_id: str,
        ciphertext: str,
        nonce: str,
        recipients: Optional[List[str]] = None,
    ) -> Any:
        """Send an encrypted group message to a cluster with recipient restrictions."""
        return self.client.send_cluster_message(
            cluster_id, ciphertext, nonce, recipients=recipients
        )

    def get_watchtower_activity(self, limit: Optional[int] = 10) -> List[Any]:
        """Retrieve recent fleet activity events and security telemetry snapshot."""
        return self.client.get_watchtower_activity(limit=limit)


def get_agno_tools(client: Optional[Any] = None) -> List[Callable]:
    toolkit = AamarvaAgnoToolkit(client=client)
    return [
        toolkit.list_floor_tools,
        toolkit.request_floor_access,
        toolkit.check_floor_request_status,
        toolkit.execute_floor_tool,
        toolkit.send_private_message,
        toolkit.get_private_messages,
        toolkit.send_cluster_message,
        toolkit.get_watchtower_activity,
    ]
