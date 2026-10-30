"""
Agno Integration for AAMARVA ADK (Python)

Provides a genuine Agno Toolkit for sovereign multi-agent coordination,
FLOOR governance, and encrypted messaging.
"""

from typing import Optional, List, Any
from .openai import execute_openai_tool_call

try:
    from agno.tools import Toolkit
    HAS_AGNO = True
except ImportError:
    HAS_AGNO = False
    Toolkit = object


class AamarvaAgnoToolkit(Toolkit):
    """
    Genuine Agno Toolkit exposing AAMARVA sovereign fleet capabilities.
    """
    def __init__(self, client: Optional[Any] = None, **kwargs):
        if not HAS_AGNO:
            raise ImportError(
                "Agno dependencies not found. Please install 'agno' via 'pip install aamarva[agno]' to use this integration."
            )
        super().__init__(name="aamarva_toolkit", **kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

        self.register(self.aamarva_floor_list_tools)
        self.register(self.aamarva_floor_request_access)
        self.register(self.aamarva_floor_check_status)
        self.register(self.aamarva_floor_execute_tool)
        self.register(self.aamarva_send_message)
        self.register(self.aamarva_get_messages)
        self.register(self.aamarva_cluster_send_message)
        self.register(self.aamarva_watchtower_activity)

    def aamarva_floor_list_tools(self) -> str:
        """Discover available AAMARVA FLOOR tools and caller access status."""
        import json
        res = self.client.get_floor_tools()
        return json.dumps(res, default=str)

    def aamarva_floor_request_access(self, tool_id: str, reason: Optional[str] = None) -> str:
        """Request human-in-the-loop approval for an AAMARVA tool."""
        import json
        res = self.client.request_floor_access(tool_id, reason)
        return json.dumps(res, default=str)

    def aamarva_floor_check_status(self, request_id: str) -> str:
        """Check status of a pending FLOOR access request."""
        import json
        res = self.client.get_floor_request_status(request_id)
        return json.dumps(res, default=str)

    def aamarva_floor_execute_tool(self, tool_id: str, arguments: dict) -> str:
        """Execute an authorized AAMARVA FLOOR tool with input arguments."""
        import json
        res = self.client.execute_floor_tool(tool_id, arguments)
        return json.dumps(res, default=str)

    def aamarva_send_message(self, connection_id: str, content: str) -> str:
        """Send an end-to-end encrypted private message to a peer agent."""
        import json
        res = self.client.send_message(connection_id, content)
        return json.dumps(res, default=str)

    def aamarva_get_messages(self, connection_id: str) -> str:
        """Retrieve and decrypt private messages from a peer connection."""
        import json
        res = self.client.get_messages(connection_id)
        return json.dumps(res, default=str)

    def aamarva_cluster_send_message(self, cluster_id: str, ciphertext: str, nonce: str, recipients: Optional[List[str]] = None) -> str:
        """Send encrypted message to a multi-agent cluster."""
        import json
        res = self.client.send_cluster_message(cluster_id, ciphertext, nonce, recipients=recipients)
        return json.dumps(res, default=str)

    def aamarva_watchtower_activity(self, limit: int = 10) -> str:
        """Retrieve recent fleet security telemetry from Watchtower."""
        import json
        res = self.client.get_watchtower_activity(limit)
        return json.dumps(res, default=str)


# Alias for backward compatibility
AamarvaToolkit = AamarvaAgnoToolkit


def get_agno_tools(client: Optional[Any] = None) -> List[Any]:
    """
    Returns a list of tools from the AAMARVA Agno Toolkit.
    """
    toolkit = AamarvaAgnoToolkit(client=client)
    return toolkit.get_tools()


__all__ = [
    "AamarvaAgnoToolkit",
    "AamarvaToolkit",
    "get_agno_tools",
]
