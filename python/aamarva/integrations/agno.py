"""
Agno Integration for AAMARVA ADK (Python)

Provides a genuine Agno Toolkit for sovereign multi-agent coordination,
FLOOR governance, and encrypted messaging.
"""

import json
from typing import Optional, List, Any, Dict

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
        try:
            res = self.client.get_floor_tools()
            return json.dumps(res, default=str)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return json.dumps({"error": str(e), "code": code})

    def aamarva_floor_request_access(self, tool_id: str, reason: Optional[str] = None) -> str:
        """Request human-in-the-loop approval for an AAMARVA FLOOR tool."""
        try:
            res = self.client.request_floor_access(tool_id, reason)
            return json.dumps(res, default=str)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return json.dumps({"error": str(e), "code": code})

    def aamarva_floor_check_status(self, request_id: str) -> str:
        """Check status of a pending FLOOR access request."""
        try:
            res = self.client.get_floor_request_status(request_id)
            return json.dumps(res, default=str)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return json.dumps({"error": str(e), "code": code})

    def aamarva_floor_execute_tool(self, tool_id: str, arguments: Optional[Dict[str, Any]] = None) -> str:
        """Execute an authorized AAMARVA FLOOR tool with input arguments."""
        try:
            res = self.client.execute_floor_tool(tool_id, arguments or {})
            return json.dumps(res, default=str)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return json.dumps({"error": str(e), "code": code})

    def aamarva_send_message(self, connection_id: str, content: str) -> str:
        """Send an end-to-end encrypted private message to a peer agent."""
        try:
            res = self.client.send_message(connection_id, content)
            return json.dumps(res, default=str)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return json.dumps({"error": str(e), "code": code})

    def aamarva_get_messages(self, connection_id: str) -> str:
        """Retrieve and decrypt private messages from a peer connection."""
        try:
            res = self.client.get_messages(connection_id)
            return json.dumps(res, default=str)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return json.dumps({"error": str(e), "code": code})

    def aamarva_cluster_send_message(
        self,
        cluster_id: str,
        plaintext: Optional[str] = None,
        ciphertext: Optional[str] = None,
        nonce: Optional[str] = None,
        recipients: Optional[List[str]] = None,
    ) -> str:
        """Send encrypted message to a multi-agent cluster."""
        try:
            if plaintext:
                res = self.client.send_encrypted_cluster_message(
                    cluster_id, plaintext, recipients=recipients
                )
            else:
                res = self.client.send_cluster_message(
                    cluster_id, ciphertext or "", nonce or "", recipients=recipients
                )
            return json.dumps(res, default=str)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return json.dumps({"error": str(e), "code": code})

    def aamarva_watchtower_activity(self, limit: int = 10) -> str:
        """Retrieve recent fleet security telemetry from Watchtower."""
        try:
            res = self.client.get_watchtower_activity(limit)
            return json.dumps(res, default=str)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return json.dumps({"error": str(e), "code": code})


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
