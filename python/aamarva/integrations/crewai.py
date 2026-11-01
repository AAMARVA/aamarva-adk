"""
CrewAI Integration for AAMARVA ADK (Python)

Provides genuine CrewAI BaseTool implementations for AAMARVA FLOOR governance,
E2EE sovereign messaging, multi-agent clusters, and fleet telemetry.
"""

import json
import asyncio
from typing import Optional, List, Any, Dict

try:
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    BaseModel = object
    Field = lambda *args, **kwargs: None

try:
    from crewai.tools import BaseTool
    HAS_CREWAI = True
except ImportError:
    HAS_CREWAI = False
    BaseTool = object


class FloorActionInput(BaseModel if HAS_PYDANTIC else object):
    action: str = Field("list", description="Action to perform: 'list', 'request_access', 'check_status', or 'execute'.") if HAS_PYDANTIC else None
    tool_id: Optional[str] = Field(None, description="Identifier of the target FLOOR tool.") if HAS_PYDANTIC else None
    reason: Optional[str] = Field(None, description="Justification reason for requesting tool access.") if HAS_PYDANTIC else None
    request_id: Optional[str] = Field(None, description="Request ID for checking pending access status.") if HAS_PYDANTIC else None
    arguments: Optional[Dict[str, Any]] = Field(None, description="Input arguments object for tool execution.") if HAS_PYDANTIC else None


class AamarvaFloorTool(BaseTool):
    """
    Native CrewAI tool for discovering, requesting access to, and executing governed AAMARVA FLOOR tools.
    """
    name: str = "aamarva_floor"
    description: str = (
        "Interact with AAMARVA FLOOR tools for discovery ('list'), access requests ('request_access'), "
        "status checks ('check_status'), and authorized tool execution ('execute')."
    )
    args_schema: Any = FloorActionInput
    client: Any = None

    def __init__(self, client: Optional[Any] = None, **kwargs):
        if not HAS_CREWAI:
            raise ImportError("CrewAI dependencies not found. Please install 'crewai' via 'pip install aamarva[crewai]'.")
        super().__init__(**kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

    def _run(self, **kwargs) -> str:
        action = kwargs.get("action", "list")
        tool_id = kwargs.get("tool_id")
        reason = kwargs.get("reason")
        request_id = kwargs.get("request_id")
        arguments = kwargs.get("arguments") or {}

        try:
            if action == "list":
                res = self.client.get_floor_tools()
            elif action == "request_access":
                if not tool_id:
                    return "Error: [INVALID_ARGUMENT] tool_id is required for request_access action."
                res = self.client.request_floor_access(tool_id, reason)
            elif action == "check_status":
                if not request_id:
                    return "Error: [INVALID_ARGUMENT] request_id is required for check_status action."
                res = self.client.get_floor_request_status(request_id)
            elif action == "execute":
                if not tool_id:
                    return "Error: [INVALID_ARGUMENT] tool_id is required for execute action."
                res = self.client.execute_floor_tool(tool_id, arguments)
            else:
                return f"Error: [INVALID_ACTION] Unknown action '{action}'."

            return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return f"Error: [{code}] {str(e)}"

    async def _arun(self, **kwargs) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._run(**kwargs))


class MessagingInput(BaseModel if HAS_PYDANTIC else object):
    action: str = Field("send", description="Action: 'send' to transmit encrypted message or 'get' to retrieve transcript.") if HAS_PYDANTIC else None
    connection_id: str = Field(..., description="Active connection channel ID.") if HAS_PYDANTIC else None
    content: Optional[str] = Field(None, description="Message text payload for 'send' action.") if HAS_PYDANTIC else None


class AamarvaMessagingTool(BaseTool):
    """
    Native CrewAI tool for end-to-end encrypted peer messaging across AAMARVA connections.
    """
    name: str = "aamarva_messaging"
    description: str = "Send ('send') and retrieve ('get') end-to-end encrypted private messages across AAMARVA direct connections."
    args_schema: Any = MessagingInput
    client: Any = None

    def __init__(self, client: Optional[Any] = None, **kwargs):
        if not HAS_CREWAI:
            raise ImportError("CrewAI dependencies not found. Please install 'crewai' via 'pip install aamarva[crewai]'.")
        super().__init__(**kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

    def _run(self, **kwargs) -> str:
        action = kwargs.get("action", "send")
        conn_id = kwargs.get("connection_id")
        content = kwargs.get("content")

        if not conn_id:
            return "Error: [INVALID_ARGUMENT] connection_id is required."

        try:
            if action == "send":
                if content is None:
                    return "Error: [INVALID_ARGUMENT] content is required for send action."
                res = self.client.send_message(conn_id, content)
            elif action == "get":
                res = self.client.get_messages(conn_id)
            else:
                return f"Error: [INVALID_ACTION] Unknown action '{action}'."

            return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return f"Error: [{code}] {str(e)}"

    async def _arun(self, **kwargs) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._run(**kwargs))


class ClusterInput(BaseModel if HAS_PYDANTIC else object):
    action: str = Field("list", description="Action: 'list' to query clusters or 'send' to broadcast an encrypted message.") if HAS_PYDANTIC else None
    cluster_id: Optional[str] = Field(None, description="Target cluster ID.") if HAS_PYDANTIC else None
    plaintext: Optional[str] = Field(None, description="Plaintext message payload to encrypt and broadcast to cluster.") if HAS_PYDANTIC else None
    ciphertext: Optional[str] = Field(None, description="Pre-encrypted ciphertext payload.") if HAS_PYDANTIC else None
    nonce: Optional[str] = Field(None, description="Cryptographic initialization vector.") if HAS_PYDANTIC else None
    recipients: Optional[List[str]] = Field(None, description="Array of recipient agent IDs for restriction.") if HAS_PYDANTIC else None


class AamarvaClusterTool(BaseTool):
    """
    Native CrewAI tool for multi-agent cluster operations and recipient-restricted messaging.
    """
    name: str = "aamarva_cluster"
    description: str = "Query clusters ('list') and broadcast recipient-restricted encrypted messages ('send') across AAMARVA clusters."
    args_schema: Any = ClusterInput
    client: Any = None

    def __init__(self, client: Optional[Any] = None, **kwargs):
        if not HAS_CREWAI:
            raise ImportError("CrewAI dependencies not found. Please install 'crewai' via 'pip install aamarva[crewai]'.")
        super().__init__(**kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

    def _run(self, **kwargs) -> str:
        action = kwargs.get("action", "list")
        cluster_id = kwargs.get("cluster_id")

        try:
            if action == "list":
                res = self.client.get_clusters()
            elif action == "send":
                if not cluster_id:
                    return "Error: [INVALID_ARGUMENT] cluster_id is required for send action."
                plaintext = kwargs.get("plaintext")
                if plaintext:
                    res = self.client.send_encrypted_cluster_message(
                        cluster_id,
                        plaintext,
                        recipients=kwargs.get("recipients"),
                    )
                else:
                    res = self.client.send_cluster_message(
                        cluster_id,
                        kwargs.get("ciphertext") or "",
                        kwargs.get("nonce") or "",
                        recipients=kwargs.get("recipients"),
                    )
            else:
                return f"Error: [INVALID_ACTION] Unknown action '{action}'."

            return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return f"Error: [{code}] {str(e)}"

    async def _arun(self, **kwargs) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._run(**kwargs))


class WatchtowerInput(BaseModel if HAS_PYDANTIC else object):
    limit: Optional[int] = Field(10, description="Maximum number of audit events to retrieve.") if HAS_PYDANTIC else None


class AamarvaWatchtowerTool(BaseTool):
    """
    Native CrewAI tool for retrieving Watchtower audit trails and security telemetry.
    """
    name: str = "aamarva_watchtower"
    description: str = "Retrieve recent fleet audit activity logs and security telemetry snapshot from Watchtower."
    args_schema: Any = WatchtowerInput
    client: Any = None

    def __init__(self, client: Optional[Any] = None, **kwargs):
        if not HAS_CREWAI:
            raise ImportError("CrewAI dependencies not found. Please install 'crewai' via 'pip install aamarva[crewai]'.")
        super().__init__(**kwargs)
        if client is None:
            from ..client import Aamarva
            self.client = Aamarva()
        else:
            self.client = client

    def _run(self, limit: int = 10, **kwargs) -> str:
        try:
            res = self.client.get_watchtower_activity(limit)
            return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        except Exception as e:
            code = getattr(e, "code", "EXECUTION_FAILED")
            return f"Error: [{code}] {str(e)}"

    async def _arun(self, limit: int = 10, **kwargs) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._run(limit, **kwargs))


def get_crewai_tools(client: Optional[Any] = None) -> List[Any]:
    """
    Returns an array of genuine CrewAI tools.
    """
    return [
        AamarvaFloorTool(client=client),
        AamarvaMessagingTool(client=client),
        AamarvaClusterTool(client=client),
        AamarvaWatchtowerTool(client=client),
    ]


__all__ = [
    "AamarvaFloorTool",
    "AamarvaMessagingTool",
    "AamarvaClusterTool",
    "AamarvaWatchtowerTool",
    "get_crewai_tools",
]
