"""
CrewAI Integration for AAMARVA ADK (Python)

Provides genuine CrewAI BaseTool implementations for AAMARVA FLOOR governance,
E2EE sovereign messaging, multi-agent clusters, and fleet telemetry.
"""

from typing import Optional, List, Any, Type
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
    action: str = Field(..., description="Action: 'list', 'request_access', 'check_status', 'execute'.") if HAS_PYDANTIC else None
    tool_id: Optional[str] = Field(None, description="Identifier of the FLOOR tool.") if HAS_PYDANTIC else None
    reason: Optional[str] = Field(None, description="Justification for access request.") if HAS_PYDANTIC else None
    request_id: Optional[str] = Field(None, description="The tool access request ID.") if HAS_PYDANTIC else None
    arguments: Optional[dict] = Field(None, description="Arguments for tool execution.") if HAS_PYDANTIC else None


class AamarvaFloorTool(BaseTool):
    name: str = "aamarva_floor"
    description: str = "Interact with AAMARVA FLOOR tools for discovery, access requests, and execution."
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
        import json
        action = kwargs.get("action", "list")
        try:
            if action == "list":
                res = self.client.get_floor_tools()
            elif action == "request_access":
                res = self.client.request_floor_access(kwargs.get("tool_id"), kwargs.get("reason"))
            elif action == "check_status":
                res = self.client.get_floor_request_status(kwargs.get("request_id"))
            elif action == "execute":
                res = self.client.execute_floor_tool(kwargs.get("tool_id"), kwargs.get("arguments") or {})
            else:
                return f"Error: Unknown action {action}"
            return json.dumps(res, default=str) if isinstance(res, (dict, list)) else str(res)
        except Exception as e:
            return f"Error: {str(e)}"


class MessagingInput(BaseModel if HAS_PYDANTIC else object):
    action: str = Field(..., description="Action: 'send' or 'get'.") if HAS_PYDANTIC else None
    connection_id: str = Field(..., description="Active connection channel ID.") if HAS_PYDANTIC else None
    content: Optional[str] = Field(None, description="Message content for 'send' action.") if HAS_PYDANTIC else None


class AamarvaMessagingTool(BaseTool):
    name: str = "aamarva_messaging"
    description: str = "Send and receive private encrypted messages across AAMARVA connections."
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
        import json
        action = kwargs.get("action")
        conn_id = kwargs.get("connection_id")
        try:
            if action == "send":
                res = self.client.send_message(conn_id, kwargs.get("content"))
            elif action == "get":
                res = self.client.get_messages(conn_id)
            else:
                return f"Error: Unknown action {action}"
            return json.dumps(res, default=str)
        except Exception as e:
            return f"Error: {str(e)}"


class ClusterInput(BaseModel if HAS_PYDANTIC else object):
    action: str = Field(..., description="Action: 'list' or 'send'.") if HAS_PYDANTIC else None
    cluster_id: Optional[str] = Field(None, description="Cluster ID.") if HAS_PYDANTIC else None
    ciphertext: Optional[str] = Field(None, description="Encrypted payload.") if HAS_PYDANTIC else None
    nonce: Optional[str] = Field(None, description="Cryptographic nonce.") if HAS_PYDANTIC else None
    recipients: Optional[List[str]] = Field(None, description="Recipient agent IDs.") if HAS_PYDANTIC else None


class AamarvaClusterTool(BaseTool):
    name: str = "aamarva_cluster"
    description: str = "Interact with multi-agent clusters and send recipient-restricted messages."
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
        import json
        action = kwargs.get("action", "list")
        try:
            if action == "list":
                res = self.client.get_clusters()
            elif action == "send":
                res = self.client.send_cluster_message(
                    kwargs.get("cluster_id"),
                    kwargs.get("ciphertext"),
                    kwargs.get("nonce"),
                    recipients=kwargs.get("recipients"),
                )
            else:
                return f"Error: Unknown action {action}"
            return json.dumps(res, default=str)
        except Exception as e:
            return f"Error: {str(e)}"


class WatchtowerInput(BaseModel if HAS_PYDANTIC else object):
    limit: Optional[int] = Field(10, description="Maximum number of events.") if HAS_PYDANTIC else None


class AamarvaWatchtowerTool(BaseTool):
    name: str = "aamarva_watchtower"
    description: str = "Retrieve recent fleet audit activity and security telemetry snapshot."
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
        import json
        try:
            res = self.client.get_watchtower_activity(limit)
            return json.dumps(res, default=str)
        except Exception as e:
            return f"Error: {str(e)}"


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
