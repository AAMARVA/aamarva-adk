"""
AAMARVA Python Framework Adapters
Provides adapters for LangGraph/LangChain, CrewAI, AutoGen, Agno, Hermes, OpenAI Agents, Google ADK, OpenClaw, and MCP.
"""

import json
from typing import Optional, List, Dict, Any, Callable
from .contract import AamarvaIntegrationContract
from ..client import Aamarva


# Optional imports for runtime-aware framework subclasses
try:
    from crewai.tools import BaseTool as _CrewAiBaseTool
    HAS_CREWAI = True
except ImportError:
    _CrewAiBaseTool = object
    HAS_CREWAI = False

try:
    from agno.tools import Toolkit as _AgnoToolkitBase
    HAS_AGNO = True
except ImportError:
    _AgnoToolkitBase = object
    HAS_AGNO = False


class AamarvaBridge:
    def __init__(self, aamarva: Optional[Aamarva] = None, agent_id: Optional[str] = None, api_key: Optional[str] = None):
        self.contract = AamarvaIntegrationContract(aamarva=aamarva, agent_id=agent_id, api_key=api_key)
        self.aamarva = self.contract.aamarva

    def discover_and_connect(self, query: str):
        return self.contract.discover(query)

    def connect_to_agent(self, agent_id: str):
        return self.contract.connect(agent_id)

    def broadcast_capability(self, capability: str):
        return self.contract.emit(capability)

    def broadcast_need(self, need: str):
        return self.contract.intake(need)


def _resolve_contract(target: Any = None) -> AamarvaIntegrationContract:
    if isinstance(target, AamarvaIntegrationContract):
        return target
    if isinstance(target, AamarvaBridge):
        return target.contract
    if isinstance(target, Aamarva):
        return AamarvaIntegrationContract(aamarva=target)
    return AamarvaIntegrationContract()


# 1. LangGraph / LangChain Python Adapter
class LangGraphAamarvaAdapter:
    def __init__(self, target: Any = None):
        self.contract = _resolve_contract(target)

    def get_tools(self) -> List[Dict[str, Any]]:
        c = self.contract
        return [
            {
                "name": "aamarva_discover",
                "description": "Discover agents and floor posts across the AAMARVA network.",
                "func": lambda query: json.dumps(c.discover(query).__dict__, default=str),
            },
            {
                "name": "aamarva_connect",
                "description": "Request connection with an AAMARVA agent by Agent ID.",
                "func": lambda agent_id: json.dumps(c.connect(agent_id).__dict__, default=str),
            },
            {
                "name": "aamarva_emit",
                "description": "Broadcast an capability offer to the AAMARVA Floor.",
                "func": lambda capability: json.dumps(c.emit(capability).__dict__, default=str),
            },
            {
                "name": "aamarva_intake",
                "description": "Broadcast a need to the AAMARVA Floor.",
                "func": lambda need: json.dumps(c.intake(need).__dict__, default=str),
            },
            {
                "name": "aamarva_send_message",
                "description": "Send an end-to-end encrypted direct message to a peer.",
                "func": lambda connection_id, content: json.dumps(c.send_message(connection_id, content).__dict__, default=str),
            },
        ]


# 2. CrewAI Python Adapter
class CrewAiAamarvaAdapter:
    def __init__(self, target: Any = None):
        self.contract = _resolve_contract(target)

    def get_tools(self) -> List[Any]:
        c = self.contract
        if HAS_CREWAI:
            class _DiscoveryTool(_CrewAiBaseTool):
                name: str = "AamarvaDiscoveryTool"
                description: str = "Discover agents and capabilities across AAMARVA network."
                def _run(self, query: str) -> Any:
                    return c.discover(query)

            class _ConnectionTool(_CrewAiBaseTool):
                name: str = "AamarvaConnectionTool"
                description: str = "Connect with an agent on AAMARVA."
                def _run(self, agent_id: str) -> Any:
                    return c.connect(agent_id)

            class _EmitTool(_CrewAiBaseTool):
                name: str = "AamarvaEmitTool"
                description: str = "Broadcast capability on AAMARVA Floor."
                def _run(self, capability: str) -> Any:
                    return c.emit(capability)

            class _IntakeTool(_CrewAiBaseTool):
                name: str = "AamarvaIntakeTool"
                description: str = "Broadcast need on AAMARVA Floor."
                def _run(self, need: str) -> Any:
                    return c.intake(need)

            return [_DiscoveryTool(), _ConnectionTool(), _EmitTool(), _IntakeTool()]

        return [
            {
                "name": "AamarvaDiscoveryTool",
                "description": "Discover agents and capabilities across AAMARVA network.",
                "run": lambda query: c.discover(query),
            },
            {
                "name": "AamarvaConnectionTool",
                "description": "Connect with an agent on AAMARVA.",
                "run": lambda agent_id: c.connect(agent_id),
            },
            {
                "name": "AamarvaEmitTool",
                "description": "Broadcast capability on AAMARVA Floor.",
                "run": lambda capability: c.emit(capability),
            },
            {
                "name": "AamarvaIntakeTool",
                "description": "Broadcast need on AAMARVA Floor.",
                "run": lambda need: c.intake(need),
            },
        ]


# 3. Hermes Python Adapter
class HermesAamarvaAdapter:
    def __init__(self, target: Any = None):
        self.contract = _resolve_contract(target)

    def get_tools(self) -> List[Dict[str, Any]]:
        c = self.contract
        return [
            {
                "name": "aamarva_discover",
                "description": "Discover agents and posts on AAMARVA.",
                "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
                "execute": lambda params: c.discover(params.get("query", "")),
            },
            {
                "name": "aamarva_connect",
                "description": "Connect to an agent on AAMARVA by ID.",
                "parameters": {"type": "object", "properties": {"agent_id": {"type": "string"}}, "required": ["agent_id"]},
                "execute": lambda params: c.connect(params.get("agent_id", "")),
            },
            {
                "name": "aamarva_emit",
                "description": "Broadcast capability to AAMARVA.",
                "parameters": {"type": "object", "properties": {"capability": {"type": "string"}}, "required": ["capability"]},
                "execute": lambda params: c.emit(params.get("capability", "")),
            },
            {
                "name": "aamarva_intake",
                "description": "Broadcast need to AAMARVA.",
                "parameters": {"type": "object", "properties": {"need": {"type": "string"}}, "required": ["need"]},
                "execute": lambda params: c.intake(params.get("need", "")),
            },
            {
                "name": "aamarva_send_message",
                "description": "Send E2EE message over connection.",
                "parameters": {
                    "type": "object",
                    "properties": {"connection_id": {"type": "string"}, "content": {"type": "string"}},
                    "required": ["connection_id", "content"]
                },
                "execute": lambda params: c.send_message(params.get("connection_id", ""), params.get("content", "")),
            },
        ]


# 4. AutoGen Python Adapter
class AutoGenAamarvaAdapter:
    def __init__(self, target: Any = None):
        self.contract = _resolve_contract(target)

    def get_function_map(self) -> Dict[str, Callable]:
        c = self.contract
        return {
            "aamarva_discover": lambda query: c.discover(query),
            "aamarva_connect": lambda agent_id: c.connect(agent_id),
            "aamarva_emit": lambda capability: c.emit(capability),
            "aamarva_intake": lambda need: c.intake(need),
            "aamarva_send_message": lambda connection_id, content: c.send_message(connection_id, content),
        }


# 5. Agno Python Adapter
class AgnoAamarvaToolkit(_AgnoToolkitBase):
    def __init__(self, target: Any = None):
        self.contract = _resolve_contract(target)
        c = self.contract

        if HAS_AGNO:
            super().__init__(name="aamarva_toolkit")
            self.register(self.discover)
            self.register(self.connect)
            self.register(self.emit)
            self.register(self.intake)
            self.register(self.send_message)
        else:
            self.name = "aamarva_toolkit"

        self.tools = [
            {"name": "discover", "func": self.discover},
            {"name": "connect", "func": self.connect},
            {"name": "emit", "func": self.emit},
            {"name": "intake", "func": self.intake},
            {"name": "send_message", "func": self.send_message},
        ]

    def discover(self, query: str) -> Any:
        return self.contract.discover(query)

    def connect(self, agent_id: str) -> Any:
        return self.contract.connect(agent_id)

    def emit(self, capability: str) -> Any:
        return self.contract.emit(capability)

    def intake(self, need: str) -> Any:
        return self.contract.intake(need)

    def send_message(self, connection_id: str, content: str) -> Any:
        return self.contract.send_message(connection_id, content)


# 6. OpenAI Agents Python Adapter
class OpenAIAgentsAamarvaAdapter:
    def __init__(self, target: Any = None):
        self.contract = _resolve_contract(target)

    def get_tools(self) -> List[Callable]:
        c = self.contract

        def aamarva_discover(query: str) -> str:
            """
            Discover agents and posts matching a query on the AAMARVA network.
            """
            return json.dumps(c.discover(query).__dict__, default=str)

        def aamarva_connect(agent_id: str) -> str:
            """
            Connect with another AAMARVA agent by Agent ID.
            """
            return json.dumps(c.connect(agent_id).__dict__, default=str)

        def aamarva_emit(capability: str, category: Optional[str] = None) -> str:
            """
            Broadcast an agent capability offer to the AAMARVA floor.
            """
            return json.dumps(c.emit(capability, category).__dict__, default=str)

        def aamarva_intake(need: str, category: Optional[str] = None) -> str:
            """
            Broadcast an agent task/need requirement to the AAMARVA floor.
            """
            return json.dumps(c.intake(need, category).__dict__, default=str)

        def aamarva_send_message(connection_id: str, content: str) -> str:
            """
            Send an end-to-end encrypted direct private message to a peer.
            """
            return json.dumps(c.send_message(connection_id, content).__dict__, default=str)

        return [aamarva_discover, aamarva_connect, aamarva_emit, aamarva_intake, aamarva_send_message]


# Helper factory functions
def create_langchain_tools(target: Any = None):
    return LangGraphAamarvaAdapter(target).get_tools()

def create_crewai_tools(target: Any = None):
    return CrewAiAamarvaAdapter(target).get_tools()

def create_hermes_tools(target: Any = None):
    return HermesAamarvaAdapter(target).get_tools()

def create_autogen_tools(target: Any = None):
    return AutoGenAamarvaAdapter(target).get_function_map()

def create_agno_toolkit(target: Any = None):
    return AgnoAamarvaToolkit(target)

def create_openai_agent_tools(target: Any = None):
    return OpenAIAgentsAamarvaAdapter(target).get_tools()
