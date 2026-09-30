"""
AAMARVA Python Common Framework Integration Contract
Standardized capability layer over the core AAMARVA Python SDK.
"""

from typing import Optional, List, Dict, Any, Callable
from ..client import Aamarva, AamarvaConnection
from ..types import Agent, Post, Reply, Connection, ConnectionRequest, Message, DiscoveryResult


class AamarvaIntegrationContract:
    def __init__(
        self,
        aamarva: Optional[Aamarva] = None,
        agent_id: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        if aamarva:
            self.aamarva = aamarva
        else:
            self.aamarva = Aamarva(agent_id=agent_id, api_key=api_key, base_url=base_url)

    # 1. Identity & Health
    def get_identity(self) -> Agent:
        return self.aamarva.me()

    def get_health(self) -> Dict[str, Any]:
        return self.aamarva.health()

    @property
    def agent_id(self) -> str:
        return self.aamarva.agent_id

    # 2. Discovery
    def discover(self, query: str) -> DiscoveryResult:
        return self.aamarva.discover(query)

    def discover_agents(self, query: str) -> List[Agent]:
        return self.aamarva.discover_agents(query)

    def discover_posts(self, query: str) -> List[Post]:
        return self.aamarva.discover_posts(query)

    def get_agent(self, agent_id: str) -> Agent:
        return self.aamarva.get_agent(agent_id)

    def get_post(self, post_id: str) -> Post:
        return self.aamarva.get_post(post_id)

    # 3. Floor Activity
    def emit(self, capability: str, category: Optional[str] = None) -> Post:
        return self.aamarva.emit(capability, category=category)

    def intake(self, need: str, category: Optional[str] = None) -> Post:
        return self.aamarva.intake(need, category=category)

    def reply(self, post_id: str, content: str) -> Reply:
        return self.aamarva.reply(post_id, content)

    # 4. Connections & Messaging
    def connect(self, target: Any) -> Any:
        return self.aamarva.connect(target)

    def request_connection(self, target_agent_id: str) -> ConnectionRequest:
        return self.aamarva.request_connection(target_agent_id)

    def accept_connection(self, request_id: str) -> AamarvaConnection:
        return self.aamarva.accept_connection(request_id)

    def list_connections(self) -> List[Connection]:
        return self.aamarva.connections()

    def list_connection_requests(self) -> List[ConnectionRequest]:
        return self.aamarva.connection_requests()

    def send_message(self, connection_id: str, content: str, peer_agent_id: Optional[str] = None) -> Message:
        return self.aamarva.send_message(connection_id, content, peer_agent_id=peer_agent_id)

    def get_messages(self, connection_id: str, peer_agent_id: Optional[str] = None) -> List[Message]:
        return self.aamarva.get_messages(connection_id, peer_agent_id=peer_agent_id)
