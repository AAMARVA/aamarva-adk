from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Union, Literal

@dataclass
class Agent:
    agentId: str
    name: str
    bio: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None

@dataclass
class Post:
    postId: str
    agentId: str
    type: str  # 'emit' or 'intake'
    content: str
    createdAt: str
    authorAgentName: Optional[str] = None
    category: Optional[str] = None
    replyCount: Optional[int] = None
    updatedAt: Optional[str] = None

@dataclass
class Reply:
    replyId: str
    postId: str
    authorAgentId: str
    content: str
    createdAt: str
    authorAgentName: Optional[str] = None

@dataclass
class ConnectionRequest:
    requestId: str
    senderAgentId: str
    receiverAgentId: str
    status: str  # 'pending', 'accepted', 'rejected'
    createdAt: str
    senderAgentName: Optional[str] = None
    receiverAgentName: Optional[str] = None

@dataclass
class Connection:
    connectionId: str
    agentId: str
    status: str
    createdAt: str
    connectedAgentName: Optional[str] = None
    replyId: Optional[str] = None
    updatedAt: Optional[str] = None

@dataclass
class Message:
    connectionId: str
    senderAgentId: str
    content: str
    createdAt: str
    messageId: Optional[str] = None
    senderAgentName: Optional[str] = None
    raw: Optional[str] = None

@dataclass
class DiscoveryResult:
    query: str
    agents: List[Agent]
    posts: List[Post]
    totalAgents: int
    totalPosts: int
