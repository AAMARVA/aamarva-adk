from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Union

@dataclass
class Agent:
    agentId: str
    name: str
    bio: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None
    avatar: Optional[str] = None
    avatarUrl: Optional[str] = None
    masterId: Optional[str] = None
    slaveIds: Optional[List[str]] = None
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None



@dataclass
class Connection:
    connectionId: str
    agentId: str
    status: str
    createdAt: str
    peerAgentId: Optional[str] = None
    connectedAgentName: Optional[str] = None
    updatedAt: Optional[str] = None

@dataclass
class Message:
    connectionId: str
    senderAgentId: str
    content: Optional[str]
    createdAt: str
    messageId: Optional[str] = None
    senderAgentName: Optional[str] = None
    ciphertext: Optional[str] = None
    nonce: Optional[str] = None
    version: Optional[int] = None
    keyEpoch: Optional[int] = None
    raw: Optional[str] = None

@dataclass
class Cluster:
    name: str
    id: Optional[str] = None
    clusterId: Optional[str] = None
    description: Optional[str] = None
    ownerUserId: Optional[str] = None
    ownerAgentId: Optional[str] = None
    membersCount: Optional[int] = None
    members: Optional[List[str]] = None
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None

@dataclass
class ClusterMessage:
    messageId: str
    clusterId: str
    senderAgentId: str
    ciphertext: str
    nonce: str
    createdAt: str
    version: Optional[int] = None
    keyEpoch: Optional[int] = None
    recipients: Optional[List[str]] = None

@dataclass
class WatchtowerActivity:
    id: str
    type: str
    summary: str
    timestamp: str
    actorAgentId: Optional[str] = None
    targetAgentId: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

@dataclass
class WatchtowerStreamTicket:
    ticket: str
    streamUrl: str
    expiresAt: str

@dataclass
class FloorTool:
    id: str
    name: str
    description: str
    inputSchema: Dict[str, Any]
    accessStatus: str

@dataclass
class FloorToolInvokeResult:
    status: str
    requestId: Optional[str] = None
    invocationId: Optional[str] = None
    result: Optional[Any] = None
    message: Optional[str] = None

@dataclass
class FloorAccessRequestStatus:
    requestId: str
    status: str
    toolId: Optional[str] = None
    agentId: Optional[str] = None
    reason: Optional[str] = None
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None


