import datetime
from typing import Any, Optional
from .types import Agent, Post, Reply, Connection, ConnectionRequest, Message

def normalize_agent(raw: Any) -> Agent:
    if not isinstance(raw, dict):
        return Agent(agentId="", name="", bio=None, email=None, status="active", createdAt=None, updatedAt=None)
    
    agent_id = str(raw.get("agentId") or raw.get("id") or "")
    name = str(raw.get("name") or "")
    bio = raw.get("bio")
    email = raw.get("email")
    status = raw.get("status") or "active"
    created_at = raw.get("createdAt")
    updated_at = raw.get("updatedAt")
    
    return Agent(
        agentId=agent_id,
        name=name,
        bio=bio if isinstance(bio, str) else None,
        email=email if isinstance(email, str) else None,
        status=status if isinstance(status, str) else "active",
        createdAt=created_at if isinstance(created_at, str) else None,
        updatedAt=updated_at if isinstance(updated_at, str) else None,
    )

def normalize_post(raw: Any) -> Post:
    if not isinstance(raw, dict):
        return Post(postId="", agentId="", type="emit", content="", createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
    
    post_id = str(raw.get("postId") or raw.get("id") or "")
    agent_id = str(raw.get("agentId") or "")
    
    author_agent_name = raw.get("authorAgentName") or raw.get("author_agent_name") or raw.get("agentName")
    
    type_str = str(raw.get("type") or "emit").lower()
    valid_type = "intake" if type_str == "intake" else "emit"
    content = str(raw.get("content") or "")
    category = raw.get("category")
    
    reply_count = raw.get("replyCount") or raw.get("reply_count") or raw.get("repliesCount") or 0
    created_at = raw.get("createdAt") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    updated_at = raw.get("updatedAt")
    
    return Post(
        postId=post_id,
        agentId=agent_id,
        type=valid_type,
        content=content,
        createdAt=created_at if isinstance(created_at, str) else datetime.datetime.now(datetime.timezone.utc).isoformat(),
        authorAgentName=author_agent_name if isinstance(author_agent_name, str) else None,
        category=category if isinstance(category, str) else None,
        replyCount=int(reply_count) if isinstance(reply_count, (int, float)) or (isinstance(reply_count, str) and reply_count.isdigit()) else 0,
        updatedAt=updated_at if isinstance(updated_at, str) else None,
    )

def normalize_reply(raw: Any) -> Reply:
    if not isinstance(raw, dict):
        return Reply(replyId="", postId="", authorAgentId="", content="", createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
    
    reply_id = str(raw.get("replyId") or raw.get("id") or "")
    post_id = str(raw.get("postId") or raw.get("post_id") or "")
    author_agent_id = str(raw.get("authorAgentId") or raw.get("author_agent_id") or raw.get("agentId") or "")
    author_agent_name = raw.get("authorAgentName") or raw.get("author_agent_name")
    content = str(raw.get("content") or "")
    created_at = raw.get("createdAt") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    return Reply(
        replyId=reply_id,
        postId=post_id,
        authorAgentId=author_agent_id,
        content=content,
        createdAt=created_at if isinstance(created_at, str) else datetime.datetime.now(datetime.timezone.utc).isoformat(),
        authorAgentName=author_agent_name if isinstance(author_agent_name, str) else None,
    )

def normalize_connection(raw: Any, current_agent_id: Optional[str] = None) -> Connection:
    if not isinstance(raw, dict):
        return Connection(connectionId="", agentId="", status="active", createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
    
    peer_agent_id = ""
    if raw.get("agentId"):
        peer_agent_id = str(raw.get("agentId"))
    elif raw.get("postOwnerAgentId") or raw.get("replyAuthorAgentId"):
        post_owner = str(raw.get("postOwnerAgentId") or "")
        reply_author = str(raw.get("replyAuthorAgentId") or "")
        if current_agent_id and post_owner == current_agent_id:
            peer_agent_id = reply_author
        elif current_agent_id and reply_author == current_agent_id:
            peer_agent_id = post_owner
        else:
            peer_agent_id = post_owner or reply_author
            
    connection_id = str(raw.get("connectionId") or raw.get("id") or "")
    connected_agent_name = raw.get("connectedAgentName") or raw.get("connected_agent_name")
    reply_id = raw.get("replyId") or raw.get("reply_id")
    status = raw.get("status") or "active"
    created_at = raw.get("createdAt") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    updated_at = raw.get("updatedAt")
    
    return Connection(
        connectionId=connection_id,
        agentId=peer_agent_id,
        connectedAgentName=connected_agent_name if isinstance(connected_agent_name, str) else None,
        replyId=reply_id if isinstance(reply_id, str) else None,
        status=status if isinstance(status, str) else "active",
        createdAt=created_at if isinstance(created_at, str) else datetime.datetime.now(datetime.timezone.utc).isoformat(),
        updatedAt=updated_at if isinstance(updated_at, str) else None,
    )

def normalize_connection_request(raw: Any) -> ConnectionRequest:
    if not isinstance(raw, dict):
        return ConnectionRequest(requestId="", senderAgentId="", receiverAgentId="", status="pending", createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
    
    request_id = str(raw.get("requestId") or raw.get("id") or "")
    sender_agent_id = str(raw.get("senderAgentId") or raw.get("sender_agent_id") or "")
    sender_agent_name = raw.get("senderAgentName") or raw.get("sender_agent_name")
    receiver_agent_id = str(raw.get("receiverAgentId") or raw.get("receiver_agent_id") or "")
    receiver_agent_name = raw.get("receiverAgentName") or raw.get("receiver_agent_name")
    status = raw.get("status") or "pending"
    created_at = raw.get("createdAt") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    return ConnectionRequest(
        requestId=request_id,
        senderAgentId=sender_agent_id,
        senderAgentName=sender_agent_name if isinstance(sender_agent_name, str) else None,
        receiverAgentId=receiver_agent_id,
        receiverAgentName=receiver_agent_name if isinstance(receiver_agent_name, str) else None,
        status=status if isinstance(status, str) else "pending",
        createdAt=created_at if isinstance(created_at, str) else datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )

def normalize_message(raw: Any, connection_id: Optional[str] = None) -> Message:
    if isinstance(raw, str):
        colon_idx = raw.find(":")
        if colon_idx > 0:
            sender = raw[:colon_idx].strip()
            text = raw[colon_idx+1:].strip()
            return Message(
                connectionId=connection_id or "",
                senderAgentId=sender,
                content=text,
                createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                raw=raw,
            )
        return Message(
            connectionId=connection_id or "",
            senderAgentId="",
            content=raw,
            createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            raw=raw,
        )
        
    if isinstance(raw, dict):
        message_id = raw.get("messageId") or raw.get("id")
        conn_id = raw.get("connectionId") or raw.get("connection_id") or connection_id or ""
        sender_agent_id = raw.get("senderAgentId") or raw.get("sender_agent_id") or raw.get("agentId") or ""
        sender_agent_name = raw.get("senderAgentName") or raw.get("sender_agent_name")
        content = raw.get("content") or raw.get("message") or ""
        created_at = raw.get("createdAt") or datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        return Message(
            messageId=message_id if isinstance(message_id, str) else None,
            connectionId=str(conn_id),
            senderAgentId=str(sender_agent_id),
            senderAgentName=sender_agent_name if isinstance(sender_agent_name, str) else None,
            content=str(content),
            createdAt=created_at if isinstance(created_at, str) else datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        
    return Message(
        connectionId=connection_id or "",
        senderAgentId="",
        content="",
        createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
