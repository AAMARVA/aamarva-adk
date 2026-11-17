import datetime
from typing import Any, Optional
from .types import (
    Agent,
    Connection,
    Message,
    Cluster,
    FloorTool,
    FloorAccessRequestStatus,
    WatchtowerActivity,
)

from .errors import AamarvaError

def extract_master_id(raw: dict) -> Optional[str]:
    fields = ["masterId", "master_id", "masterAgentId", "master_agent_id", "ownerAgentId", "owner_agent_id"]
    candidates = []
    for f in fields:
        val = raw.get(f)
        if isinstance(val, str) and val.strip():
            candidates.append((f, val.strip()))

    if not candidates:
        return None

    primary_field, primary_val = candidates[0]
    for field, val in candidates[1:]:
        if val != primary_val:
            raise AamarvaError(
                f"Conflicting master/owner identity fields detected: {primary_field}={primary_val} vs {field}={val}.",
                code="MASTER_RESOLUTION_FAILED"
            )

    return primary_val

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
    master_id = extract_master_id(raw)
    
    return Agent(
        agentId=agent_id,
        name=name,
        bio=bio if isinstance(bio, str) else None,
        email=email if isinstance(email, str) else None,
        status=status if isinstance(status, str) else "active",
        avatar=raw.get("avatar"),
        avatarUrl=raw.get("avatarUrl") or raw.get("avatar_url"),
        masterId=master_id,
        slaveIds=raw.get("slaveIds") or raw.get("slave_ids"),
        createdAt=created_at if isinstance(created_at, str) else None,
        updatedAt=updated_at if isinstance(updated_at, str) else None,
    )

def normalize_connection(raw: Any, current_agent_id: Optional[str] = None) -> Connection:
    if not isinstance(raw, dict):
        return Connection(connectionId="", agentId="", status="active", createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
    
    peer_agent_id = ""
    if raw.get("peerAgentId"):
        peer_agent_id = str(raw.get("peerAgentId"))
    elif raw.get("agentId") and raw.get("agentId") != current_agent_id:
        peer_agent_id = str(raw.get("agentId"))
    elif raw.get("targetAgentId"):
        peer_agent_id = str(raw.get("targetAgentId"))
    elif raw.get("receiverAgentId"):
        peer_agent_id = str(raw.get("receiverAgentId"))
            
    connection_id = str(raw.get("connectionId") or raw.get("id") or "")
    connected_agent_name = raw.get("connectedAgentName") or raw.get("connected_agent_name")
    status = raw.get("status") or "active"
    created_at = raw.get("createdAt") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    updated_at = raw.get("updatedAt")
    
    return Connection(
        connectionId=connection_id,
        agentId=str(raw.get("agentId") or current_agent_id or ""),
        peerAgentId=peer_agent_id or None,
        connectedAgentName=connected_agent_name if isinstance(connected_agent_name, str) else None,
        status=status if isinstance(status, str) else "active",
        createdAt=created_at if isinstance(created_at, str) else datetime.datetime.now(datetime.timezone.utc).isoformat(),
        updatedAt=updated_at if isinstance(updated_at, str) else None,
    )


def _parse_positive_int(val: Any) -> Optional[int]:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, int):
        return val if val >= 1 else None
    if isinstance(val, str):
        trimmed = val.strip()
        if trimmed.isdigit():
            parsed = int(trimmed)
            return parsed if parsed >= 1 else None
    return None


def normalize_message(raw: Any, connection_id: Optional[str] = None) -> Message:
    if isinstance(raw, str):
        raise AamarvaError("Plaintext transcript string received on private E2EE channel; transport must be encrypted.", code="PLAINTEXT_MESSAGE_RECEIVED")
    
    if not isinstance(raw, dict):
        raise AamarvaError("Invalid message format received.", code="MESSAGE_INVALID_ENVELOPE")

    has_plaintext = bool((raw.get("content") and str(raw.get("content")).strip()) or (raw.get("message") and str(raw.get("message")).strip()))
    ciphertext = raw.get("ciphertext") if isinstance(raw.get("ciphertext"), str) and raw.get("ciphertext").strip() else None
    nonce = raw.get("nonce") if isinstance(raw.get("nonce"), str) and raw.get("nonce").strip() else None
    version = _parse_positive_int(raw.get("version"))
    raw_epoch = raw.get("keyEpoch") if raw.get("keyEpoch") is not None else raw.get("key_epoch")
    key_epoch = _parse_positive_int(raw_epoch)

    if has_plaintext and not ciphertext:
        raise AamarvaError("Plaintext message received from private-message endpoint; transport must be encrypted.", code="PLAINTEXT_MESSAGE_RECEIVED")

    if not ciphertext or not nonce or version is None or key_epoch is None:
        if has_plaintext:
            raise AamarvaError("Plaintext message received from private-message endpoint; transport must be encrypted.", code="PLAINTEXT_MESSAGE_RECEIVED")
        raise AamarvaError("Invalid encrypted envelope: missing or invalid required fields, version, or key epoch.", code="MESSAGE_INVALID_ENVELOPE")

    return Message(
        messageId=str(raw.get("messageId") or raw.get("id") or ""),
        connectionId=str(raw.get("connectionId") or connection_id or ""),
        senderAgentId=str(raw.get("senderAgentId") or raw.get("sender_agent_id") or ""),
        senderAgentName=raw.get("senderAgentName") or raw.get("sender_agent_name"),
        content=None,
        ciphertext=str(ciphertext),
        nonce=str(nonce),
        version=version,
        keyEpoch=key_epoch,
        createdAt=raw.get("createdAt") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )

def normalize_cluster(raw: Any) -> Cluster:
    if not isinstance(raw, dict):
        return Cluster(name="", createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat())

    raw_epoch = raw.get("epoch") if raw.get("epoch") is not None else (raw.get("keyEpoch") if raw.get("keyEpoch") is not None else raw.get("key_epoch"))
    epoch = _parse_positive_int(raw_epoch)
    raw_members = raw.get("members")
    members = None
    if isinstance(raw_members, list):
        members = [
            str(m.get("agentId") or m.get("id") or "") if isinstance(m, dict) else str(m)
            for m in raw_members
        ]
        members = [m for m in members if m]

    return Cluster(
        id=str(raw.get("id") or raw.get("clusterId") or ""),
        clusterId=str(raw.get("clusterId") or raw.get("id") or ""),
        name=str(raw.get("name") or ""),
        description=raw.get("description"),
        ownerUserId=raw.get("ownerUserId") or raw.get("owner_user_id"),
        ownerAgentId=raw.get("ownerAgentId") or raw.get("owner_agent_id"),
        membersCount=raw.get("membersCount") or raw.get("members_count"),
        members=members,
        epoch=epoch,
        keyEpoch=epoch,
        keyFingerprint=raw.get("keyFingerprint") or raw.get("key_fingerprint"),
        rosterHash=raw.get("rosterHash") or raw.get("roster_hash"),
        rotationStatus=raw.get("rotationStatus") or raw.get("rotation_status"),
        createdAt=raw.get("createdAt"),
        updatedAt=raw.get("updatedAt"),
    )

def normalize_floor_tool(raw: Any) -> FloorTool:
    if not isinstance(raw, dict):
        return FloorTool(id="", name="", description="", inputSchema={}, accessStatus="required")

    schema = raw.get("inputSchema") or raw.get("input_schema") or raw.get("parameters") or {"type": "object"}
    req_id = raw.get("requestId") or raw.get("request_id") or raw.get("pendingRequestId") or raw.get("pending_request_id")
    mcp_server_id = raw.get("mcpServerId") or raw.get("mcp_server_id")
    gateway_id = raw.get("gatewayId") or raw.get("gateway_id")
    gateway_url = raw.get("gatewayUrl") or raw.get("gateway_url")
    return FloorTool(
        id=str(raw.get("id") or raw.get("toolId") or raw.get("tool_id") or ""),
        name=str(raw.get("name") or ""),
        description=str(raw.get("description") or ""),
        inputSchema=schema if isinstance(schema, dict) else {"type": "object"},
        accessStatus=str(raw.get("accessStatus") or raw.get("access_status") or raw.get("status") or "required").strip().lower(),
        requestId=str(req_id).strip() if isinstance(req_id, str) and req_id.strip() else None,
        mcpServerId=str(mcp_server_id).strip() if isinstance(mcp_server_id, str) and mcp_server_id.strip() else None,
        gatewayId=str(gateway_id).strip() if isinstance(gateway_id, str) and gateway_id.strip() else None,
        gatewayUrl=str(gateway_url).strip() if isinstance(gateway_url, str) and gateway_url.strip() else None,
    )

def normalize_floor_request_status(raw: Any) -> FloorAccessRequestStatus:
    if not isinstance(raw, dict):
        return FloorAccessRequestStatus(requestId="", status="pending")

    inv_id = raw.get("invocationId") or raw.get("invocation_id")
    gateway_envelope = raw.get("gatewayEnvelope") if isinstance(raw.get("gatewayEnvelope"), dict) else (
        raw.get("gateway_envelope") if isinstance(raw.get("gateway_envelope"), dict) else None
    )
    approved_args = raw.get("approvedArguments") if raw.get("approvedArguments") is not None else raw.get("approved_arguments")
    verification_info = raw.get("verificationInfo") if raw.get("verificationInfo") is not None else raw.get("verification_info")
    return FloorAccessRequestStatus(
        requestId=str(raw.get("requestId") or raw.get("request_id") or raw.get("id") or ""),
        status=str(raw.get("status") or "pending").strip().lower(),
        toolId=raw.get("toolId") or raw.get("tool_id"),
        invocationId=str(inv_id).strip() if isinstance(inv_id, str) and inv_id.strip() else None,
        agentId=raw.get("agentId") or raw.get("agent_id"),
        agentName=raw.get("agentName") or raw.get("agent_name"),
        mcpServerId=raw.get("mcpServerId") or raw.get("mcp_server_id"),
        gatewayId=raw.get("gatewayId") or raw.get("gateway_id"),
        gatewayUrl=raw.get("gatewayUrl") or raw.get("gateway_url"),
        approvedArgsDigest=raw.get("approvedArgsDigest") or raw.get("approved_args_digest"),
        approvedArguments=approved_args if isinstance(approved_args, dict) else None,
        scope=raw.get("scope"),
        expiresAt=raw.get("expiresAt") or raw.get("expires_at"),
        verificationInfo=verification_info if isinstance(verification_info, dict) else None,
        gatewayEnvelope=gateway_envelope,
        reason=raw.get("reason"),
        createdAt=raw.get("createdAt"),
        updatedAt=raw.get("updatedAt"),
    )

def normalize_watchtower_activity(raw: Any) -> WatchtowerActivity:
    if not isinstance(raw, dict):
        return WatchtowerActivity(id="", type="unknown", summary="", timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat())

    return WatchtowerActivity(
        id=str(raw.get("id") or raw.get("activityId") or raw.get("activity_id") or ""),
        type=str(raw.get("type") or raw.get("eventType") or "unknown"),
        summary=str(raw.get("summary") or raw.get("description") or ""),
        timestamp=str(raw.get("timestamp") or raw.get("createdAt") or datetime.datetime.now(datetime.timezone.utc).isoformat()),
        actorAgentId=raw.get("actorAgentId") or raw.get("actor_agent_id"),
        targetAgentId=raw.get("targetAgentId") or raw.get("target_agent_id"),
        details=raw.get("details") if isinstance(raw.get("details"), dict) else None,
    )


