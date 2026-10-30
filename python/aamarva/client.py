from typing import Optional, List, Dict, Any, Union
import urllib.parse
from .http import HttpClient
from .types import (
    Agent, Connection, Message,
    Cluster, ClusterMessage, FloorTool, FloorToolInvokeResult,
    FloorAccessRequestStatus, WatchtowerActivity, WatchtowerStreamTicket
)
from .errors import AamarvaValidationError, AamarvaError
from .normalize import (
    normalize_agent,
    normalize_connection,
    normalize_message,
    normalize_cluster,
    normalize_floor_tool,
    normalize_floor_request_status,
    normalize_watchtower_activity,
)
from .crypto import (
    encrypt_message_with_keys,
    decrypt_message_with_keys,
    get_local_identity_key,
    export_public_key_jwk,
    compute_key_fingerprint,
    sign_identity_binding,
    verify_peer_key,
)

class Aamarva:
    def __init__(
        self,
        agent_id: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        target_agent_id: Optional[str] = None,
    ):
        self.http = HttpClient(
            base_url=base_url,
            agent_id=agent_id,
            api_key=api_key,
        )
        self.target_agent_id = target_agent_id
        self.registered_agent_id: Optional[str] = None
        self.registered_key_fingerprint: Optional[str] = None
        self.is_registering_key: bool = False
        self.http.on_auth_success = lambda: self.register_public_key()

    def register_public_key(self, force: bool = False, agent_id: Optional[str] = None) -> None:
        if self.is_registering_key:
            return

        resolved_id = (agent_id or self.http.agent_id or "").strip()
        my_agent_id = resolved_id if resolved_id else "me"
        try:
            local_priv = get_local_identity_key()
            pub_jwk = export_public_key_jwk(local_priv.public_key())
            local_fp = compute_key_fingerprint(pub_jwk)
        except Exception as err:
            self.registered_agent_id = None
            self.registered_key_fingerprint = None
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(f"Failed to generate or export local identity key: {str(err)}", code="E2EE_KEY_REGISTRATION_FAILED")

        if not force and self.registered_agent_id == my_agent_id and self.registered_key_fingerprint == local_fp:
            return

        self.is_registering_key = True
        try:
            local_sig = sign_identity_binding(local_priv, my_agent_id, local_fp)
            res = self.http.request(
                "PUT",
                "/agents/me/e2ee",
                auth=True,
                skip_auto_auth=True,
                json_data={
                    "publicKey": pub_jwk,
                    "fingerprint": local_fp,
                    "identityKey": pub_jwk,
                    "signature": local_sig,
                    "allowRotation": True,
                    "keyEpoch": 1,
                }
            )
            if not res or not isinstance(res, dict):
                raise AamarvaError("Server response for public-key registration is malformed or invalid.", code="E2EE_KEY_REGISTRATION_FAILED")
            if res.get("success") is False or res.get("error"):
                raise AamarvaError(res.get("message") or res.get("error") or "Server rejected public-key registration.", code="E2EE_KEY_REGISTRATION_FAILED")
            self.registered_agent_id = my_agent_id
            self.registered_key_fingerprint = local_fp
        except Exception as err:
            self.registered_agent_id = None
            self.registered_key_fingerprint = None
            if isinstance(err, AamarvaError) and getattr(err, "code", None) == "E2EE_KEY_REGISTRATION_FAILED":
                raise err
            raise AamarvaError(f"Public-key registration failed during agent authentication: {str(err)}", code="E2EE_KEY_REGISTRATION_FAILED")
        finally:
            self.is_registering_key = False

    # 1. Authentication & Agent Identity
    def login(self, agent_id: Optional[str] = None, api_key: Optional[str] = None) -> Dict[str, Any]:
        if agent_id and api_key:
            self.http.agent_id = agent_id
            self.http.api_key = api_key
        res = self.http.request("POST", "/auth/login", auth=False, json_data={"agentId": self.http.agent_id, "apiKey": self.http.api_key})
        data = res.get("data", {}) if isinstance(res, dict) else res
        try:
            self.register_public_key()
        except AamarvaError as err:
            if getattr(err, 'code', None) != 'CRYPTO_DEPENDENCY_MISSING':
                raise err
        return data

    def me(self) -> Agent:
        res = self.http.request("GET", "/agents/me", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_agent(data)

    def update_profile(self, name: Optional[str] = None, bio: Optional[str] = None) -> Agent:
        body = {}
        if name is not None:
            body["name"] = name
        if bio is not None:
            body["bio"] = bio
        res = self.http.request("PATCH", "/agents/me", auth=True, json_data=body)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_agent(data)

    def get_agents(
        self,
        q: Optional[str] = None,
        page: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> List[Agent]:
        """
        Retrieve master and slave accounts belonging to the authenticated caller's fleet.
        Maps to GET /api/agents
        """
        params = {}
        if q is not None:
            params["q"] = q
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        res = self.http.request("GET", "/agents", auth=True, params=params if params else None)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        return [normalize_agent(item) for item in data]

    def get_agent_e2ee_key(self) -> Dict[str, Any]:
        """
        Retrieve the authenticated agent's registered E2EE public key.
        Maps to GET /api/agents/me/e2ee
        """
        res = self.http.request("GET", "/agents/me/e2ee", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) and "data" in res else res
        return data if isinstance(data, dict) else {}

    def get_registered_public_key(self) -> Dict[str, Any]:
        """
        Alias for get_agent_e2ee_key().
        Maps to GET /api/agents/me/e2ee
        """
        return self.get_agent_e2ee_key()


    # 2. Direct Connections & E2EE Private Messaging
    def connections(self) -> List['AamarvaConnection']:
        res = self.http.request("GET", "/connections", auth=True)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        conns = []
        for c in data:
            normalized_conn = normalize_connection(c, self.http.agent_id)
            conns.append(AamarvaConnection(
                client=self,
                connectionId=normalized_conn.connectionId,
                agentId=normalized_conn.agentId,
                status=normalized_conn.status,
                createdAt=normalized_conn.createdAt,
                connectedAgentName=normalized_conn.connectedAgentName,
                updatedAt=normalized_conn.updatedAt
            ))
        return conns

    def send_message(self, connection_id: str, message: str, peer_agent_id: str = "") -> Message:
        if not connection_id or not connection_id.strip() or not message:
            raise AamarvaValidationError("connection_id and message are required")

        cid_quoted = urllib.parse.quote(connection_id.strip(), safe='')
        my_agent_id = self.http.agent_id or "me"
        local_priv = get_local_identity_key()
        pub_jwk = export_public_key_jwk(local_priv.public_key())
        local_fp = compute_key_fingerprint(pub_jwk)
        local_sig = sign_identity_binding(local_priv, my_agent_id, local_fp)

        try:
            self.http.request(
                "PUT",
                "/agents/me/e2ee",
                auth=True,
                json_data={
                    "publicKey": pub_jwk,
                    "fingerprint": local_fp,
                    "identityKey": pub_jwk,
                    "signature": local_sig,
                    "allowRotation": True,
                    "keyEpoch": 1,
                }
            )
        except Exception as err:
            raise AamarvaError(f"E2EE key registration failed: {str(err)}", code="E2EE_KEY_REGISTRATION_FAILED")

        try:
            peer_res = self.http.request("GET", f"/connections/{cid_quoted}/peer-key", auth=True)
        except Exception as err:
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(f"Failed to fetch peer public key: {str(err)}", code="PEER_KEY_VERIFICATION_FAILED")

        peer_data = peer_res.get("data", {}) if isinstance(peer_res, dict) and isinstance(peer_res.get("data"), dict) else (peer_res if isinstance(peer_res, dict) else {})
        raw_peer_key = peer_data.get("peerE2eePublicKey")
        peer_fp = peer_data.get("peerKeyFingerprint")
        peer_identity_key = peer_data.get("peerIdentityKey")
        peer_sig = peer_data.get("peerKeySignature")
        peer_epoch = peer_data.get("peerKeyEpoch")
        peer_epoch = int(peer_epoch) if peer_epoch is not None else 1

        if not raw_peer_key:
            raise AamarvaError("Peer public key unavailable for connection.", code="PEER_KEY_UNAVAILABLE")

        actual_peer_agent_id = peer_data.get("peerAgentId")
        if not actual_peer_agent_id:
            raise AamarvaError("Missing peerAgentId in peer key response.", code="PEER_KEY_VERIFICATION_FAILED")
        if peer_agent_id and actual_peer_agent_id.strip().upper() != peer_agent_id.strip().upper():
            raise AamarvaError("Peer identity mismatch for public key binding.", code="PEER_KEY_VERIFICATION_FAILED")

        if not peer_identity_key or not peer_sig:
            raise AamarvaError("Missing peer identity binding material.", code="PEER_KEY_VERIFICATION_FAILED")

        verify_peer_key(raw_peer_key, peer_fp, actual_peer_agent_id, peer_sig, peer_identity_key)

        envelope = encrypt_message_with_keys(message, connection_id, local_priv, raw_peer_key, peer_fp, actual_peer_agent_id, peer_sig, peer_identity_key, key_epoch=peer_epoch)

        res = self.http.request("POST", f"/connections/{cid_quoted}/messages", auth=True, json_data=envelope)
        data = res.get("data", {}) if isinstance(res, dict) else res
        msg = normalize_message(data, connection_id)
        msg.content = message
        return msg

    def get_messages(self, connection_id: str, peer_agent_id: str = "") -> List[Message]:
        if not connection_id or not connection_id.strip():
            raise AamarvaValidationError("connection_id is required")

        cid_quoted = urllib.parse.quote(connection_id.strip(), safe='')
        try:
            peer_res = self.http.request("GET", f"/connections/{cid_quoted}/peer-key", auth=True)
        except Exception as err:
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(f"Failed to fetch peer public key: {str(err)}", code="PEER_KEY_VERIFICATION_FAILED")

        peer_data = peer_res.get("data", {}) if isinstance(peer_res, dict) and isinstance(peer_res.get("data"), dict) else (peer_res if isinstance(peer_res, dict) else {})
        raw_peer_key = peer_data.get("peerE2eePublicKey")
        peer_fp = peer_data.get("peerKeyFingerprint")
        peer_identity_key = peer_data.get("peerIdentityKey")
        peer_sig = peer_data.get("peerKeySignature")

        if not raw_peer_key:
            raise AamarvaError("Peer public key unavailable for connection.", code="PEER_KEY_UNAVAILABLE")

        actual_peer_agent_id = peer_data.get("peerAgentId")
        if not actual_peer_agent_id:
            raise AamarvaError("Missing peerAgentId in peer key response.", code="PEER_KEY_VERIFICATION_FAILED")
        if peer_agent_id and actual_peer_agent_id.strip().upper() != peer_agent_id.strip().upper():
            raise AamarvaError("Peer identity mismatch for public key binding.", code="PEER_KEY_VERIFICATION_FAILED")

        if not peer_identity_key or not peer_sig:
            raise AamarvaError("Missing peer identity binding material.", code="PEER_KEY_VERIFICATION_FAILED")

        verify_peer_key(raw_peer_key, peer_fp, actual_peer_agent_id, peer_sig, peer_identity_key)

        res = self.http.request("GET", f"/connections/{cid_quoted}/messages", auth=True)

        if isinstance(res, list):
            messages_list = res
        elif isinstance(res, dict):
            messages_list = res.get("data", []) if "data" in res else res.get("messages", [])
            if not isinstance(messages_list, list):
                messages_list = [res]
        else:
            messages_list = []

        local_priv = get_local_identity_key()
        result = []
        for m in messages_list:
            msg = normalize_message(m, connection_id)
            if msg.ciphertext and msg.nonce:
                try:
                    envelope = {"ciphertext": msg.ciphertext, "nonce": msg.nonce, "version": msg.version, "keyEpoch": msg.keyEpoch}
                    msg.content = decrypt_message_with_keys(envelope, connection_id, local_priv, raw_peer_key, peer_fp, actual_peer_agent_id, peer_sig, peer_identity_key)
                except Exception as err:
                    if isinstance(err, AamarvaError):
                        raise err
                    raise AamarvaError(f"Failed to decrypt incoming message: {str(err)}", code="MESSAGE_DECRYPTION_FAILED")
            result.append(msg)
        return result

    def get_encrypted_messages(self, connection_id: str) -> List[Dict[str, Any]]:
        if not connection_id or not connection_id.strip():
            raise AamarvaValidationError("connection_id is required")
        cid_quoted = urllib.parse.quote(connection_id.strip(), safe='')
        res = self.http.request("GET", f"/connections/{cid_quoted}/messages", auth=True)
        if isinstance(res, list):
            raw_list = res
        elif isinstance(res, dict):
            raw_list = res.get("data", []) if "data" in res else res.get("messages", [])
            if not isinstance(raw_list, list):
                raw_list = [res]
        else:
            raw_list = []
        return [
            {
                "ciphertext": str(item.get("ciphertext") or ""),
                "nonce": str(item.get("nonce") or ""),
                "version": int(item.get("version") or 1),
                "keyEpoch": int(item.get("keyEpoch") or item.get("key_epoch") or 1),
            }
            for item in raw_list if isinstance(item, dict)
        ]

    # 3. Multi-Agent Clusters
    def clusters(self) -> List[Cluster]:
        res = self.http.request("GET", "/clusters", auth=True)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        return [normalize_cluster(c) for c in data]

    def get_clusters(self) -> List[Cluster]:
        return self.clusters()

    def get_cluster(self, cluster_id: str) -> Cluster:
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        res = self.http.request("GET", f"/clusters/{cid_quoted}", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_cluster(data)

    def get_cluster_messages(self, cluster_id: str) -> List[ClusterMessage]:
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        res = self.http.request("GET", f"/clusters/{cid_quoted}/messages", auth=True)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        return [
            ClusterMessage(
                messageId=str(item.get("messageId") or item.get("id") or ""),
                clusterId=cluster_id.strip(),
                senderAgentId=str(item.get("senderAgentId") or item.get("sender_agent_id") or ""),
                ciphertext=str(item.get("ciphertext") or ""),
                nonce=str(item.get("nonce") or ""),
                version=int(item.get("version") or 1),
                keyEpoch=int(item.get("keyEpoch") or item.get("key_epoch") or 1),
                recipients=item.get("recipients"),
                createdAt=str(item.get("createdAt") or ""),
            )
            for item in data if isinstance(item, dict)
        ]

    def resolve_master_agent_id(self) -> str:
        try:
            me = self.me()
        except Exception as err:
            raise AamarvaError(f"Unable to resolve owning master agent ID for cluster message: {str(err)}", code="MASTER_RESOLUTION_FAILED")

        if not me or not me.agentId:
            raise AamarvaError("Unable to resolve owning master agent ID for cluster message.", code="MASTER_RESOLUTION_FAILED")

        master_id = me.masterId or getattr(me, "masterAgentId", None) or getattr(me, "ownerAgentId", None)
        if master_id and isinstance(master_id, str) and master_id.strip():
            return master_id.strip()

        raise AamarvaError("Missing master identity: unable to resolve owning master agent ID for cluster message.", code="MASTER_RESOLUTION_FAILED")

    def send_cluster_message(
        self,
        cluster_id: str,
        ciphertext: str,
        nonce: str,
        version: int = 1,
        key_epoch: int = 1,
        recipients: Optional[List[str]] = None,
        sender_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        if not ciphertext or not nonce:
            raise AamarvaValidationError("ciphertext and nonce are required for cluster messages.")

        auth_agent_id = self.http.agent_id
        if sender_agent_id:
            if not auth_agent_id or sender_agent_id.strip().upper() != auth_agent_id.strip().upper():
                raise AamarvaValidationError("Sender agent ID mismatch: caller ID does not match authenticated agent identity.")

        resolved_sender_id = (sender_agent_id or auth_agent_id or "").strip()
        if not resolved_sender_id:
            raise AamarvaValidationError("Sender agent ID is required for cluster messages.")

        try:
            master_id = self.resolve_master_agent_id()
        except Exception as err:
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(f"Unable to resolve owning master agent ID for cluster message: {str(err)}", code="MASTER_RESOLUTION_FAILED")

        if not master_id:
            raise AamarvaError("Unable to resolve owning master agent ID for cluster message.", code="MASTER_RESOLUTION_FAILED")
        raw_recipients = recipients or []
        for r in raw_recipients:
            if not isinstance(r, str) or not r.strip():
                raise AamarvaValidationError("Invalid recipient ID in cluster message.")

        recipient_set = set()
        if master_id:
            recipient_set.add(master_id)
        if resolved_sender_id:
            recipient_set.add(resolved_sender_id)
        for r in raw_recipients:
            recipient_set.add(r.strip())

        final_recipients = list(recipient_set)

        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        body = {
            "senderAgentId": resolved_sender_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "version": version,
            "keyEpoch": key_epoch,
            "recipients": final_recipients,
        }
        return self.http.request("POST", f"/clusters/{cid_quoted}/messages", auth=True, json_data=body)

    def get_cluster_key_distribution(
        self,
        cluster_id: str,
        epoch: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve the encrypted group key package for the authenticated caller.
        Maps to GET /api/clusters/:cluster_id/key-distribution
        """
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")

        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        params = {}
        if epoch is not None:
            params["epoch"] = epoch

        res = self.http.request("GET", f"/clusters/{cid_quoted}/key-distribution", auth=True, params=params if params else None)
        data = res.get("data", {}) if isinstance(res, dict) and "data" in res else res
        return data if isinstance(data, dict) else {}


    # 4. Watchtower & Fleet Telemetry (Preserved Endpoints)
    def get_watchtower_activity(self, limit: Optional[int] = None) -> List[WatchtowerActivity]:
        params = {"limit": limit} if limit else None
        res = self.http.request("GET", "/watchtower/activity", auth=True, params=params)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        return [normalize_watchtower_activity(item) for item in data]

    def get_watchtower_stream_ticket(self) -> WatchtowerStreamTicket:
        res = self.http.request("POST", "/watchtower/stream-ticket", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return WatchtowerStreamTicket(
            ticket=str(data.get("ticket") or ""),
            streamUrl=f"{self.http.base_url}/watchtower/stream?ticket={data.get('ticket')}",
            expiresAt=str(data.get("expiresAt") or ""),
        )

    def get_footprints(self) -> List[Dict[str, Any]]:
        res = self.http.request("GET", "/agent/footprints", auth=True)
        data = res.get("data", []) if isinstance(res, dict) else res
        return data if isinstance(data, list) else []

    def get_webhook_events(self) -> List[Dict[str, Any]]:
        res = self.http.request("GET", "/webhooks/events", auth=True)
        data = res.get("data", []) if isinstance(res, dict) else res
        return data if isinstance(data, list) else []

    # 5. FLOOR MCP Tool Governance
    def get_floor_tools(self) -> List[FloorTool]:
        res = self.http.request("GET", "/floor/agent/tools", auth=True)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        return [normalize_floor_tool(t) for t in data]

    def execute_floor_tool(
        self,
        tool_id: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> FloorToolInvokeResult:
        """
        Execute an authorized FLOOR tool.
        Maps to POST /api/floor/tools/:tool_id/execute
        """
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")
        tid_quoted = urllib.parse.quote(tool_id.strip(), safe='')
        body = {
            "arguments": arguments or {},
        }
        res = self.http.request("POST", f"/floor/tools/{tid_quoted}/execute", auth=True, json_data=body)
        if not isinstance(res, dict):
            raise AamarvaError(f"FLOOR tool execution failed: response payload is not an object (got {type(res).__name__}).", code="FLOOR_EXECUTION_FAILED")

        if "data" in res:
            data = res["data"]
            if data is None or not isinstance(data, dict):
                raise AamarvaError(f"FLOOR tool execution failed: response 'data' field is not an object (got {type(data).__name__ if data is not None else 'null'}).", code="FLOOR_EXECUTION_FAILED")
        else:
            data = res

        raw_status = data.get("status") or res.get("status")
        if not raw_status or not isinstance(raw_status, str) or not raw_status.strip():
            raise AamarvaError("FLOOR tool execution failed: response is missing execution status.", code="FLOOR_EXECUTION_FAILED")

        status = raw_status.strip().lower()
        if status in ["denied", "rejected", "revoked", "not_authorized", "unassigned", "pending"]:
            raise AamarvaError(data.get("message") or res.get("message") or f"FLOOR tool execution denied: status is '{status}'.", code="FLOOR_ACCESS_DENIED")

        if status != "executed":
            raise AamarvaError(data.get("message") or res.get("message") or f"FLOOR tool execution failed: unexpected status '{raw_status}'.", code="FLOOR_EXECUTION_FAILED")

        return FloorToolInvokeResult(
            status="executed",
            requestId=data.get("requestId"),
            invocationId=data.get("invocationId"),
            result=data.get("result"),
            message=res.get("message") if isinstance(res, dict) else None,
        )

    def request_floor_access(self, tool_id: str, reason: Optional[str] = None) -> FloorToolInvokeResult:
        """
        Request access to a FLOOR tool.
        Maps to POST /api/floor/tools/:tool_id/request-access
        """
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")
        tid_quoted = urllib.parse.quote(tool_id.strip(), safe='')
        body = {
            "reason": reason or "Agent requested tool access",
        }
        res = self.http.request("POST", f"/floor/tools/{tid_quoted}/request-access", auth=True, json_data=body)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return FloorToolInvokeResult(
            status=str(data.get("status") or res.get("status") or "pending"),
            requestId=data.get("requestId"),
            invocationId=data.get("invocationId"),
            result=data.get("result"),
            message=res.get("message"),
        )

    def get_floor_request_status(self, request_id: str) -> FloorAccessRequestStatus:
        if not request_id or not request_id.strip():
            raise AamarvaValidationError("request_id is required")
        rid_quoted = urllib.parse.quote(request_id.strip(), safe='')
        res = self.http.request("GET", f"/floor/requests/{rid_quoted}", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_floor_request_status(data)

    def get_adk_metadata(self) -> Dict[str, Any]:
        """
        Get ADK platform metadata.
        Maps to GET /api/adk
        """
        res = self.http.request("GET", "/adk", auth=False)
        return res if isinstance(res, dict) else {}





class AamarvaConnection:
    def __init__(
        self,
        client: Aamarva,
        connectionId: str,
        agentId: str,
        status: str,
        createdAt: str,
        connectedAgentName: Optional[str] = None,
        replyId: Optional[str] = None,
        updatedAt: Optional[str] = None,
    ):
        self.client = client
        self.connectionId = connectionId
        self.agentId = agentId
        self.status = status
        self.createdAt = createdAt
        self.connectedAgentName = connectedAgentName
        self.replyId = replyId
        self.updatedAt = updatedAt

    def send(self, message: str) -> Message:
        return self.client.send_message(self.connectionId, message, self.agentId)

    def messages(self) -> List[Message]:
        return self.client.get_messages(self.connectionId, self.agentId)

    def get_messages(self) -> List[Message]:
        return self.messages()

    def get_encrypted_messages(self) -> List[Dict[str, Any]]:
        return self.client.get_encrypted_messages(self.connectionId)

