import base64
import datetime
import json
import time
from typing import Optional, List, Dict, Any, Union
import urllib.parse
from .http import HttpClient
from .types import (
    Agent, Connection, Message,
    ClusterMember, Cluster, ClusterMessage, FloorTool, FloorToolInvokeResult,
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
    normalize_agent_id,
    canonical_member_set,
    compute_key_fingerprint,
    compute_group_key_fingerprint,
    compute_roster_hash,
    compute_audience_hash,
    sign_identity_binding,
    verify_peer_key,
    generate_cluster_key,
    wrap_cluster_key_for_recipient,
    unwrap_cluster_key,
    encrypt_cluster_message,
    decrypt_cluster_message,
    sign_cluster_message_v2,
    verify_cluster_message_signature_v2,
)
from .mcp_executor import invoke_external_mcp_tool

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
            target_agent_id=target_agent_id,
        )
        self.registered_agent_id: Optional[str] = None
        self.registered_key_fingerprint: Optional[str] = None
        self.is_registering_key: bool = False
        self.cluster_key_cache: Dict[str, bytes] = {}
        self._pending_floor_requests: Dict[str, str] = {}
        self.http.on_auth_success = lambda: self.register_public_key()

    @property
    def target_agent_id(self) -> Optional[str]:
        return self.http.target_agent_id

    @target_agent_id.setter
    def target_agent_id(self, value: Optional[str]) -> None:
        self.http.target_agent_id = value

    def set_target_agent_id(self, target_agent_id: Optional[str]) -> None:
        self.http.set_target_agent_id(target_agent_id)

    def get_target_agent_id(self) -> Optional[str]:
        return self.http.get_target_agent_id()

    def register_public_key(self, force: bool = False, agent_id: Optional[str] = None) -> None:
        if self.is_registering_key:
            return

        resolved_id = (agent_id or self.http.agent_id or "").strip()
        my_agent_id = resolved_id if resolved_id else "me"
        try:
            local_priv = get_local_identity_key(my_agent_id)
            pub_jwk = export_public_key_jwk(local_priv.public_key())
            local_fp = compute_key_fingerprint(pub_jwk)
        except Exception as err:
            if agent_id is None or self.registered_agent_id == my_agent_id:
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
            if agent_id is None or self.registered_agent_id == my_agent_id:
                self.registered_agent_id = None
                self.registered_key_fingerprint = None
            if isinstance(err, AamarvaError) and getattr(err, "code", None) == "E2EE_KEY_REGISTRATION_FAILED":
                raise err
            raise AamarvaError(f"Public-key registration failed during agent authentication: {str(err)}", code="E2EE_KEY_REGISTRATION_FAILED")
        finally:
            self.is_registering_key = False

    def is_e2ee_ready(self) -> bool:
        return bool(self.registered_agent_id and self.registered_key_fingerprint)

    # 1. Authentication & Agent Identity
    def login(self, agent_id: Optional[str] = None, api_key: Optional[str] = None) -> Dict[str, Any]:
        if agent_id and api_key:
            self.http.agent_id = agent_id
            self.http.api_key = api_key
        res = self.http.request("POST", "/auth/login", auth=False, json_data={"agentId": self.http.agent_id, "apiKey": self.http.api_key})
        data = res.get("data", {}) if isinstance(res, dict) else res
        self.register_public_key()
        return data

    def me(self) -> Agent:
        res = self.http.request("GET", "/agents/me", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_agent(data)

    def update_profile(
        self,
        name: Optional[str] = None,
        bio: Optional[str] = None,
        avatar: Optional[str] = None,
    ) -> Agent:
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if bio is not None:
            body["bio"] = bio
        if avatar is not None:
            body["avatar"] = avatar
        if not body:
            raise AamarvaValidationError(
                "At least one property (name, bio, or avatar) is required to update profile."
            )
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
    def connections(
        self,
        page: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> List['AamarvaConnection']:
        params: Dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        if params:
            res = self.http.request("GET", "/connections", auth=True, params=params)
        else:
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

    def get_peer_key_by_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Retrieve peer public key details by target Agent ID (Workflow 1/2 lookup).
        Maps to GET /api/connections/peer-key/:agentId
        """
        if not agent_id or not agent_id.strip():
            raise AamarvaValidationError("agent_id is required")
        aid_quoted = urllib.parse.quote(agent_id.strip(), safe='')
        res = self.http.request("GET", f"/connections/peer-key/{aid_quoted}", auth=True)
        return res.get("data", {}) if isinstance(res, dict) and "data" in res else (res if isinstance(res, dict) else {})

    def _fetch_verified_peer_key(self, connection_id: str, expected_peer_agent_id: str = "") -> Dict[str, Any]:
        cid_quoted = urllib.parse.quote(connection_id.strip(), safe='')
        try:
            peer_res = self.http.request("GET", f"/connections/{cid_quoted}/peer-key", auth=True)
        except Exception as err:
            status_code = getattr(err, "status_code", None)
            target_id = (expected_peer_agent_id or "").strip()
            if target_id and (status_code == 404 or getattr(err, "code", None) == "NOT_FOUND"):
                peer_res = self.http.request(
                    "GET",
                    f"/connections/peer-key/{urllib.parse.quote(target_id, safe='')}",
                    auth=True,
                )
            elif isinstance(err, AamarvaError):
                raise err
            else:
                raise AamarvaError(f"Failed to fetch peer public key: {str(err)}", code="PEER_KEY_VERIFICATION_FAILED")

        peer_data = (
            peer_res.get("data", {})
            if isinstance(peer_res, dict) and isinstance(peer_res.get("data"), dict)
            else (peer_res if isinstance(peer_res, dict) else {})
        )
        raw_peer_key = peer_data.get("peerE2eePublicKey") or peer_data.get("e2eePublicKey") or peer_data.get("publicKey")
        peer_fp = peer_data.get("peerKeyFingerprint") or peer_data.get("keyFingerprint") or peer_data.get("fingerprint")
        peer_identity_key = peer_data.get("peerIdentityKey") or peer_data.get("identityKey")
        peer_sig = peer_data.get("peerKeySignature") or peer_data.get("signature")
        peer_epoch = peer_data.get("peerKeyEpoch") if peer_data.get("peerKeyEpoch") is not None else peer_data.get("keyEpoch")
        peer_epoch = int(peer_epoch) if peer_epoch is not None else 1

        if not raw_peer_key:
            raise AamarvaError("Peer public key unavailable for connection.", code="PEER_KEY_UNAVAILABLE")

        actual_peer_agent_id = peer_data.get("peerAgentId") or peer_data.get("agentId")
        if not actual_peer_agent_id:
            raise AamarvaError("Missing peerAgentId in peer key response.", code="PEER_KEY_VERIFICATION_FAILED")
        if expected_peer_agent_id and actual_peer_agent_id.strip().upper() != expected_peer_agent_id.strip().upper():
            raise AamarvaError("Peer identity mismatch for public key binding.", code="PEER_KEY_VERIFICATION_FAILED")

        if not peer_identity_key or not peer_sig:
            raise AamarvaError("Missing peer identity binding material.", code="PEER_KEY_VERIFICATION_FAILED")

        verify_peer_key(raw_peer_key, peer_fp, actual_peer_agent_id, peer_sig, peer_identity_key)

        return {
            "raw_peer_key": raw_peer_key,
            "peer_fp": peer_fp,
            "peer_identity_key": peer_identity_key,
            "peer_sig": peer_sig,
            "peer_epoch": peer_epoch,
            "actual_peer_agent_id": actual_peer_agent_id,
        }

    def send_message(self, connection_id: str, message: str, peer_agent_id: str = "") -> Message:
        if not connection_id or not connection_id.strip() or not message:
            raise AamarvaValidationError("connection_id and message are required")

        cid_quoted = urllib.parse.quote(connection_id.strip(), safe='')
        my_agent_id = self.http.agent_id or "me"
        self.register_public_key()
        local_priv = get_local_identity_key(my_agent_id)

        peer_info = self._fetch_verified_peer_key(connection_id, peer_agent_id)

        envelope = encrypt_message_with_keys(
            message,
            connection_id,
            local_priv,
            peer_info["raw_peer_key"],
            peer_info["peer_fp"],
            peer_info["actual_peer_agent_id"],
            peer_info["peer_sig"],
            peer_info["peer_identity_key"],
            key_epoch=peer_info["peer_epoch"],
            sender_agent_id=my_agent_id,
        )

        res = self.http.request("POST", f"/connections/{cid_quoted}/messages", auth=True, json_data=envelope)
        data = res.get("data", {}) if isinstance(res, dict) else res
        msg = normalize_message(data, connection_id)
        msg.content = message
        return msg

    def get_messages(self, connection_id: str, peer_agent_id: str = "") -> List[Message]:
        if not connection_id or not connection_id.strip():
            raise AamarvaValidationError("connection_id is required")

        cid_quoted = urllib.parse.quote(connection_id.strip(), safe='')
        peer_info = self._fetch_verified_peer_key(connection_id, peer_agent_id)

        res = self.http.request("GET", f"/connections/{cid_quoted}/messages", auth=True)

        if isinstance(res, list):
            messages_list = res
        elif isinstance(res, dict):
            messages_list = res.get("data", []) if "data" in res else res.get("messages", [])
            if not isinstance(messages_list, list):
                messages_list = [res]
        else:
            messages_list = []

        my_agent_id = self.http.agent_id or "me"
        result = []
        for m in messages_list:
            msg = normalize_message(m, connection_id)
            if msg.ciphertext and msg.nonce:
                try:
                    msg_epoch = msg.keyEpoch if getattr(msg, "keyEpoch", None) and msg.keyEpoch > 1 else None
                    local_priv = get_local_identity_key(my_agent_id, epoch=msg_epoch)
                    envelope = {
                        "ciphertext": msg.ciphertext,
                        "nonce": msg.nonce,
                        "version": msg.version,
                        "keyEpoch": msg.keyEpoch,
                        "senderAgentId": msg.senderAgentId,
                    }
                    msg.content = decrypt_message_with_keys(
                        envelope,
                        connection_id,
                        local_priv,
                        peer_info["raw_peer_key"],
                        peer_info["peer_fp"],
                        peer_info["actual_peer_agent_id"],
                        peer_info["peer_sig"],
                        peer_info["peer_identity_key"],
                        sender_agent_id=msg.senderAgentId or peer_info["actual_peer_agent_id"],
                    )
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

    def get_cluster_members(self, cluster_id: str) -> List[ClusterMember]:
        """
        Retrieve cluster members and registered public keys for Workflow 2 roster & wrapping.
        Maps to GET /api/clusters/public/:clusterId/members
        """
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        res = self.http.request("GET", f"/clusters/public/{cid_quoted}/members", auth=True)
        raw = res.get("data", []) if isinstance(res, dict) else res
        if isinstance(raw, dict):
            raw = raw.get("members", [])
        if not isinstance(raw, list):
            raw = []

        members: List[ClusterMember] = []
        for item in raw:
            if isinstance(item, str) and item.strip():
                members.append(ClusterMember(agentId=item.strip()))
            elif isinstance(item, dict):
                aid = str(item.get("agentId") or item.get("agent_id") or item.get("id") or "").strip()
                if aid:
                    raw_epoch = item.get("keyEpoch") if item.get("keyEpoch") is not None else item.get("key_epoch")
                    members.append(
                        ClusterMember(
                            agentId=aid,
                            name=item.get("name"),
                            role=item.get("role"),
                            status=item.get("status"),
                            publicKey=item.get("publicKey") or item.get("e2eePublicKey") or item.get("peerE2eePublicKey"),
                            keyFingerprint=item.get("keyFingerprint") or item.get("fingerprint") or item.get("peerKeyFingerprint"),
                            keyEpoch=int(raw_epoch) if raw_epoch is not None else None,
                            identityKey=item.get("identityKey") or item.get("peerIdentityKey"),
                            keySignature=item.get("keySignature") or item.get("signature") or item.get("peerKeySignature"),
                        )
                    )
        return members

    def rotate_cluster_key(
        self,
        cluster_id: str,
        current_epoch: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Rotate the active group encryption epoch for a cluster.
        Maps to POST /api/clusters/:clusterId/rotate-key
        """
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        body: Dict[str, Any] = {}
        if current_epoch is not None:
            body["currentEpoch"] = current_epoch
        if reason is not None:
            body["reason"] = reason
        res = self.http.request("POST", f"/clusters/{cid_quoted}/rotate-key", auth=True, json_data=body)
        data = res.get("data", {}) if isinstance(res, dict) and isinstance(res.get("data"), dict) else (res if isinstance(res, dict) else {})
        next_epoch = int(data.get("epoch") or data.get("keyEpoch") or 1)
        return {
            "clusterId": str(data.get("clusterId") or cluster_id.strip()),
            "epoch": next_epoch,
            "keyEpoch": int(data.get("keyEpoch") or next_epoch),
            "rotationStatus": data.get("rotationStatus"),
            "rotatedAt": data.get("rotatedAt"),
            "message": data.get("message") or (res.get("message") if isinstance(res, dict) else None),
        }

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
                audienceHash=item.get("audienceHash") or item.get("audience_hash"),
                rosterHash=item.get("rosterHash") or item.get("roster_hash"),
                keyFingerprint=item.get("keyFingerprint") or item.get("key_fingerprint"),
                signature=item.get("signature"),
                sequence=item.get("sequence"),
                recipients=item.get("recipients"),
                recipientAgentIds=item.get("recipientAgentIds"),
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
        version: int = 2,
        key_epoch: int = 1,
        recipients: Optional[List[str]] = None,
        sender_agent_id: Optional[str] = None,
        audience_hash: Optional[str] = None,
        roster_hash: Optional[str] = None,
        key_fingerprint: Optional[str] = None,
        signature: Optional[str] = None,
        strict_preflight: Optional[bool] = None,
        sequence: Optional[Union[str, int]] = None,
        recipient_agent_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        if not ciphertext or not nonce:
            raise AamarvaValidationError("ciphertext and nonce are required for cluster messages.")

        if isinstance(version, bool) or not isinstance(version, int) or version != 2:
            raise AamarvaValidationError(
                "Cluster messages require protocol version 2.",
                code="INVALID_CLUSTER_MESSAGE_VERSION",
            )

        if isinstance(key_epoch, bool) or not isinstance(key_epoch, int) or key_epoch < 1:
            raise AamarvaValidationError(
                "Cluster messages require key_epoch to be an integer >= 1.",
                code="INVALID_CLUSTER_KEY_EPOCH",
            )

        if not isinstance(nonce, str):
            raise AamarvaValidationError(
                "Cluster message nonce must be a valid Base64-encoded 12-byte string.",
                code="INVALID_CLUSTER_NONCE",
            )
        try:
            decoded_nonce = base64.b64decode(nonce.encode("ascii"), validate=True)
        except Exception:
            raise AamarvaValidationError(
                "Cluster message nonce must be a valid Base64-encoded 12-byte string.",
                code="INVALID_CLUSTER_NONCE",
            )
        if base64.b64encode(decoded_nonce).decode("ascii") != nonce or len(decoded_nonce) != 12:
            raise AamarvaValidationError(
                "Cluster message nonce must decode from Base64 to exactly 12 bytes.",
                code="INVALID_CLUSTER_NONCE",
            )

        raw_recipients = recipients or []
        for r in raw_recipients:
            if not isinstance(r, str) or not r.strip():
                raise AamarvaValidationError("Invalid recipient ID in cluster message.")

        if recipient_agent_ids:
            for r in recipient_agent_ids:
                if not isinstance(r, str) or not r.strip():
                    raise AamarvaValidationError("Invalid recipient ID in cluster message.")

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

        recipient_set = set()
        if master_id:
            recipient_set.add(master_id)
        if resolved_sender_id:
            recipient_set.add(resolved_sender_id)
        for r in raw_recipients:
            recipient_set.add(r.strip())
        if recipient_agent_ids:
            for r in recipient_agent_ids:
                recipient_set.add(r.strip())

        final_recipients = list(recipient_set)

        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        body: Dict[str, Any] = {
            "senderAgentId": resolved_sender_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "version": version,
            "keyEpoch": key_epoch,
            "recipients": final_recipients,
        }
        if audience_hash is not None:
            body["audienceHash"] = audience_hash
        if roster_hash is not None:
            body["rosterHash"] = roster_hash
        if key_fingerprint is not None:
            body["keyFingerprint"] = key_fingerprint
        if signature is not None:
            body["signature"] = signature
        if strict_preflight is not None:
            body["strictPreflight"] = strict_preflight
        if sequence is not None:
            body["sequence"] = sequence
        if recipient_agent_ids is not None:
            body["recipientAgentIds"] = recipient_agent_ids

        return self.http.request("POST", f"/clusters/{cid_quoted}/messages", auth=True, json_data=body)

    def submit_cluster_key_distribution(
        self,
        cluster_id: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Submit key packages to the platform's key-distribution endpoint.
        Maps to POST /api/clusters/:cluster_id/key-distribution
        """
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")

        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        body = {"clusterId": cluster_id.strip(), **payload}
        self.http.request("POST", f"/clusters/{cid_quoted}/key-distribution", auth=True, json_data=body)

    def _cluster_cache_key(self, cluster_id: str, epoch: int = 1, audience_hash: str = "ALL") -> str:
        return f"{cluster_id}:{epoch}:{audience_hash or 'ALL'}"

    def _resolve_recipient_key_material(
        self,
        agent_id: str,
        cluster_members: List[ClusterMember],
        explicit_keys: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        norm_target = normalize_agent_id(agent_id)
        if explicit_keys:
            direct = explicit_keys.get(agent_id) or explicit_keys.get(norm_target)
            if direct is not None:
                if isinstance(direct, dict) and "publicKey" in direct and "kty" not in direct:
                    return {
                        "publicKey": direct["publicKey"],
                        "keyFingerprint": direct.get("keyFingerprint") or direct.get("fingerprint"),
                        "keyEpoch": direct.get("keyEpoch"),
                    }
                return {"publicKey": direct}

        for m in cluster_members:
            if normalize_agent_id(m.agentId) == norm_target and m.publicKey:
                return {
                    "publicKey": m.publicKey,
                    "keyFingerprint": m.keyFingerprint,
                    "keyEpoch": m.keyEpoch,
                }

        try:
            pk = self.get_peer_key_by_agent(agent_id)
            raw_key = pk.get("publicKey") or pk.get("peerE2eePublicKey") or pk.get("peerIdentityKey")
            if raw_key:
                return {
                    "publicKey": raw_key,
                    "keyFingerprint": pk.get("fingerprint") or pk.get("peerKeyFingerprint"),
                    "keyEpoch": pk.get("keyEpoch") if pk.get("keyEpoch") is not None else pk.get("peerKeyEpoch"),
                }
        except Exception:
            pass

        try:
            conns = self.connections()
            conn = next((c for c in conns if normalize_agent_id(getattr(c, "agentId", None)) == norm_target), None)
            if conn:
                cid_quoted = urllib.parse.quote(conn.connectionId.strip(), safe='')
                pk_res = self.http.request("GET", f"/connections/{cid_quoted}/peer-key", auth=True)
                pk_data = pk_res.get("data", {}) if isinstance(pk_res, dict) else pk_res
                raw_key = pk_data.get("peerE2eePublicKey") or pk_data.get("peerIdentityKey")
                if raw_key:
                    return {
                        "publicKey": raw_key,
                        "keyFingerprint": pk_data.get("peerKeyFingerprint"),
                        "keyEpoch": pk_data.get("peerKeyEpoch"),
                    }
        except Exception:
            pass

        return None

    def distribute_cluster_key(
        self,
        cluster_id: str,
        recipients: Optional[List[str]] = None,
        epoch: int = 1,
        recipient_public_keys: Optional[Dict[str, Any]] = None,
        audience_hash: Optional[str] = None,
        roster_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate, wrap, and distribute cluster symmetric keys to all required recipients (Workflow 2).
        """
        auth_agent_id = (self.http.agent_id or "me").strip()
        master_id = self.resolve_master_agent_id()

        cluster_members: List[ClusterMember] = []
        try:
            cluster_members = self.get_cluster_members(cluster_id)
        except Exception:
            try:
                cl = self.get_cluster(cluster_id)
                if cl.members:
                    cluster_members = [
                        ClusterMember(agentId=m) if isinstance(m, str) else m
                        for m in cl.members
                    ]
            except Exception:
                pass

        active_roster_ids = canonical_member_set(
            [master_id, auth_agent_id]
            + [m.agentId for m in cluster_members]
            + (recipients or [])
        )

        final_recipients: List[str] = []
        seen_norm = set()

        def _add_unique(aid: Optional[str]) -> None:
            if not aid or not isinstance(aid, str) or not aid.strip():
                return
            norm = normalize_agent_id(aid)
            if norm not in seen_norm:
                seen_norm.add(norm)
                final_recipients.append(aid.strip())

        _add_unique(master_id)
        _add_unique(auth_agent_id)
        if recipients:
            for r in recipients:
                _add_unique(r)
        else:
            for m in cluster_members:
                _add_unique(m.agentId)

        resolved_roster_hash = roster_hash or compute_roster_hash(active_roster_ids)
        resolved_audience_hash = audience_hash or compute_audience_hash(final_recipients, active_roster_ids)

        cluster_key = generate_cluster_key()
        key_fingerprint = compute_group_key_fingerprint(cluster_key)
        sender_priv = get_local_identity_key(auth_agent_id, epoch=epoch if epoch > 1 else None)
        sender_pub = export_public_key_jwk(sender_priv.public_key())
        sender_pub_fp = compute_key_fingerprint(sender_pub)

        key_packages = []
        for r_id in final_recipients:
            r_pub = None
            r_fp = None
            r_epoch = None

            if normalize_agent_id(r_id) == normalize_agent_id(auth_agent_id) and not (recipient_public_keys or {}).get(r_id):
                r_pub = sender_pub
                r_fp = sender_pub_fp
                r_epoch = epoch
            else:
                resolved_mat = self._resolve_recipient_key_material(r_id, cluster_members, recipient_public_keys)
                if resolved_mat:
                    r_pub = resolved_mat["publicKey"]
                    r_fp = resolved_mat.get("keyFingerprint")
                    r_epoch = resolved_mat.get("keyEpoch")

            if not r_pub:
                raise AamarvaError(
                    f'Recipient "{r_id}" does not have a registered public key for cluster encryption.',
                    code="RECIPIENT_KEY_MISSING",
                )

            wrapped = wrap_cluster_key_for_recipient(
                cluster_key,
                r_pub,
                sender_priv,
                cluster_id=cluster_id,
                epoch=epoch,
                audience_hash=resolved_audience_hash,
                roster_hash=resolved_roster_hash,
                key_fingerprint=key_fingerprint,
                sender_agent_id=auth_agent_id,
                sender_public_key=sender_pub,
                recipient_agent_id=r_id,
                recipient_key_fingerprint=r_fp,
                recipient_key_epoch=r_epoch,
            )
            key_packages.append({
                "recipientAgentId": r_id,
                "encryptedKeyPackage": wrapped["encryptedKeyPackage"],
                "nonce": wrapped["nonce"],
                "keyFingerprint": key_fingerprint,
                "wrappingParams": wrapped["wrappingParams"],
            })

        self.submit_cluster_key_distribution(cluster_id, {
            "epoch": epoch,
            "audienceHash": resolved_audience_hash,
            "rosterHash": resolved_roster_hash,
            "keyFingerprint": key_fingerprint,
            "senderAgentId": auth_agent_id,
            "keyPackages": key_packages,
        })

        self.cluster_key_cache[self._cluster_cache_key(cluster_id, epoch, resolved_audience_hash)] = {
            "key": cluster_key,
            "keyFingerprint": key_fingerprint,
            "rosterHash": resolved_roster_hash,
            "audienceHash": resolved_audience_hash,
            "epoch": epoch,
        }
        return {
            "epoch": epoch,
            "clusterKey": cluster_key,
            "keyFingerprint": key_fingerprint,
            "rosterHash": resolved_roster_hash,
            "audienceHash": resolved_audience_hash,
            "recipients": final_recipients,
        }

    def get_cluster_key_distribution(
        self,
        cluster_id: str,
        epoch: Optional[int] = None,
        audience_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve the encrypted group key package for the authenticated caller.
        Maps to GET /api/clusters/:cluster_id/key-distribution
        """
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")

        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        params: Dict[str, Any] = {}
        if epoch is not None:
            params["epoch"] = epoch
        if audience_hash is not None and str(audience_hash).strip():
            params["audienceHash"] = str(audience_hash).strip()

        res = self.http.request("GET", f"/clusters/{cid_quoted}/key-distribution", auth=True, params=params if params else None)
        data = res.get("data", {}) if isinstance(res, dict) and "data" in res else res
        return data if isinstance(data, dict) else {}

    def _get_cluster_key_entry(
        self,
        cluster_id: str,
        epoch: int = 1,
        audience_hash: str = "ALL",
        sender_public_key: Optional[Any] = None,
        expected_key_fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        requested_audience = audience_hash or "ALL"
        cache_key = self._cluster_cache_key(cluster_id, epoch, requested_audience)
        if cache_key in self.cluster_key_cache:
            cached = self.cluster_key_cache[cache_key]
            if isinstance(cached, bytes):
                return {
                    "key": cached,
                    "keyFingerprint": compute_group_key_fingerprint(cached),
                    "audienceHash": requested_audience,
                    "epoch": epoch,
                }
            return cached

        dist = self.get_cluster_key_distribution(
            cluster_id,
            epoch=epoch,
            audience_hash=audience_hash if audience_hash and audience_hash != "ALL" else None,
        )
        if not dist or not dist.get("encryptedKeyPackage"):
            raise AamarvaError(
                f'No cluster key package available for cluster "{cluster_id}" at epoch {epoch}.',
                code="CLUSTER_KEY_MISSING",
            )

        raw_pkg = dist["encryptedKeyPackage"]
        pkg_obj: Optional[Dict[str, Any]] = None
        if isinstance(raw_pkg, dict):
            pkg_obj = raw_pkg
        elif isinstance(raw_pkg, str) and raw_pkg.strip().startswith("{"):
            try:
                pkg_obj = json.loads(raw_pkg)
            except Exception:
                pkg_obj = None

        auth_agent_id = (self.http.agent_id or "me").strip()
        target_epoch = dist.get("recipientKeyEpoch")
        local_priv = get_local_identity_key(
            auth_agent_id,
            epoch=int(target_epoch) if target_epoch is not None else (epoch if epoch > 1 else None),
        )

        sender_pub = sender_public_key or dist.get("senderPublicKey") or (pkg_obj or {}).get("senderPublicKey")
        resolved_sender_id = dist.get("senderAgentId") or (pkg_obj or {}).get("senderAgentId")

        if not sender_pub and resolved_sender_id:
            if normalize_agent_id(resolved_sender_id) == normalize_agent_id(auth_agent_id):
                sender_pub = export_public_key_jwk(local_priv.public_key())
            else:
                try:
                    members = self.get_cluster_members(cluster_id)
                    match = next((m for m in members if normalize_agent_id(m.agentId) == normalize_agent_id(resolved_sender_id)), None)
                    if match and match.publicKey:
                        sender_pub = match.publicKey
                except Exception:
                    pass
                if not sender_pub:
                    try:
                        pk = self.get_peer_key_by_agent(resolved_sender_id)
                        sender_pub = pk.get("publicKey") or pk.get("peerE2eePublicKey") or pk.get("peerIdentityKey")
                    except Exception:
                        pass
                if not sender_pub:
                    try:
                        conns = self.connections()
                        conn = next((c for c in conns if normalize_agent_id(getattr(c, 'agentId', None)) == normalize_agent_id(resolved_sender_id)), None)
                        if conn:
                            cid_quoted = urllib.parse.quote(conn.connectionId.strip(), safe='')
                            pk_res = self.http.request("GET", f"/connections/{cid_quoted}/peer-key", auth=True)
                            pk_data = pk_res.get("data", {}) if isinstance(pk_res, dict) else pk_res
                            sender_pub = pk_data.get("peerE2eePublicKey") or pk_data.get("peerIdentityKey")
                    except Exception:
                        pass

        if not sender_pub:
            raise AamarvaError(
                f'Unable to unwrap cluster key: missing sender public key for "{resolved_sender_id or "unknown"}".',
                code="CLUSTER_KEY_UNWRAP_FAILED",
            )

        resolved_audience = str(dist.get("audienceHash") or (pkg_obj or {}).get("audienceHash") or requested_audience or "ALL")
        resolved_expected_fp = expected_key_fingerprint or dist.get("keyFingerprint") or (pkg_obj or {}).get("keyFingerprint")
        nonce = str(dist.get("nonce") or (pkg_obj or {}).get("iv") or (dist.get("wrappingParams") or {}).get("nonce") or "")

        try:
            cluster_key = unwrap_cluster_key(
                raw_pkg,
                nonce,
                local_priv,
                sender_pub,
                cluster_id=cluster_id,
                epoch=epoch,
                audience_hash=resolved_audience,
                expected_key_fingerprint=resolved_expected_fp,
            )
        except Exception as err:
            if dist.get("recipientKeyMismatch"):
                raise AamarvaError(
                    f'Cluster key unwrapping failed due to recipient key mismatch (expected fingerprint: {dist.get("recipientKeyFingerprint") or "unknown"}).',
                    code="RECIPIENT_KEY_MISMATCH",
                ) from err
            raise err

        entry = {
            "key": cluster_key,
            "keyFingerprint": resolved_expected_fp or compute_group_key_fingerprint(cluster_key),
            "rosterHash": dist.get("rosterHash") or (pkg_obj or {}).get("rosterHash"),
            "audienceHash": resolved_audience,
            "epoch": epoch,
        }
        self.cluster_key_cache[self._cluster_cache_key(cluster_id, epoch, resolved_audience)] = entry
        return entry

    def get_cluster_key(
        self,
        cluster_id: str,
        epoch: int = 1,
        sender_public_key: Optional[Any] = None,
        audience_hash: str = "ALL",
        expected_key_fingerprint: Optional[str] = None,
    ) -> bytes:
        """
        Retrieve and locally decrypt symmetric cluster key for the given epoch and audience scope.
        """
        return self._get_cluster_key_entry(
            cluster_id,
            epoch=epoch,
            audience_hash=audience_hash,
            sender_public_key=sender_public_key,
            expected_key_fingerprint=expected_key_fingerprint,
        )["key"]

    def send_encrypted_cluster_message(
        self,
        cluster_id: str,
        plaintext: str,
        recipients: Optional[List[str]] = None,
        epoch: Optional[int] = None,
        recipient_public_keys: Optional[Dict[str, Any]] = None,
        audience_hash: Optional[str] = None,
        roster_hash: Optional[str] = None,
        sequence: Optional[Union[str, int]] = None,
        auto_rotate: bool = True,
    ) -> Dict[str, Any]:
        """
        Encrypt and broadcast a cluster message using Workflow 2 (protocol v2, audience scoping,
        ECDSA IEEE P1363 envelope signature, strictPreflight, and 409 epoch race adoption).
        """
        cluster: Optional[Cluster] = None
        try:
            cluster = self.get_cluster(cluster_id)
        except Exception:
            cluster = None

        resolved_epoch = epoch or (cluster.epoch if cluster and cluster.epoch else None) or (cluster.keyEpoch if cluster and cluster.keyEpoch else None) or 1

        if cluster and cluster.rotationStatus and str(cluster.rotationStatus).startswith("ROTATION_REQUIRED"):
            if not auto_rotate:
                raise AamarvaError(
                    f"Cluster key rotation required before sending: {cluster.rotationStatus}",
                    code="CLUSTER_ROTATION_REQUIRED",
                )
            rotated = self.rotate_cluster_key(cluster_id, current_epoch=resolved_epoch)
            resolved_epoch = int(rotated.get("epoch") or resolved_epoch + 1)

        cluster_members: List[ClusterMember] = []
        try:
            cluster_members = self.get_cluster_members(cluster_id)
        except Exception:
            if cluster and cluster.members:
                cluster_members = [
                    ClusterMember(agentId=m) if isinstance(m, str) else m
                    for m in cluster.members
                ]

        master_id = self.resolve_master_agent_id()
        sender_id = (self.http.agent_id or "").strip()

        active_roster_ids = canonical_member_set(
            [master_id, sender_id]
            + [m.agentId for m in cluster_members]
            + (recipients or [])
        )

        targeted_raw = ([master_id, sender_id] + list(recipients)) if recipients else active_roster_ids
        all_recipients: List[str] = []
        seen_norm = set()
        for r in targeted_raw:
            if r and isinstance(r, str) and r.strip():
                norm = normalize_agent_id(r)
                if norm not in seen_norm:
                    seen_norm.add(norm)
                    all_recipients.append(r.strip())

        resolved_roster_hash = roster_hash or (cluster.rosterHash if cluster else None) or compute_roster_hash(active_roster_ids)
        resolved_audience_hash = audience_hash or compute_audience_hash(all_recipients, active_roster_ids)

        try:
            key_entry = self._get_cluster_key_entry(cluster_id, epoch=resolved_epoch, audience_hash=resolved_audience_hash)
        except Exception:
            try:
                dist = self.distribute_cluster_key(
                    cluster_id,
                    recipients=all_recipients,
                    epoch=resolved_epoch,
                    recipient_public_keys=recipient_public_keys,
                    audience_hash=resolved_audience_hash,
                    roster_hash=resolved_roster_hash,
                )
                key_entry = {
                    "key": dist["clusterKey"],
                    "keyFingerprint": dist["keyFingerprint"],
                    "rosterHash": dist["rosterHash"],
                    "audienceHash": dist["audienceHash"],
                    "epoch": dist["epoch"],
                }
            except Exception as dist_err:
                status_code = getattr(dist_err, "status_code", None)
                err_text = f"{getattr(dist_err, 'code', '')} {str(dist_err)}"
                if status_code == 409 or "EPOCH_KEY_ALREADY_SEALED" in err_text or "ALREADY_SEALED" in err_text:
                    key_entry = self._get_cluster_key_entry(cluster_id, epoch=resolved_epoch, audience_hash=resolved_audience_hash)
                else:
                    raise dist_err

        key_fingerprint = key_entry.get("keyFingerprint") or compute_group_key_fingerprint(key_entry["key"])
        enc = encrypt_cluster_message(
            plaintext,
            key_entry["key"],
            cluster_id,
            epoch=resolved_epoch,
            audience_hash=resolved_audience_hash,
            sender_agent_id=sender_id,
        )

        sender_priv = get_local_identity_key(sender_id or "me", epoch=resolved_epoch if resolved_epoch > 1 else None)
        signature = sign_cluster_message_v2(
            sender_priv,
            cluster_id=cluster_id,
            key_epoch=resolved_epoch,
            sender_agent_id=sender_id,
            audience_hash=resolved_audience_hash,
            roster_hash=resolved_roster_hash,
            sequence="" if sequence is None else sequence,
            key_fingerprint=key_fingerprint,
            nonce=enc["nonce"],
            ciphertext=enc["ciphertext"],
        )

        res = self.send_cluster_message(
            cluster_id,
            ciphertext=enc["ciphertext"],
            nonce=enc["nonce"],
            version=2,
            key_epoch=resolved_epoch,
            recipients=all_recipients,
            audience_hash=resolved_audience_hash,
            roster_hash=resolved_roster_hash,
            key_fingerprint=key_fingerprint,
            signature=signature,
            strict_preflight=True,
            sequence=sequence,
            recipient_agent_ids=all_recipients,
        )

        res_data = res.get("data", {}) if isinstance(res, dict) and isinstance(res.get("data"), dict) else res
        msg_id = str((res_data if isinstance(res_data, dict) else {}).get("messageId") or (res if isinstance(res, dict) else {}).get("messageId") or (res_data if isinstance(res_data, dict) else {}).get("id") or "msg_cluster")
        return {
            "messageId": msg_id,
            "version": 2,
            "keyEpoch": resolved_epoch,
            "audienceHash": resolved_audience_hash,
            "rosterHash": resolved_roster_hash,
            "keyFingerprint": key_fingerprint,
            "signature": signature,
            "recipients": all_recipients,
            "ciphertext": enc["ciphertext"],
            "nonce": enc["nonce"],
            "senderAgentId": sender_id,
        }

    def decrypt_cluster_message(
        self,
        cluster_id: str,
        message: Dict[str, Any],
        sender_public_key: Optional[Any] = None,
        verify_signature: Optional[bool] = None,
    ) -> str:
        """
        Decrypt an encrypted cluster message using the cluster symmetric key (Workflow 2).
        """
        epoch = int(message.get("keyEpoch") or 1)
        version = int(message.get("version") if message.get("version") is not None else 2)
        audience_hash = str(message.get("audienceHash") or "ALL")
        should_verify = (
            verify_signature is True
            or (verify_signature is not False and bool(sender_public_key and message.get("signature")))
        )

        resolved_sender_pub = sender_public_key
        if should_verify and message.get("signature") and message.get("rosterHash") and message.get("keyFingerprint"):
            sender_id = str(message.get("senderAgentId") or "").strip()
            if not resolved_sender_pub and sender_id:
                my_agent_id = (self.http.agent_id or "").strip()
                if my_agent_id and normalize_agent_id(sender_id) == normalize_agent_id(my_agent_id):
                    resolved_sender_pub = export_public_key_jwk(
                        get_local_identity_key(my_agent_id, epoch=epoch if epoch > 1 else None).public_key()
                    )
                else:
                    try:
                        members = self.get_cluster_members(cluster_id)
                        match = next((m for m in members if normalize_agent_id(m.agentId) == normalize_agent_id(sender_id)), None)
                        if match:
                            resolved_sender_pub = match.publicKey or match.identityKey
                    except Exception:
                        pass
                    if not resolved_sender_pub:
                        try:
                            pk = self.get_peer_key_by_agent(sender_id)
                            resolved_sender_pub = pk.get("publicKey") or pk.get("peerE2eePublicKey")
                        except Exception:
                            pass
            if not resolved_sender_pub:
                raise AamarvaError("Unable to verify cluster message signature: sender public key unavailable.", code="CLUSTER_SIGNATURE_INVALID")
            ok = verify_cluster_message_signature_v2(
                resolved_sender_pub,
                cluster_id=cluster_id,
                key_epoch=epoch,
                sender_agent_id=sender_id,
                audience_hash=audience_hash,
                roster_hash=str(message.get("rosterHash")),
                sequence="" if message.get("sequence") is None else message.get("sequence"),
                key_fingerprint=str(message.get("keyFingerprint")),
                nonce=str(message["nonce"]),
                ciphertext=str(message["ciphertext"]),
                signature_b64=str(message["signature"]),
            )
            if not ok:
                raise AamarvaError("Cluster message ECDSA signature verification failed.", code="CLUSTER_SIGNATURE_INVALID")

        cluster_key = self.get_cluster_key(
            cluster_id,
            epoch=epoch,
            sender_public_key=resolved_sender_pub or sender_public_key,
            audience_hash=audience_hash,
            expected_key_fingerprint=message.get("keyFingerprint"),
        )
        return decrypt_cluster_message(
            message["ciphertext"],
            message["nonce"],
            cluster_key,
            cluster_id,
            epoch=epoch,
            version=version,
            audience_hash=audience_hash,
            sender_agent_id=message.get("senderAgentId"),
        )


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
    def _floor_scope_key(self, tool_id: str) -> str:
        auth_agent = (self.http.agent_id or "").strip().upper()
        target_agent = (self.http.target_agent_id or "").strip().upper()
        return f"{auth_agent}::{target_agent}::{tool_id.strip()}"

    def get_floor_tools(self) -> List[FloorTool]:
        res = self.http.request("GET", "/floor/agent/tools", auth=True)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        return [normalize_floor_tool(t) for t in data]

    def create_floor_invocation(
        self,
        tool_id: str,
        reason: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request / create an invocation for a FLOOR tool.
        Maps to POST /api/floor/tools/:tool_id/invoke
        """
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")

        clean_tool_id = tool_id.strip()
        tid_quoted = urllib.parse.quote(clean_tool_id, safe='')
        body = {
            "reason": reason or "Agent requested tool invocation",
            "arguments": arguments or {},
        }
        try:
            res = self.http.request("POST", f"/floor/tools/{tid_quoted}/invoke", auth=True, json_data=body)
        except Exception as err:
            if getattr(err, "status_code", None) == 403:
                raise AamarvaError(
                    f'Agent access to tool "{clean_tool_id}" was denied.',
                    code="FLOOR_ACCESS_DENIED",
                    status_code=403,
                )
            raise err

        res_dict = res if isinstance(res, dict) else {}
        data = (res_dict.get("data", {}) if isinstance(res_dict.get("data"), dict) else res_dict) or {}
        status = str(data.get("status") or res_dict.get("status") or "pending").strip().lower()
        req_id = str(data.get("requestId") or res_dict.get("requestId") or data.get("invocationId") or "").strip() or None
        inv_id = str(data.get("invocationId") or data.get("id") or req_id or "").strip()

        if status == "pending" and req_id:
            self._pending_floor_requests[self._floor_scope_key(clean_tool_id)] = req_id

        return {
            "invocationId": inv_id,
            "requestId": req_id,
            "toolId": str(data.get("toolId") or clean_tool_id).strip(),
            "status": status,
            "message": res_dict.get("message") or data.get("message"),
        }

    def wait_for_floor_approval(
        self,
        request_id: str,
        poll_interval_ms: int = 1000,
        timeout_ms: int = 30000,
        tool_id: Optional[str] = None,
    ) -> FloorAccessRequestStatus:
        """
        Poll a pending FLOOR approval request until a terminal decision is returned.
        Maps to GET /api/floor/requests/:request_id
        """
        if not request_id or not request_id.strip():
            raise AamarvaValidationError("request_id is required")

        req_id = request_id.strip()
        interval_sec = max(5, poll_interval_ms) / 1000.0
        timeout_sec = max(interval_sec, timeout_ms / 1000.0)
        deadline = time.monotonic() + timeout_sec

        while True:
            status_res = self.get_floor_request_status(req_id)
            st = (status_res.status or "pending").strip().lower()

            if st == "approved":
                if not status_res.invocationId:
                    raise AamarvaError(
                        f'FLOOR approval response for request "{req_id}" omitted required invocationId.',
                        code="FLOOR_EXECUTION_FAILED",
                    )
                return status_res

            if st in ["denied", "rejected", "revoked", "expired"]:
                details: Dict[str, Any] = {"requestId": req_id, "status": st}
                if tool_id:
                    details["toolId"] = tool_id
                raise AamarvaError(
                    f"FLOOR tool access request {req_id} was {st}.",
                    code="FLOOR_ACCESS_DENIED",
                    details=details,
                )

            if st != "pending":
                raise AamarvaError(
                    f'FLOOR access request {req_id} returned unexpected status "{st}".',
                    code="FLOOR_EXECUTION_FAILED",
                )

            now = time.monotonic()
            if now >= deadline:
                details = {"requestId": req_id, "status": "pending"}
                if tool_id:
                    details["toolId"] = tool_id
                raise AamarvaError(
                    f"Agent is not authorized yet. Access request {req_id} is still pending human approval.",
                    code="FLOOR_ACCESS_DENIED",
                    details=details,
                )

            time.sleep(min(interval_sec, max(0.001, deadline - now)))

    def obtain_floor_execution_authorization(
        self,
        invocation_id: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Obtain execution authorization for a FLOOR invocation.
        Maps to POST /api/floor/invocations/:invocation_id/execute
        """
        if not invocation_id or not invocation_id.strip():
            raise AamarvaValidationError("invocation_id is required")

        expected_iid = invocation_id.strip()
        submitted_args = arguments or {}
        iid_quoted = urllib.parse.quote(expected_iid, safe='')
        body = {
            "arguments": submitted_args,
        }
        try:
            res = self.http.request("POST", f"/floor/invocations/{iid_quoted}/execute", auth=True, json_data=body)
        except Exception as err:
            if getattr(err, "status_code", None) == 403:
                raise AamarvaError(
                    "FLOOR execution authorization denied by platform.",
                    code="FLOOR_ACCESS_DENIED",
                    status_code=403,
                )
            raise err

        if not isinstance(res, dict):
            raise AamarvaError("FLOOR authorization failed: response payload is not an object.", code="FLOOR_EXECUTION_FAILED")

        if res.get("success") is False:
            raise AamarvaError("FLOOR execution authorization was rejected by platform.", code="FLOOR_ACCESS_DENIED")

        data = res.get("data")
        if not isinstance(data, dict):
            raise AamarvaError("FLOOR authorization failed: malformed authorization payload.", code="FLOOR_EXECUTION_FAILED")

        raw_status = str(data.get("status") or res.get("status") or "").strip().lower()

        if raw_status in ["denied", "rejected", "revoked", "expired", "unassigned", "pending"]:
            raise AamarvaError(
                f"FLOOR execution authorization denied: status is '{raw_status}'.",
                code="FLOOR_ACCESS_DENIED",
            )

        if raw_status != "approved":
            raise AamarvaError(
                f"FLOOR authorization failed: expected status 'approved', got '{raw_status}'.",
                code="FLOOR_EXECUTION_FAILED",
            )

        raw_iid = data.get("invocationId")
        returned_iid = raw_iid.strip() if isinstance(raw_iid, str) else ""
        if not returned_iid or returned_iid != expected_iid:
            raise AamarvaError("FLOOR authorization failed: invocation ID missing or mismatched in platform response.", code="FLOOR_EXECUTION_FAILED")

        tool_obj = data.get("tool")
        returned_tool_id = ""
        if isinstance(data.get("toolId"), str) and data["toolId"].strip():
            returned_tool_id = data["toolId"].strip()
        elif isinstance(tool_obj, dict) and isinstance(tool_obj.get("id"), str) and tool_obj["id"].strip():
            returned_tool_id = tool_obj["id"].strip()
        if not returned_tool_id:
            raise AamarvaError("FLOOR authorization failed: authorized toolId is missing in platform response.", code="FLOOR_EXECUTION_FAILED")

        server_url = data.get("serverUrl") or data.get("mcpServerUrl") or (data.get("server") or {}).get("url")
        if not server_url or not isinstance(server_url, str) or not server_url.strip():
            raise AamarvaError("FLOOR authorization failed: valid MCP serverUrl is missing in response.", code="FLOOR_EXECUTION_FAILED")
        parsed_url = urllib.parse.urlparse(server_url.strip())
        if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
            raise AamarvaError("FLOOR authorization failed: malformed or unsupported MCP serverUrl in response.", code="FLOOR_EXECUTION_FAILED")

        grant = data.get("grant")
        if not grant or not isinstance(grant, dict):
            raise AamarvaError("FLOOR authorization failed: grant details missing in response.", code="FLOOR_EXECUTION_FAILED")

        grant_status = str(grant.get("status") or "").strip().lower()
        if grant_status in ["denied", "rejected", "revoked", "expired", "inactive"]:
            raise AamarvaError(f"FLOOR authorization denied: grant status is '{grant_status}'.", code="FLOOR_ACCESS_DENIED")

        expires_raw = grant.get("expiresAt") or data.get("expiresAt")
        if isinstance(expires_raw, str) and expires_raw.strip():
            try:
                exp_str = expires_raw.strip()
                if exp_str.endswith("Z"):
                    exp_str = exp_str[:-1] + "+00:00"
                exp_dt = datetime.datetime.fromisoformat(exp_str)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
                if exp_dt <= datetime.datetime.now(datetime.timezone.utc):
                    raise AamarvaError("FLOOR authorization denied: execution grant has expired.", code="FLOOR_ACCESS_DENIED")
            except AamarvaError:
                raise
            except Exception:
                raise AamarvaError("FLOOR authorization denied: malformed grant expiration timestamp.", code="FLOOR_ACCESS_DENIED")

        expected_agent = (self.http.target_agent_id or self.http.agent_id or "").strip()
        verification_info = data.get("verificationInfo") if isinstance(data.get("verificationInfo"), dict) else {}
        returned_agent = str(data.get("agentId") or grant.get("agentId") or verification_info.get("agentId") or "").strip()
        if expected_agent and returned_agent and returned_agent.upper() != expected_agent.upper():
            raise AamarvaError("FLOOR authorization failed: agent fleet context mismatch in authorization response.", code="FLOOR_EXECUTION_FAILED")

        approved_args = None
        if isinstance(data.get("approvedArguments"), dict):
            approved_args = data["approvedArguments"]
        elif isinstance(grant.get("approvedArguments"), dict):
            approved_args = grant["approvedArguments"]
        if approved_args is not None:
            if json.dumps(approved_args, sort_keys=True) != json.dumps(submitted_args, sort_keys=True):
                raise AamarvaError("FLOOR authorization failed: execution arguments do not match approved arguments.", code="FLOOR_EXECUTION_FAILED")

        return {
            "invocationId": returned_iid,
            "toolId": returned_tool_id,
            "status": "approved",
            "serverUrl": server_url.strip(),
            "agentId": returned_agent or None,
            "expiresAt": expires_raw if isinstance(expires_raw, str) else None,
            "approvedArguments": approved_args,
            "auth": data.get("auth") or data.get("authentication") or data.get("authConfig"),
            "grant": grant,
        }

    def execute_floor_tool(
        self,
        tool_id: str,
        arguments: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        invocation_id: Optional[str] = None,
        request_id: Optional[str] = None,
        wait_for_approval: bool = False,
        poll_interval_ms: int = 1000,
        poll_timeout_ms: Optional[int] = None,
    ) -> FloorToolInvokeResult:
        """
        Execute a FLOOR tool via the platform's 5-stage zero-trust governance sequence:
        Discovery -> Access evaluation -> Approval status/polling -> Execute authorization -> External MCP invocation.
        """
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")

        clean_tool_id = tool_id.strip()
        scope_key = self._floor_scope_key(clean_tool_id)
        should_wait = bool(wait_for_approval or (poll_timeout_ms is not None and poll_timeout_ms > 0))
        effective_timeout_ms = poll_timeout_ms if poll_timeout_ms is not None and poll_timeout_ms > 0 else 30000

        # Stage 1: Tool discovery (informational only; never authorizes execution)
        tools = self.get_floor_tools()
        tool = next((t for t in tools if t.id == clean_tool_id), None)
        if not tool:
            raise AamarvaError(f'Tool "{clean_tool_id}" not found in available fleet tools.', code="FLOOR_TOOL_NOT_FOUND")

        access_status = (tool.accessStatus or "").strip().lower()
        resolved_invocation_id = invocation_id.strip() if isinstance(invocation_id, str) and invocation_id.strip() else None

        if not resolved_invocation_id and access_status in ["revoked", "denied", "rejected", "expired"]:
            self._pending_floor_requests.pop(scope_key, None)
            raise AamarvaError(
                f'Agent access to tool "{clean_tool_id}" is {access_status}.',
                code="FLOOR_ACCESS_DENIED",
            )

        # Stage 2 & 3: Access evaluation, reuse existing pending request, and optional HITL polling
        if not resolved_invocation_id:
            existing_req_id = (
                (request_id.strip() if isinstance(request_id, str) and request_id.strip() else None)
                or (tool.requestId.strip() if getattr(tool, "requestId", None) else None)
                or self._pending_floor_requests.get(scope_key)
            )

            if existing_req_id:
                if should_wait:
                    approved_status = self.wait_for_floor_approval(
                        existing_req_id,
                        poll_interval_ms=poll_interval_ms,
                        timeout_ms=effective_timeout_ms,
                        tool_id=clean_tool_id,
                    )
                    self._pending_floor_requests.pop(scope_key, None)
                    resolved_invocation_id = approved_status.invocationId
                else:
                    status_res = self.get_floor_request_status(existing_req_id)
                    req_status = (status_res.status or "pending").strip().lower()
                    if req_status == "approved":
                        self._pending_floor_requests.pop(scope_key, None)
                        if not status_res.invocationId:
                            raise AamarvaError(
                                f'FLOOR approval for request "{existing_req_id}" omitted invocationId.',
                                code="FLOOR_EXECUTION_FAILED",
                            )
                        resolved_invocation_id = status_res.invocationId
                    elif req_status == "pending":
                        raise AamarvaError(
                            f'Agent is not authorized to execute tool "{clean_tool_id}". Access request {existing_req_id} is pending human approval.',
                            code="FLOOR_ACCESS_DENIED",
                            details={"requestId": existing_req_id, "status": "pending", "toolId": clean_tool_id},
                        )
                    elif req_status in ["denied", "rejected", "revoked", "expired"]:
                        self._pending_floor_requests.pop(scope_key, None)
                        raise AamarvaError(
                            f'Agent access to tool "{clean_tool_id}" was {req_status}.',
                            code="FLOOR_ACCESS_DENIED",
                            details={"requestId": existing_req_id, "status": req_status, "toolId": clean_tool_id},
                        )
                    else:
                        raise AamarvaError(
                            f'FLOOR access request {existing_req_id} returned unexpected status "{req_status}".',
                            code="FLOOR_EXECUTION_FAILED",
                        )
            else:
                has_grant = access_status in ["authorized", "granted", "approved"]
                inv_res = self.create_floor_invocation(
                    clean_tool_id,
                    reason=reason or ("Authorized execution run" if has_grant else "Agent requested execution"),
                    arguments=arguments,
                )
                if inv_res["status"] == "pending":
                    req_id = inv_res.get("requestId") or inv_res.get("invocationId")
                    if req_id:
                        self._pending_floor_requests[scope_key] = req_id
                    if should_wait and req_id:
                        approved_status = self.wait_for_floor_approval(
                            req_id,
                            poll_interval_ms=poll_interval_ms,
                            timeout_ms=effective_timeout_ms,
                            tool_id=clean_tool_id,
                        )
                        self._pending_floor_requests.pop(scope_key, None)
                        resolved_invocation_id = approved_status.invocationId
                    else:
                        raise AamarvaError(
                            f'Agent is not authorized to execute tool "{clean_tool_id}". Access request {req_id} is pending human approval.',
                            code="FLOOR_ACCESS_DENIED",
                            details={"requestId": req_id, "status": "pending", "toolId": clean_tool_id},
                        )
                elif inv_res["status"] in ["denied", "rejected", "revoked", "expired"]:
                    raise AamarvaError(
                        f'Agent access to tool "{clean_tool_id}" was denied (status: {inv_res["status"]}).',
                        code="FLOOR_ACCESS_DENIED",
                    )
                elif inv_res["status"] not in ["approved", "authorized", "granted"]:
                    raise AamarvaError(
                        f'FLOOR invocation creation returned unexpected status "{inv_res["status"]}".',
                        code="FLOOR_EXECUTION_FAILED",
                    )
                else:
                    resolved_invocation_id = inv_res["invocationId"]

        if not resolved_invocation_id:
            raise AamarvaError("FLOOR invocation creation failed to return a valid invocationId.", code="FLOOR_EXECUTION_FAILED")

        # Stage 4: Mandatory execution authorization gate before any MCP connection
        auth_details = self.obtain_floor_execution_authorization(resolved_invocation_id, arguments=arguments)

        if auth_details["status"] != "approved":
            raise AamarvaError(f"FLOOR execution denied: status is '{auth_details['status']}'.", code="FLOOR_ACCESS_DENIED")

        if auth_details["toolId"].strip() != clean_tool_id:
            raise AamarvaError(
                f'FLOOR execution authorization mismatch: authorized tool "{auth_details["toolId"]}" does not match requested tool "{clean_tool_id}".',
                code="FLOOR_EXECUTION_FAILED",
            )

        # Stage 5: External MCP tool execution over verified connection
        mcp_result = invoke_external_mcp_tool(
            server_url=auth_details["serverUrl"],
            tool_id=clean_tool_id,
            args=arguments,
            auth=auth_details.get("auth"),
            input_schema=tool.inputSchema,
        )

        return FloorToolInvokeResult(
            status="approved",
            invocationId=resolved_invocation_id,
            toolId=clean_tool_id,
            result=mcp_result,
            serverUrl=auth_details["serverUrl"],
        )

    def request_floor_access(
        self,
        tool_id: str,
        reason: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> FloorToolInvokeResult:
        """
        Request access to a FLOOR tool without executing it.
        Reuses an existing pending request when already pending.
        Maps to POST /api/floor/tools/:tool_id/invoke
        """
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")

        clean_tool_id = tool_id.strip()
        scope_key = self._floor_scope_key(clean_tool_id)

        try:
            tools = self.get_floor_tools()
            existing = next((t for t in tools if t.id == clean_tool_id), None)
            if existing and (existing.accessStatus or "").lower() in ["authorized", "granted", "approved"]:
                return FloorToolInvokeResult(
                    status="approved",
                    toolId=clean_tool_id,
                    message="Tool access is already granted via persistent access policy.",
                )
            existing_req_id = (
                (existing.requestId.strip() if existing and getattr(existing, "requestId", None) else None)
                or self._pending_floor_requests.get(scope_key)
            )
            if existing_req_id:
                status_res = self.get_floor_request_status(existing_req_id)
                st = (status_res.status or "pending").lower()
                if st == "pending":
                    return FloorToolInvokeResult(
                        status="pending",
                        requestId=existing_req_id,
                        toolId=clean_tool_id,
                        message="Access request is already pending approval.",
                    )
                self._pending_floor_requests.pop(scope_key, None)
                if st == "approved":
                    return FloorToolInvokeResult(
                        status="approved",
                        requestId=existing_req_id,
                        invocationId=status_res.invocationId,
                        toolId=clean_tool_id,
                        message="Access request has been approved.",
                    )
        except Exception:
            pass

        inv = self.create_floor_invocation(clean_tool_id, reason=reason, arguments=arguments)
        req_id = inv.get("requestId") or inv.get("invocationId")
        if inv.get("status") == "pending" and req_id:
            self._pending_floor_requests[scope_key] = req_id
        return FloorToolInvokeResult(
            status=inv.get("status") or "pending",
            requestId=req_id,
            invocationId=inv.get("invocationId"),
            toolId=clean_tool_id,
            message=inv.get("message") or "Access request submitted for approval.",
        )

    def get_floor_request_status(self, request_id: str) -> FloorAccessRequestStatus:
        if not request_id or not request_id.strip():
            raise AamarvaValidationError("request_id is required")
        rid_quoted = urllib.parse.quote(request_id.strip(), safe='')
        res = self.http.request("GET", f"/floor/requests/{rid_quoted}", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) and "data" in res else res
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

