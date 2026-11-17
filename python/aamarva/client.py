import base64
import datetime
import json
import math
import re
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

    def _parse_positive_int_strict(self, val: Any) -> Optional[int]:
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

    def _assert_valid_audience_hash(self, audience_hash: str) -> str:
        trimmed = audience_hash.strip()
        if trimmed != "ALL" and not re.match(r"^AUD:[0-9A-F]{32}$", trimmed):
            raise AamarvaValidationError(
                'Invalid audienceHash: must be "ALL" or "AUD:<32-HEX>".',
                code="INVALID_AUDIENCE_HASH",
            )
        return trimmed

    def _assert_valid_roster_hash(self, roster_hash: str) -> str:
        trimmed = roster_hash.strip()
        if not re.match(r"^RST:[0-9A-F]{32}$", trimmed):
            raise AamarvaValidationError(
                'Invalid rosterHash: must match "RST:<32-HEX>".',
                code="INVALID_ROSTER_HASH",
            )
        return trimmed

    def _assert_valid_fingerprint(self, fp: str, code: str = "CLUSTER_KEY_FINGERPRINT_MISMATCH") -> str:
        trimmed = fp.strip()
        if not re.match(r"^SHA256:([0-9A-F]{2}:){31}[0-9A-F]{2}$", trimmed):
            raise AamarvaValidationError(
                f"Invalid SHA-256 key fingerprint format: {trimmed}",
                code=code,
            )
        return trimmed

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
        if peer_data.get("connectionId") and str(peer_data.get("connectionId")).strip() != connection_id.strip():
            raise AamarvaError("Connection ID mismatch in peer key response.", code="PEER_KEY_VERIFICATION_FAILED")

        raw_peer_key = peer_data.get("peerE2eePublicKey") or peer_data.get("e2eePublicKey") or peer_data.get("publicKey")
        peer_fp = peer_data.get("peerKeyFingerprint") or peer_data.get("keyFingerprint") or peer_data.get("fingerprint")
        peer_identity_key = peer_data.get("peerIdentityKey") or peer_data.get("identityKey")
        peer_sig = peer_data.get("peerKeySignature") or peer_data.get("signature")
        raw_peer_epoch = peer_data.get("peerKeyEpoch") if peer_data.get("peerKeyEpoch") is not None else peer_data.get("keyEpoch")
        peer_epoch = self._parse_positive_int_strict(raw_peer_epoch)
        if peer_epoch is None:
            raise AamarvaError("Missing or invalid peerKeyEpoch in peer key response.", code="PEER_KEY_VERIFICATION_FAILED")

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
            if msg.connectionId and msg.connectionId.strip() != connection_id.strip():
                raise AamarvaError("Connection ID mismatch in encrypted message envelope.", code="MESSAGE_INVALID_ENVELOPE")
            if msg.ciphertext and msg.nonce:
                try:
                    local_priv = get_local_identity_key(my_agent_id, epoch=msg.keyEpoch)
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
        result = []
        for item in raw_list:
            msg = normalize_message(item, connection_id)
            result.append({
                "ciphertext": msg.ciphertext,
                "nonce": msg.nonce,
                "version": msg.version,
                "keyEpoch": msg.keyEpoch,
            })
        return result

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
        if isinstance(raw, dict) and isinstance(raw.get("members"), list):
            raw = raw.get("members")
        if not isinstance(raw, list):
            raise AamarvaError("Malformed cluster members response.", code="CLUSTER_MEMBERSHIP_INVALID")

        members: List[ClusterMember] = []
        for item in raw:
            if isinstance(item, str) and item.strip():
                members.append(ClusterMember(agentId=item.strip()))
            elif isinstance(item, dict):
                aid = str(item.get("agentId") or item.get("agent_id") or item.get("id") or "").strip()
                if aid:
                    raw_epoch = item.get("keyEpoch") if item.get("keyEpoch") is not None else item.get("key_epoch")
                    parsed_epoch: Optional[int] = None
                    if raw_epoch is not None:
                        parsed_epoch = self._parse_positive_int_strict(raw_epoch)
                        if parsed_epoch is None:
                            raise AamarvaError(
                                f'Invalid keyEpoch for cluster member "{aid}".',
                                code="CLUSTER_MEMBERSHIP_INVALID",
                            )
                    members.append(
                        ClusterMember(
                            agentId=aid,
                            name=item.get("name"),
                            role=item.get("role"),
                            status=item.get("status"),
                            publicKey=item.get("publicKey") or item.get("e2eePublicKey") or item.get("peerE2eePublicKey"),
                            keyFingerprint=item.get("keyFingerprint") or item.get("fingerprint") or item.get("peerKeyFingerprint"),
                            keyEpoch=parsed_epoch,
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
        clean_cluster_id = cluster_id.strip()
        expected_current_epoch: Optional[int] = None
        if current_epoch is not None:
            expected_current_epoch = self._parse_positive_int_strict(current_epoch)
            if expected_current_epoch is None:
                raise AamarvaValidationError(
                    "currentEpoch must be a positive integer >= 1.",
                    code="CLUSTER_INVALID_EPOCH",
                )

        cid_quoted = urllib.parse.quote(clean_cluster_id, safe='')
        body: Dict[str, Any] = {}
        if expected_current_epoch is not None:
            body["currentEpoch"] = expected_current_epoch
        if reason is not None:
            body["reason"] = reason
        res = self.http.request("POST", f"/clusters/{cid_quoted}/rotate-key", auth=True, json_data=body)
        data = res.get("data") if isinstance(res, dict) and isinstance(res.get("data"), dict) else None
        if data is None:
            raise AamarvaError("Malformed response from cluster rotate-key endpoint.", code="CLUSTER_ROTATION_FAILED")
        if data.get("clusterId") is not None and str(data.get("clusterId")).strip() != clean_cluster_id:
            raise AamarvaError("Cluster ID mismatch in rotateClusterKey response.", code="CLUSTER_ROTATION_FAILED")

        raw_epoch = data.get("epoch") if data.get("epoch") is not None else data.get("keyEpoch")
        next_epoch = self._parse_positive_int_strict(raw_epoch)
        if next_epoch is None:
            raise AamarvaError("Missing or invalid rotated epoch in rotateClusterKey response.", code="CLUSTER_ROTATION_FAILED")
        if data.get("keyEpoch") is not None:
            parsed_ke = self._parse_positive_int_strict(data.get("keyEpoch"))
            if parsed_ke is None or parsed_ke != next_epoch:
                raise AamarvaError("Inconsistent epoch and keyEpoch in rotateClusterKey response.", code="CLUSTER_ROTATION_FAILED")
        if expected_current_epoch is not None and next_epoch <= expected_current_epoch:
            raise AamarvaError(
                f"Cluster rotation failed to advance epoch monotonically (expected > {expected_current_epoch}, got {next_epoch}).",
                code="CLUSTER_ROTATION_FAILED",
            )

        for key in list(self.cluster_key_cache.keys()):
            if key.startswith(f"{clean_cluster_id}:"):
                entry = self.cluster_key_cache.get(key)
                if not isinstance(entry, dict) or (entry.get("epoch") or 0) < next_epoch:
                    del self.cluster_key_cache[key]

        return {
            "clusterId": str(data.get("clusterId") or clean_cluster_id),
            "epoch": next_epoch,
            "keyEpoch": next_epoch,
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
                version=self._parse_positive_int_strict(item.get("version")) or 0,
                keyEpoch=self._parse_positive_int_strict(item.get("keyEpoch") if item.get("keyEpoch") is not None else item.get("key_epoch")) or 0,
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

    def _resolve_authoritative_cluster_context(
        self,
        cluster_id: str,
        recipients: Optional[List[str]] = None,
        recipient_agent_ids: Optional[List[str]] = None,
        expected_roster_hash: Optional[str] = None,
        expected_audience_hash: Optional[str] = None,
        sender_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_cluster_id = cluster_id.strip()
        auth_agent_id = (self.http.agent_id or "").strip()
        if not auth_agent_id:
            raise AamarvaValidationError(
                "Sender agent ID is required for cluster operations.",
                code="MISSING_SENDER_IDENTITY",
            )
        if sender_agent_id and normalize_agent_id(sender_agent_id) != normalize_agent_id(auth_agent_id):
            raise AamarvaValidationError(
                "Sender agent ID mismatch: caller ID does not match authenticated agent identity.",
                code="SENDER_IDENTITY_MISMATCH",
            )

        master_id = self.resolve_master_agent_id()
        if not master_id:
            raise AamarvaError("Unable to resolve owning master agent ID for cluster message.", code="MASTER_RESOLUTION_FAILED")

        cluster = self.get_cluster(clean_cluster_id)
        returned_cluster_id = str(cluster.clusterId or cluster.id or "").strip()
        if returned_cluster_id and returned_cluster_id != clean_cluster_id:
            raise AamarvaError(
                f'Cluster metadata ID mismatch: expected "{clean_cluster_id}", got "{returned_cluster_id}".',
                code="CLUSTER_CONTEXT_MISMATCH",
            )

        cluster_epoch = self._parse_positive_int_strict(cluster.epoch if cluster.epoch is not None else cluster.keyEpoch)
        if cluster_epoch is None:
            raise AamarvaError(
                f'Cluster "{clean_cluster_id}" is missing a valid positive integer epoch.',
                code="CLUSTER_INVALID_EPOCH",
            )

        cluster_members = self.get_cluster_members(clean_cluster_id)
        if not cluster_members:
            raise AamarvaError(f'Cluster "{clean_cluster_id}" has no authoritative members.', code="CLUSTER_MEMBERSHIP_INVALID")

        member_map: Dict[str, ClusterMember] = {}
        for m in cluster_members:
            norm = normalize_agent_id(m.agentId)
            if norm:
                member_map[norm] = m

        active_roster_ids = canonical_member_set([m.agentId for m in cluster_members])
        if normalize_agent_id(auth_agent_id) not in member_map:
            raise AamarvaError(
                f'Authenticated agent "{auth_agent_id}" is not an authoritative member of cluster "{clean_cluster_id}".',
                code="CLUSTER_MEMBERSHIP_INVALID",
            )
        if normalize_agent_id(master_id) not in member_map:
            raise AamarvaError(
                f'Owning master agent "{master_id}" is not an authoritative member of cluster "{clean_cluster_id}".',
                code="CLUSTER_MEMBERSHIP_INVALID",
            )

        def _validate_rec_list(lst: Optional[List[str]]) -> None:
            if not lst:
                return
            for r in lst:
                if not isinstance(r, str) or not r.strip():
                    raise AamarvaValidationError("Invalid recipient ID in cluster message.", code="INVALID_RECIPIENT_ID")
                if normalize_agent_id(r) not in member_map:
                    raise AamarvaError(
                        f'Requested recipient "{r.strip()}" is not an authoritative member of cluster "{clean_cluster_id}".',
                        code="CLUSTER_MEMBERSHIP_INVALID",
                    )

        _validate_rec_list(recipients)
        _validate_rec_list(recipient_agent_ids)

        if recipients is not None and recipient_agent_ids is not None:
            if canonical_member_set(recipients) != canonical_member_set(recipient_agent_ids):
                raise AamarvaValidationError("Conflicting recipients and recipientAgentIds lists.", code="CLUSTER_MEMBERSHIP_INVALID")

        roster_hash = compute_roster_hash(active_roster_ids)
        if cluster.rosterHash and cluster.rosterHash != roster_hash:
            raise AamarvaError(
                f"Cluster rosterHash mismatch: metadata has {cluster.rosterHash}, authoritative members compute {roster_hash}.",
                code="ROSTER_HASH_MISMATCH",
            )
        if expected_roster_hash is not None:
            clean_exp_roster = self._assert_valid_roster_hash(expected_roster_hash)
            if clean_exp_roster != roster_hash:
                raise AamarvaValidationError(
                    f"Caller rosterHash mismatch: expected {roster_hash}, got {clean_exp_roster}.",
                    code="ROSTER_HASH_MISMATCH",
                )

        requested = recipients if (recipients and len(recipients) > 0) else (recipient_agent_ids if (recipient_agent_ids and len(recipient_agent_ids) > 0) else None)
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
        if requested:
            for r in requested:
                _add_unique(r)
        else:
            for m in cluster_members:
                _add_unique(m.agentId)

        audience_hash = compute_audience_hash(final_recipients, active_roster_ids)
        if expected_audience_hash is not None:
            clean_exp_aud = self._assert_valid_audience_hash(expected_audience_hash)
            if clean_exp_aud != audience_hash:
                raise AamarvaValidationError(
                    f"Caller audienceHash mismatch: expected {audience_hash}, got {clean_exp_aud}.",
                    code="AUDIENCE_HASH_MISMATCH",
                )

        return {
            "cluster": cluster,
            "clusterEpoch": cluster_epoch,
            "clusterMembers": cluster_members,
            "memberMap": member_map,
            "activeRosterIds": active_roster_ids,
            "rosterHash": roster_hash,
            "audienceHash": audience_hash,
            "finalRecipients": final_recipients,
            "masterId": master_id,
            "senderId": auth_agent_id,
        }

    def _post_verified_cluster_message(self, cluster_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe='')
        return self.http.request("POST", f"/clusters/{cid_quoted}/messages", auth=True, json_data=payload)

    def send_cluster_message(
        self,
        cluster_id: str,
        ciphertext: str,
        nonce: str,
        version: int = 2,
        key_epoch: Optional[int] = None,
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

        parsed_epoch = self._parse_positive_int_strict(key_epoch)
        if parsed_epoch is None:
            raise AamarvaValidationError(
                "Cluster messages require explicit keyEpoch as an integer >= 1.",
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

        if strict_preflight is not True:
            raise AamarvaValidationError(
                "Cluster messages require strictPreflight=True.",
                code="STRICT_PREFLIGHT_REQUIRED",
            )

        if not audience_hash or not isinstance(audience_hash, str):
            raise AamarvaValidationError(
                "audienceHash is required for Workflow 2 cluster messages.",
                code="INVALID_AUDIENCE_HASH",
            )
        clean_audience_hash = self._assert_valid_audience_hash(audience_hash)

        if not roster_hash or not isinstance(roster_hash, str):
            raise AamarvaValidationError(
                "rosterHash is required for Workflow 2 cluster messages.",
                code="INVALID_ROSTER_HASH",
            )
        clean_roster_hash = self._assert_valid_roster_hash(roster_hash)

        if not key_fingerprint or not isinstance(key_fingerprint, str):
            raise AamarvaValidationError(
                "keyFingerprint is required for Workflow 2 cluster messages.",
                code="CLUSTER_KEY_FINGERPRINT_MISMATCH",
            )
        clean_key_fingerprint = self._assert_valid_fingerprint(key_fingerprint)

        if not signature or not isinstance(signature, str) or not signature.strip():
            raise AamarvaValidationError(
                "ECDSA v2 signature is required for Workflow 2 cluster messages.",
                code="CLUSTER_SIGNATURE_INVALID",
            )
        try:
            sig_bytes = base64.b64decode(signature.encode("ascii"), validate=True)
        except Exception:
            sig_bytes = b""
        if len(sig_bytes) != 64:
            raise AamarvaValidationError(
                "Cluster message signature must be a 64-byte IEEE P1363 Base64 string.",
                code="CLUSTER_SIGNATURE_INVALID",
            )

        raw_recipients = recipients or []
        for r in raw_recipients:
            if not isinstance(r, str) or not r.strip():
                raise AamarvaValidationError("Invalid recipient ID in cluster message.", code="INVALID_RECIPIENT_ID")

        if recipient_agent_ids:
            for r in recipient_agent_ids:
                if not isinstance(r, str) or not r.strip():
                    raise AamarvaValidationError("Invalid recipient ID in cluster message.", code="INVALID_RECIPIENT_ID")

        auth_agent_id = self.http.agent_id
        if sender_agent_id:
            if not auth_agent_id or sender_agent_id.strip().upper() != auth_agent_id.strip().upper():
                raise AamarvaValidationError(
                    "Sender agent ID mismatch: caller ID does not match authenticated agent identity.",
                    code="SENDER_IDENTITY_MISMATCH",
                )

        if not ((sender_agent_id or auth_agent_id or "").strip()):
            raise AamarvaValidationError("Sender agent ID is required for cluster messages.", code="MISSING_SENDER_IDENTITY")

        ctx = self._resolve_authoritative_cluster_context(
            cluster_id,
            recipients=recipients,
            recipient_agent_ids=recipient_agent_ids,
            expected_roster_hash=clean_roster_hash,
            expected_audience_hash=clean_audience_hash,
            sender_agent_id=sender_agent_id,
        )

        if ctx["cluster"].rotationStatus and str(ctx["cluster"].rotationStatus).startswith("ROTATION_REQUIRED"):
            raise AamarvaError(
                f"Cluster key rotation required before sending: {ctx['cluster'].rotationStatus}",
                code="CLUSTER_ROTATION_REQUIRED",
            )
        if parsed_epoch != ctx["clusterEpoch"]:
            raise AamarvaError(
                f"Cluster keyEpoch mismatch: active cluster epoch is {ctx['clusterEpoch']}, got {parsed_epoch}.",
                code="CLUSTER_INVALID_EPOCH",
            )

        sender_member = ctx["memberMap"].get(normalize_agent_id(ctx["senderId"]))
        sender_pub_key = (sender_member.publicKey or sender_member.identityKey) if sender_member else None
        if sender_member and sender_member.publicKey and sender_member.keyFingerprint:
            if compute_key_fingerprint(export_public_key_jwk(sender_member.publicKey)) != sender_member.keyFingerprint:
                raise AamarvaError("Authoritative sender member key fingerprint mismatch.", code="CLUSTER_SIGNATURE_INVALID")
        if not sender_pub_key:
            sender_pub_key = export_public_key_jwk(
                get_local_identity_key(ctx["senderId"], epoch=sender_member.keyEpoch if sender_member else None).public_key()
            )

        sig_ok = verify_cluster_message_signature_v2(
            sender_pub_key,
            cluster_id=cluster_id.strip(),
            key_epoch=parsed_epoch,
            sender_agent_id=ctx["senderId"],
            audience_hash=ctx["audienceHash"],
            roster_hash=ctx["rosterHash"],
            sequence="" if sequence is None else sequence,
            key_fingerprint=clean_key_fingerprint,
            nonce=nonce,
            ciphertext=ciphertext,
            signature_b64=signature,
        )
        if not sig_ok:
            raise AamarvaError("Cluster message ECDSA v2 signature verification failed.", code="CLUSTER_SIGNATURE_INVALID")

        payload: Dict[str, Any] = {
            "senderAgentId": ctx["senderId"],
            "ciphertext": ciphertext,
            "nonce": nonce,
            "version": 2,
            "keyEpoch": parsed_epoch,
            "recipients": ctx["finalRecipients"],
            "recipientAgentIds": ctx["finalRecipients"],
            "audienceHash": ctx["audienceHash"],
            "rosterHash": ctx["rosterHash"],
            "keyFingerprint": clean_key_fingerprint,
            "signature": signature,
            "strictPreflight": True,
        }
        if sequence is not None:
            payload["sequence"] = sequence

        return self._post_verified_cluster_message(cluster_id, payload)

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

    def _resolve_authoritative_member_key(
        self,
        agent_id: str,
        member: ClusterMember,
        explicit_keys: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        norm_target = normalize_agent_id(agent_id)
        resolved_key = member.publicKey
        resolved_fp = member.keyFingerprint
        resolved_epoch = member.keyEpoch

        if resolved_key and member.identityKey and member.keySignature and resolved_fp:
            verify_peer_key(resolved_key, resolved_fp, agent_id, member.keySignature, member.identityKey)
        elif resolved_key and resolved_fp:
            if compute_key_fingerprint(export_public_key_jwk(resolved_key)) != resolved_fp:
                raise AamarvaError(
                    f'Cluster member "{agent_id}" public key fingerprint mismatch.',
                    code="RECIPIENT_KEY_MISMATCH",
                )

        if not resolved_key:
            pk = self.get_peer_key_by_agent(agent_id)
            raw_key = pk.get("publicKey") or pk.get("peerE2eePublicKey") or pk.get("peerIdentityKey")
            pk_fp = pk.get("fingerprint") or pk.get("peerKeyFingerprint")
            pk_id_key = pk.get("peerIdentityKey") or pk.get("identityKey")
            pk_sig = pk.get("peerKeySignature") or pk.get("signature")
            if raw_key:
                if pk_id_key and pk_sig and pk_fp:
                    verify_peer_key(raw_key, pk_fp, agent_id, pk_sig, pk_id_key)
                elif pk_fp and compute_key_fingerprint(export_public_key_jwk(raw_key)) != pk_fp:
                    raise AamarvaError(
                        f'Peer key fingerprint mismatch for "{agent_id}".',
                        code="RECIPIENT_KEY_MISMATCH",
                    )
                resolved_key = raw_key
                resolved_fp = pk_fp or resolved_fp
                pk_epoch = pk.get("keyEpoch") if pk.get("keyEpoch") is not None else pk.get("peerKeyEpoch")
                parsed_pk_epoch = self._parse_positive_int_strict(pk_epoch)
                if parsed_pk_epoch is not None:
                    resolved_epoch = parsed_pk_epoch

        if explicit_keys:
            direct = explicit_keys.get(agent_id) or explicit_keys.get(norm_target)
            if direct is not None:
                direct_pub = direct["publicKey"] if isinstance(direct, dict) and "publicKey" in direct and "kty" not in direct else direct
                direct_fp = compute_key_fingerprint(export_public_key_jwk(direct_pub))
                if resolved_key:
                    auth_fp = resolved_fp or compute_key_fingerprint(export_public_key_jwk(resolved_key))
                    if direct_fp != auth_fp:
                        raise AamarvaError(
                            f'Caller-supplied public key for "{agent_id}" contradicts authoritative registered key.',
                            code="RECIPIENT_KEY_MISMATCH",
                        )
                else:
                    resolved_key = direct_pub
                    resolved_fp = direct_fp

        if not resolved_key:
            raise AamarvaError(
                f'Recipient "{agent_id}" does not have a registered public key for cluster encryption.',
                code="RECIPIENT_KEY_MISSING",
            )

        return {
            "publicKey": resolved_key,
            "keyFingerprint": resolved_fp,
            "keyEpoch": resolved_epoch,
        }

    def distribute_cluster_key(
        self,
        cluster_id: str,
        recipients: Optional[List[str]] = None,
        epoch: Optional[int] = None,
        recipient_public_keys: Optional[Dict[str, Any]] = None,
        audience_hash: Optional[str] = None,
        roster_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate, wrap, and distribute cluster symmetric keys to all authoritative recipients (Workflow 2).
        """
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")

        if epoch is not None and self._parse_positive_int_strict(epoch) is None:
            raise AamarvaValidationError(
                "Cluster key distribution epoch must be an integer >= 1.",
                code="CLUSTER_INVALID_EPOCH",
            )

        ctx = self._resolve_authoritative_cluster_context(
            cluster_id,
            recipients=recipients,
            expected_roster_hash=roster_hash,
            expected_audience_hash=audience_hash,
        )

        if ctx["cluster"].rotationStatus and str(ctx["cluster"].rotationStatus).startswith("ROTATION_REQUIRED"):
            raise AamarvaError(
                f"Cluster key rotation required before key distribution: {ctx['cluster'].rotationStatus}",
                code="CLUSTER_ROTATION_REQUIRED",
            )

        resolved_epoch = ctx["clusterEpoch"]
        if epoch is not None and epoch != resolved_epoch:
            raise AamarvaError(
                f"Requested key distribution epoch {epoch} does not match authoritative cluster epoch {resolved_epoch}.",
                code="CLUSTER_INVALID_EPOCH",
            )

        auth_agent_id = ctx["senderId"]
        sender_member = ctx["memberMap"].get(normalize_agent_id(auth_agent_id))
        sender_priv = get_local_identity_key(
            auth_agent_id,
            epoch=sender_member.keyEpoch if sender_member else None,
        )
        sender_pub = export_public_key_jwk(sender_priv.public_key())
        sender_pub_fp = compute_key_fingerprint(sender_pub)

        cluster_key = generate_cluster_key()
        key_fingerprint = compute_group_key_fingerprint(cluster_key)

        key_packages = []
        for r_id in ctx["finalRecipients"]:
            if normalize_agent_id(r_id) == normalize_agent_id(auth_agent_id) and not (recipient_public_keys or {}).get(r_id):
                r_pub = sender_pub
                r_fp = sender_pub_fp
                r_epoch = (sender_member.keyEpoch if sender_member and sender_member.keyEpoch else None) or 1
            else:
                member_record = ctx["memberMap"][normalize_agent_id(r_id)]
                resolved_mat = self._resolve_authoritative_member_key(r_id, member_record, recipient_public_keys)
                r_pub = resolved_mat["publicKey"]
                r_fp = resolved_mat.get("keyFingerprint")
                r_epoch = resolved_mat.get("keyEpoch")

            wrapped = wrap_cluster_key_for_recipient(
                cluster_key,
                r_pub,
                sender_priv,
                cluster_id=cluster_id.strip(),
                epoch=resolved_epoch,
                audience_hash=ctx["audienceHash"],
                roster_hash=ctx["rosterHash"],
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
            "epoch": resolved_epoch,
            "audienceHash": ctx["audienceHash"],
            "rosterHash": ctx["rosterHash"],
            "keyFingerprint": key_fingerprint,
            "senderAgentId": auth_agent_id,
            "keyPackages": key_packages,
        })

        self.cluster_key_cache[self._cluster_cache_key(cluster_id.strip(), resolved_epoch, ctx["audienceHash"])] = {
            "key": cluster_key,
            "keyFingerprint": key_fingerprint,
            "rosterHash": ctx["rosterHash"],
            "audienceHash": ctx["audienceHash"],
            "epoch": resolved_epoch,
        }
        return {
            "epoch": resolved_epoch,
            "clusterKey": cluster_key,
            "keyFingerprint": key_fingerprint,
            "rosterHash": ctx["rosterHash"],
            "audienceHash": ctx["audienceHash"],
            "recipients": ctx["finalRecipients"],
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
            valid_epoch = self._parse_positive_int_strict(epoch)
            if valid_epoch is None:
                raise AamarvaValidationError("epoch must be a positive integer >= 1.", code="CLUSTER_INVALID_EPOCH")
            params["epoch"] = valid_epoch
        if audience_hash is not None and str(audience_hash).strip():
            params["audienceHash"] = str(audience_hash).strip()

        res = self.http.request("GET", f"/clusters/{cid_quoted}/key-distribution", auth=True, params=params if params else None)
        data = res.get("data", {}) if isinstance(res, dict) and "data" in res else res
        return data if isinstance(data, dict) else {}

    def _get_cluster_key_entry(
        self,
        cluster_id: str,
        epoch: int,
        audience_hash: str = "ALL",
        sender_public_key: Optional[Any] = None,
        expected_key_fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        clean_cluster_id = cluster_id.strip()
        valid_epoch = self._parse_positive_int_strict(epoch)
        if valid_epoch is None:
            raise AamarvaValidationError("Valid positive integer epoch is required to retrieve cluster key.", code="CLUSTER_INVALID_EPOCH")

        requested_audience = self._assert_valid_audience_hash(audience_hash or "ALL")
        clean_exp_opt_fp = self._assert_valid_fingerprint(expected_key_fingerprint) if expected_key_fingerprint else None

        cache_key = self._cluster_cache_key(clean_cluster_id, valid_epoch, requested_audience)
        if cache_key in self.cluster_key_cache:
            cached = self.cluster_key_cache[cache_key]
            if isinstance(cached, bytes):
                fp = compute_group_key_fingerprint(cached)
                if clean_exp_opt_fp and fp != clean_exp_opt_fp:
                    raise AamarvaError(
                        f"Cluster key fingerprint mismatch: expected {clean_exp_opt_fp}, cached {fp}.",
                        code="CLUSTER_KEY_FINGERPRINT_MISMATCH",
                    )
                return {
                    "key": cached,
                    "keyFingerprint": fp,
                    "audienceHash": requested_audience,
                    "epoch": valid_epoch,
                }
            if clean_exp_opt_fp and cached.get("keyFingerprint") != clean_exp_opt_fp:
                raise AamarvaError(
                    f"Cluster key fingerprint mismatch: expected {clean_exp_opt_fp}, cached {cached.get('keyFingerprint')}.",
                    code="CLUSTER_KEY_FINGERPRINT_MISMATCH",
                )
            return cached

        dist = self.get_cluster_key_distribution(
            clean_cluster_id,
            epoch=valid_epoch,
            audience_hash=requested_audience if requested_audience != "ALL" else None,
        )
        if not dist or not dist.get("encryptedKeyPackage"):
            raise AamarvaError(
                f'No cluster key package available for cluster "{clean_cluster_id}" at epoch {valid_epoch}.',
                code="CLUSTER_KEY_MISSING",
            )

        if dist.get("recipientKeyMismatch"):
            raise AamarvaError(
                f'Cluster key unwrapping failed due to recipient key mismatch (expected fingerprint: {dist.get("recipientKeyFingerprint") or "unknown"}).',
                code="RECIPIENT_KEY_MISMATCH",
            )

        if dist.get("clusterId") is not None and str(dist.get("clusterId")).strip() != clean_cluster_id:
            raise AamarvaError("Cluster key distribution clusterId mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if dist.get("epoch") is not None:
            dist_epoch = self._parse_positive_int_strict(dist.get("epoch"))
            if dist_epoch is None or dist_epoch != valid_epoch:
                raise AamarvaError("Cluster key distribution epoch mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if dist.get("audienceHash") is not None and str(dist.get("audienceHash")).strip() != requested_audience:
            raise AamarvaError("Cluster key distribution audienceHash mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")

        raw_pkg = dist["encryptedKeyPackage"]
        pkg_obj: Optional[Dict[str, Any]] = None
        if isinstance(raw_pkg, dict):
            pkg_obj = raw_pkg
        elif isinstance(raw_pkg, str) and raw_pkg.strip().startswith("{"):
            try:
                parsed = json.loads(raw_pkg)
                if not isinstance(parsed, dict):
                    raise ValueError("package JSON must be an object")
                pkg_obj = parsed
            except Exception as err:
                raise AamarvaError("Malformed JSON in cluster encryptedKeyPackage.", code="CLUSTER_KEY_UNWRAP_FAILED") from err

        auth_agent_id = (self.http.agent_id or "").strip()
        if not auth_agent_id:
            raise AamarvaValidationError("Authenticated agent ID is required to unwrap cluster key.")
        if dist.get("recipientAgentId") and normalize_agent_id(str(dist.get("recipientAgentId"))) != normalize_agent_id(auth_agent_id):
            raise AamarvaError("Cluster key distribution recipientAgentId mismatch.", code="RECIPIENT_KEY_MISMATCH")

        raw_rec_key_epoch = dist.get("recipientKeyEpoch") if dist.get("recipientKeyEpoch") is not None else (pkg_obj or {}).get("recipientKeyEpoch")
        target_personal_epoch: Optional[int] = None
        if raw_rec_key_epoch is not None:
            target_personal_epoch = self._parse_positive_int_strict(raw_rec_key_epoch)
            if target_personal_epoch is None:
                raise AamarvaError("Invalid recipientKeyEpoch in cluster key distribution.", code="IDENTITY_KEY_INVALID")

        local_priv = get_local_identity_key(auth_agent_id, epoch=target_personal_epoch)
        if dist.get("recipientKeyFingerprint"):
            local_fp = compute_key_fingerprint(export_public_key_jwk(local_priv.public_key()))
            if local_fp != dist.get("recipientKeyFingerprint"):
                raise AamarvaError(
                    f'Recipient key fingerprint mismatch: expected {dist.get("recipientKeyFingerprint")}, local {local_fp}.',
                    code="RECIPIENT_KEY_MISMATCH",
                )

        resolved_sender_id = str(dist.get("senderAgentId") or (pkg_obj or {}).get("senderAgentId") or "").strip()
        if not resolved_sender_id:
            raise AamarvaError("Cluster key distribution is missing senderAgentId.", code="CLUSTER_KEY_UNWRAP_FAILED")

        members = self.get_cluster_members(clean_cluster_id)
        if normalize_agent_id(resolved_sender_id) == normalize_agent_id(auth_agent_id):
            self_member = next((m for m in members if normalize_agent_id(m.agentId) == normalize_agent_id(auth_agent_id)), None)
            if not self_member:
                raise AamarvaError(
                    f'Key distributor "{resolved_sender_id}" is not an authoritative cluster member.',
                    code="CLUSTER_MEMBERSHIP_INVALID",
                )
            auth_sender_pub = self_member.publicKey or export_public_key_jwk(
                get_local_identity_key(auth_agent_id, epoch=self_member.keyEpoch).public_key()
            )
        else:
            match = next((m for m in members if normalize_agent_id(m.agentId) == normalize_agent_id(resolved_sender_id)), None)
            if not match:
                raise AamarvaError(
                    f'Cluster key distributor "{resolved_sender_id}" is not an authoritative member of cluster "{clean_cluster_id}".',
                    code="CLUSTER_MEMBERSHIP_INVALID",
                )
            auth_sender_pub = self._resolve_authoritative_member_key(resolved_sender_id, match)["publicKey"]

        auth_sender_fp = compute_key_fingerprint(export_public_key_jwk(auth_sender_pub))
        inline_or_override_pub = sender_public_key or dist.get("senderPublicKey") or (pkg_obj or {}).get("senderPublicKey")
        if inline_or_override_pub:
            provided_fp = compute_key_fingerprint(export_public_key_jwk(inline_or_override_pub))
            if provided_fp != auth_sender_fp:
                raise AamarvaError(
                    f'Cluster key sender public key does not match authoritative key for "{resolved_sender_id}".',
                    code="CLUSTER_KEY_UNWRAP_FAILED",
                )

        dist_fp = self._assert_valid_fingerprint(str(dist["keyFingerprint"])) if dist.get("keyFingerprint") else None
        if clean_exp_opt_fp and dist_fp and clean_exp_opt_fp != dist_fp:
            raise AamarvaError(
                f"Cluster key fingerprint mismatch: expected {clean_exp_opt_fp}, distribution has {dist_fp}.",
                code="CLUSTER_KEY_FINGERPRINT_MISMATCH",
            )
        pkg_fp_raw = (pkg_obj or {}).get("keyFingerprint")
        resolved_expected_fp = clean_exp_opt_fp or dist_fp or (self._assert_valid_fingerprint(pkg_fp_raw) if isinstance(pkg_fp_raw, str) else None)
        if not resolved_expected_fp:
            raise AamarvaError("Missing group keyFingerprint in cluster key distribution.", code="CLUSTER_KEY_FINGERPRINT_MISMATCH")

        nonce = str(dist.get("nonce") or (pkg_obj or {}).get("iv") or (dist.get("wrappingParams") or {}).get("nonce") or "")
        cluster_key = unwrap_cluster_key(
            raw_pkg,
            nonce,
            local_priv,
            auth_sender_pub,
            cluster_id=clean_cluster_id,
            epoch=valid_epoch,
            audience_hash=requested_audience,
            expected_key_fingerprint=resolved_expected_fp,
            recipient_agent_id=auth_agent_id,
            wrapping_params=dist.get("wrappingParams") if isinstance(dist.get("wrappingParams"), dict) else None,
        )

        entry = {
            "key": cluster_key,
            "keyFingerprint": resolved_expected_fp,
            "rosterHash": dist.get("rosterHash") or (pkg_obj or {}).get("rosterHash"),
            "audienceHash": requested_audience,
            "epoch": valid_epoch,
        }
        self.cluster_key_cache[cache_key] = entry
        return entry

    def get_cluster_key(
        self,
        cluster_id: str,
        epoch: Optional[int] = None,
        sender_public_key: Optional[Any] = None,
        audience_hash: str = "ALL",
        expected_key_fingerprint: Optional[str] = None,
    ) -> bytes:
        """
        Retrieve and locally decrypt symmetric cluster key for the given epoch and audience scope.
        """
        if epoch is None:
            raise AamarvaValidationError("epoch is required to retrieve cluster key.", code="CLUSTER_INVALID_EPOCH")
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
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        if not isinstance(plaintext, str) or not plaintext:
            raise AamarvaValidationError("Non-empty plaintext string is required.")
        if epoch is not None and self._parse_positive_int_strict(epoch) is None:
            raise AamarvaValidationError("epoch must be a positive integer >= 1.", code="CLUSTER_INVALID_EPOCH")

        pre_ctx = self._resolve_authoritative_cluster_context(
            cluster_id,
            recipients=recipients,
            expected_roster_hash=roster_hash,
            expected_audience_hash=audience_hash,
        )

        resolved_epoch = pre_ctx["clusterEpoch"]
        if pre_ctx["cluster"].rotationStatus and str(pre_ctx["cluster"].rotationStatus).startswith("ROTATION_REQUIRED"):
            if not auto_rotate:
                raise AamarvaError(
                    f"Cluster key rotation required before sending: {pre_ctx['cluster'].rotationStatus}",
                    code="CLUSTER_ROTATION_REQUIRED",
                )
            rotated = self.rotate_cluster_key(cluster_id, current_epoch=resolved_epoch)
            resolved_epoch = int(rotated["epoch"])
            post_cluster = self.get_cluster(cluster_id)
            post_epoch = self._parse_positive_int_strict(post_cluster.epoch if post_cluster.epoch is not None else post_cluster.keyEpoch)
            if post_epoch is not None and post_epoch != resolved_epoch:
                raise AamarvaError(
                    f"Post-rotation cluster epoch mismatch: rotate returned {resolved_epoch}, cluster reports {post_epoch}.",
                    code="CLUSTER_ROTATION_FAILED",
                )
            if post_cluster.rotationStatus and str(post_cluster.rotationStatus).startswith("ROTATION_REQUIRED"):
                raise AamarvaError(
                    f"Cluster still requires rotation after rotateClusterKey: {post_cluster.rotationStatus}",
                    code="CLUSTER_ROTATION_REQUIRED",
                )

        if epoch is not None and epoch != resolved_epoch:
            raise AamarvaError(
                f"Requested epoch {epoch} does not match current authoritative cluster epoch {resolved_epoch}.",
                code="CLUSTER_INVALID_EPOCH",
            )

        clean_cluster_id = cluster_id.strip()
        resolved_roster_hash = pre_ctx["rosterHash"]
        resolved_audience_hash = pre_ctx["audienceHash"]
        all_recipients = pre_ctx["finalRecipients"]
        sender_id = pre_ctx["senderId"]
        member_map = pre_ctx["memberMap"]

        try:
            key_entry = self._get_cluster_key_entry(clean_cluster_id, epoch=resolved_epoch, audience_hash=resolved_audience_hash)
        except Exception as get_err:
            is_missing_key = (
                getattr(get_err, "code", None) == "CLUSTER_KEY_MISSING"
                or getattr(get_err, "status_code", None) == 404
            )
            if not is_missing_key:
                raise get_err

            try:
                dist = self.distribute_cluster_key(
                    clean_cluster_id,
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
                    key_entry = self._get_cluster_key_entry(clean_cluster_id, epoch=resolved_epoch, audience_hash=resolved_audience_hash)
                else:
                    raise dist_err

        key_fingerprint = key_entry["keyFingerprint"]
        enc = encrypt_cluster_message(
            plaintext,
            key_entry["key"],
            clean_cluster_id,
            epoch=resolved_epoch,
            audience_hash=resolved_audience_hash,
            sender_agent_id=sender_id,
        )

        sender_member = member_map.get(normalize_agent_id(sender_id))
        sender_priv = get_local_identity_key(
            sender_id,
            epoch=sender_member.keyEpoch if sender_member else None,
        )
        signature = sign_cluster_message_v2(
            sender_priv,
            cluster_id=clean_cluster_id,
            key_epoch=resolved_epoch,
            sender_agent_id=sender_id,
            audience_hash=resolved_audience_hash,
            roster_hash=resolved_roster_hash,
            sequence="" if sequence is None else sequence,
            key_fingerprint=key_fingerprint,
            nonce=enc["nonce"],
            ciphertext=enc["ciphertext"],
        )

        payload: Dict[str, Any] = {
            "senderAgentId": sender_id,
            "ciphertext": enc["ciphertext"],
            "nonce": enc["nonce"],
            "version": 2,
            "keyEpoch": resolved_epoch,
            "recipients": all_recipients,
            "recipientAgentIds": all_recipients,
            "audienceHash": resolved_audience_hash,
            "rosterHash": resolved_roster_hash,
            "keyFingerprint": key_fingerprint,
            "signature": signature,
            "strictPreflight": True,
        }
        if sequence is not None:
            payload["sequence"] = sequence

        res = self._post_verified_cluster_message(clean_cluster_id, payload)

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
        Decrypt an encrypted cluster message using the cluster symmetric key (Workflow 2) with mandatory signature verification.
        """
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        clean_cluster_id = cluster_id.strip()

        if verify_signature is False:
            raise AamarvaError("Disabling cluster message signature verification is not permitted.", code="CLUSTER_SIGNATURE_INVALID")

        if not isinstance(message, dict) or not message.get("ciphertext") or not message.get("nonce"):
            raise AamarvaValidationError("Cluster message ciphertext and nonce are required.", code="CLUSTER_MESSAGE_DECRYPTION_FAILED")

        version = self._parse_positive_int_strict(message.get("version"))
        if version != 2:
            raise AamarvaError("Cluster message decryption requires protocol version 2.", code="INVALID_CLUSTER_MESSAGE_VERSION")

        epoch = self._parse_positive_int_strict(message.get("keyEpoch"))
        if epoch is None:
            raise AamarvaError("Cluster message is missing valid positive integer keyEpoch.", code="CLUSTER_INVALID_EPOCH")

        if not message.get("audienceHash") or not isinstance(message.get("audienceHash"), str):
            raise AamarvaError("Cluster message is missing audienceHash.", code="INVALID_AUDIENCE_HASH")
        audience_hash = self._assert_valid_audience_hash(message["audienceHash"])

        if not message.get("rosterHash") or not isinstance(message.get("rosterHash"), str):
            raise AamarvaError("Cluster message is missing rosterHash.", code="INVALID_ROSTER_HASH")
        roster_hash = self._assert_valid_roster_hash(message["rosterHash"])

        if not message.get("keyFingerprint") or not isinstance(message.get("keyFingerprint"), str):
            raise AamarvaError("Cluster message is missing keyFingerprint.", code="CLUSTER_KEY_FINGERPRINT_MISMATCH")
        key_fingerprint = self._assert_valid_fingerprint(message["keyFingerprint"])

        sender_id = str(message.get("senderAgentId") or "").strip()
        if not sender_id:
            raise AamarvaError("Cluster message is missing senderAgentId.", code="CLUSTER_SIGNATURE_INVALID")

        if not message.get("signature") or not isinstance(message.get("signature"), str) or not message["signature"].strip():
            raise AamarvaError("Cluster message is missing required ECDSA v2 signature.", code="CLUSTER_SIGNATURE_INVALID")

        members = self.get_cluster_members(clean_cluster_id)
        sender_member = next((m for m in members if normalize_agent_id(m.agentId) == normalize_agent_id(sender_id)), None)
        if not sender_member:
            raise AamarvaError(
                f'Message sender "{sender_id}" is not an authoritative member of cluster "{clean_cluster_id}".',
                code="CLUSTER_MEMBERSHIP_INVALID",
            )

        my_agent_id = (self.http.agent_id or "").strip()
        if my_agent_id and normalize_agent_id(sender_id) == normalize_agent_id(my_agent_id) and not sender_member.publicKey:
            resolved_sender_pub = export_public_key_jwk(
                get_local_identity_key(my_agent_id, epoch=sender_member.keyEpoch).public_key()
            )
        else:
            resolved_sender_pub = self._resolve_authoritative_member_key(sender_id, sender_member)["publicKey"]

        if sender_public_key is not None:
            auth_fp = compute_key_fingerprint(export_public_key_jwk(resolved_sender_pub))
            supplied_fp = compute_key_fingerprint(export_public_key_jwk(sender_public_key))
            if supplied_fp != auth_fp:
                raise AamarvaError(
                    f'Supplied senderPublicKey contradicts authoritative key for "{sender_id}".',
                    code="CLUSTER_SIGNATURE_INVALID",
                )

        ok = verify_cluster_message_signature_v2(
            resolved_sender_pub,
            cluster_id=clean_cluster_id,
            key_epoch=epoch,
            sender_agent_id=sender_id,
            audience_hash=audience_hash,
            roster_hash=roster_hash,
            sequence="" if message.get("sequence") is None else message.get("sequence"),
            key_fingerprint=key_fingerprint,
            nonce=str(message["nonce"]),
            ciphertext=str(message["ciphertext"]),
            signature_b64=str(message["signature"]),
        )
        if not ok:
            raise AamarvaError("Cluster message ECDSA signature verification failed.", code="CLUSTER_SIGNATURE_INVALID")

        key_entry = self._get_cluster_key_entry(
            clean_cluster_id,
            epoch=epoch,
            audience_hash=audience_hash,
            expected_key_fingerprint=key_fingerprint,
        )
        if key_entry.get("rosterHash") and key_entry.get("rosterHash") != roster_hash:
            raise AamarvaError(
                f'Cluster message rosterHash mismatch: expected sealed {key_entry.get("rosterHash")}, got {roster_hash}.',
                code="ROSTER_HASH_MISMATCH",
            )

        return decrypt_cluster_message(
            message["ciphertext"],
            message["nonce"],
            key_entry["key"],
            clean_cluster_id,
            epoch=epoch,
            version=version,
            audience_hash=audience_hash,
            sender_agent_id=sender_id,
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

        forbidden_gateway_fields = (
            "serverUrl",
            "mcpServerUrl",
            "server",
            "auth",
            "authentication",
            "authConfig",
            "grantToken",
            "accessToken",
        )
        for field in forbidden_gateway_fields:
            if field in data and data[field] is not None:
                raise AamarvaError(
                    "FLOOR invocation failed: platform returned external MCP gateway URL or credentials; the Agent ADK does not perform external MCP execution.",
                    code="FLOOR_EXECUTION_FAILED",
                )

        has_direct_result = ("result" in data and data["result"] is not None) or ("output" in data and data["output"] is not None)
        direct_result = data["result"] if ("result" in data and data["result"] is not None) else data.get("output")

        out = {
            "invocationId": inv_id,
            "requestId": req_id,
            "toolId": str(data.get("toolId") or clean_tool_id).strip(),
            "status": status,
            "message": res_dict.get("message") or data.get("message"),
        }
        if has_direct_result:
            out["result"] = direct_result
            out["hasDirectResult"] = True
        return out

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
        required_scope: Optional[str] = None,
        fleet_id: Optional[str] = None,
        require_approved_arguments: bool = False,
    ) -> FloorToolInvokeResult:
        """
        Execute an authorized FLOOR tool through the AAMARVA platform API.
        Discovery -> Access evaluation -> Approval status/polling -> Platform-mediated execution.

        The Agent ADK never connects directly to external MCP servers and never retrieves
        or handles MCP server-owner credentials.
        """
        if not tool_id or not isinstance(tool_id, str) or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")
        if arguments is not None and not isinstance(arguments, dict):
            raise AamarvaValidationError("arguments must be a dictionary")

        clean_tool_id = tool_id.strip()
        submitted_args = arguments if arguments is not None else {}
        scope_key = self._floor_scope_key(clean_tool_id)
        should_wait = bool(wait_for_approval or (poll_timeout_ms is not None and poll_timeout_ms > 0))
        effective_timeout_ms = poll_timeout_ms if poll_timeout_ms is not None and poll_timeout_ms > 0 else 30000
        auth_agent_id = (self.http.agent_id or "").strip()
        target_agent_id = (self.http.target_agent_id or "").strip()
        expected_agent = target_agent_id or auth_agent_id

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

        def _assert_request_binding(status_res: FloorAccessRequestStatus) -> None:
            if status_res.toolId and status_res.toolId.strip() != clean_tool_id:
                raise AamarvaError(
                    f'FLOOR request status toolId "{status_res.toolId}" does not match requested tool "{clean_tool_id}".',
                    code="FLOOR_EXECUTION_FAILED",
                )
            if expected_agent and status_res.agentId and status_res.agentId.strip().upper() != expected_agent.upper():
                raise AamarvaError(
                    "FLOOR request status agentId does not match target agent context.",
                    code="FLOOR_EXECUTION_FAILED",
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
                    _assert_request_binding(approved_status)
                    self._pending_floor_requests.pop(scope_key, None)
                    resolved_invocation_id = approved_status.invocationId
                else:
                    status_res = self.get_floor_request_status(existing_req_id)
                    req_status = (status_res.status or "pending").strip().lower()
                    if req_status == "approved":
                        _assert_request_binding(status_res)
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
                    arguments=submitted_args,
                )
                if inv_res.get("toolId") and str(inv_res["toolId"]).strip() != clean_tool_id:
                    raise AamarvaError(
                        f'FLOOR invocation toolId "{inv_res["toolId"]}" does not match requested tool "{clean_tool_id}".',
                        code="FLOOR_EXECUTION_FAILED",
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
                        _assert_request_binding(approved_status)
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
                elif inv_res["status"] not in ["approved", "authorized", "granted", "executed", "completed"]:
                    raise AamarvaError(
                        f'FLOOR invocation creation returned unexpected status "{inv_res["status"]}".',
                        code="FLOOR_EXECUTION_FAILED",
                    )
                elif inv_res["status"] in ["executed", "completed"] and inv_res.get("hasDirectResult"):
                    return FloorToolInvokeResult(
                        status=inv_res["status"],
                        invocationId=inv_res.get("invocationId") or None,
                        toolId=clean_tool_id,
                        result=inv_res.get("result"),
                        message=inv_res.get("message") if isinstance(inv_res.get("message"), str) else None,
                    )
                else:
                    resolved_invocation_id = inv_res["invocationId"]

        if not resolved_invocation_id:
            raise AamarvaError("FLOOR invocation creation failed to return a valid invocationId.", code="FLOOR_EXECUTION_FAILED")

        # Stage 4: Platform-mediated tool execution (POST /api/floor/invocations/:invocation_id/execute)
        expected_iid = resolved_invocation_id.strip()
        iid_quoted = urllib.parse.quote(expected_iid, safe='')
        body = {
            "arguments": submitted_args,
        }
        try:
            res = self.http.request("POST", f"/floor/invocations/{iid_quoted}/execute", auth=True, json_data=body)
        except Exception as err:
            if getattr(err, "status_code", None) == 403:
                raise AamarvaError(
                    "FLOOR execution denied by platform.",
                    code="FLOOR_ACCESS_DENIED",
                    status_code=403,
                )
            raise err

        if not isinstance(res, dict):
            raise AamarvaError("FLOOR execution failed: response payload is not an object.", code="FLOOR_EXECUTION_FAILED")

        if res.get("success") is False:
            raise AamarvaError("FLOOR execution was rejected by platform.", code="FLOOR_ACCESS_DENIED")

        data = res.get("data")
        if not isinstance(data, dict):
            raise AamarvaError("FLOOR execution failed: malformed execution payload.", code="FLOOR_EXECUTION_FAILED")

        # Reject any external MCP gateway destination or credential fields in the Agent ADK
        forbidden_gateway_fields = (
            "serverUrl",
            "mcpServerUrl",
            "server",
            "auth",
            "authentication",
            "authConfig",
            "grantToken",
            "accessToken",
        )
        for field in forbidden_gateway_fields:
            if field in data and data[field] is not None:
                raise AamarvaError(
                    "FLOOR execution failed: platform returned external MCP gateway URL or credentials; the Agent ADK does not execute external MCP servers or handle gateway credentials.",
                    code="FLOOR_EXECUTION_FAILED",
                )

        # Validate invocationId binding
        raw_iid = data.get("invocationId")
        returned_iid = raw_iid.strip() if isinstance(raw_iid, str) else ""

        # Validate verificationInfo when present
        verification_info: Optional[Dict[str, Any]] = None
        if "verificationInfo" in data and data["verificationInfo"] is not None:
            if not isinstance(data["verificationInfo"], dict):
                raise AamarvaError("FLOOR execution failed: malformed verificationInfo object.", code="FLOOR_EXECUTION_FAILED")
            verification_info = data["verificationInfo"]
            if verification_info.get("verified") is False:
                raise AamarvaError("FLOOR execution failed: verificationInfo.verified is false.", code="FLOOR_ACCESS_DENIED")
            if verification_info.get("verified") is not True:
                raise AamarvaError("FLOOR execution failed: verificationInfo.verified must be true.", code="FLOOR_EXECUTION_FAILED")
            if "invocationId" in verification_info and verification_info["invocationId"] is not None:
                v_iid = verification_info["invocationId"]
                if not isinstance(v_iid, str) or v_iid.strip() != expected_iid:
                    raise AamarvaError("FLOOR execution failed: verificationInfo.invocationId does not match invocation.", code="FLOOR_EXECUTION_FAILED")

        # Validate status (empty status is only accepted for the reconciled docs contract when verificationInfo.verified is True)
        raw_status = str(data.get("status") or res.get("status") or "").strip().lower()
        has_verified_proof = verification_info is not None and verification_info.get("verified") is True
        if not raw_status:
            if not has_verified_proof or not returned_iid:
                raise AamarvaError(
                    "FLOOR execution failed: expected status 'approved' or 'executed', got ''.",
                    code="FLOOR_EXECUTION_FAILED",
                )
        elif raw_status in ["denied", "rejected", "revoked", "expired", "unassigned", "pending"]:
            raise AamarvaError(
                f"FLOOR execution denied: status is '{raw_status}'.",
                code="FLOOR_ACCESS_DENIED",
            )
        elif raw_status not in ["approved", "executed", "completed"]:
            raise AamarvaError(
                f"FLOOR execution failed: expected status 'approved' or 'executed', got '{raw_status}'.",
                code="FLOOR_EXECUTION_FAILED",
            )

        if not returned_iid or returned_iid != expected_iid:
            raise AamarvaError("FLOOR execution failed: invocation ID missing or mismatched in platform response.", code="FLOOR_EXECUTION_FAILED")

        # Validate grant metadata when present
        grant: Optional[Dict[str, Any]] = None
        if "grant" in data and data["grant"] is not None:
            raw_grant = data["grant"]
            if not isinstance(raw_grant, dict) or len(raw_grant) == 0:
                raise AamarvaError("FLOOR execution failed: grant details missing or empty in response.", code="FLOOR_EXECUTION_FAILED")
            grant = raw_grant
            if grant.get("revoked") is True or bool(grant.get("revokedAt")):
                raise AamarvaError("FLOOR execution denied: grant has been revoked.", code="FLOOR_ACCESS_DENIED")
            raw_grant_status = grant.get("status")
            grant_status = raw_grant_status.strip().lower() if isinstance(raw_grant_status, str) else ""
            if grant_status in ["denied", "rejected", "revoked", "expired", "inactive", "pending"]:
                raise AamarvaError(f"FLOOR execution denied: grant status is '{grant_status}'.", code="FLOOR_ACCESS_DENIED")
            if not grant_status or grant_status not in ["authorized", "granted", "approved", "active"]:
                raise AamarvaError(f"FLOOR execution denied: grant status is missing or inactive ('{grant_status}').", code="FLOOR_ACCESS_DENIED")
            if "invocationId" in grant and grant["invocationId"] is not None:
                g_iid = grant["invocationId"]
                if not isinstance(g_iid, str) or g_iid.strip() != expected_iid:
                    raise AamarvaError("FLOOR execution failed: grant.invocationId does not match invocation.", code="FLOOR_EXECUTION_FAILED")

        if grant is None and not has_verified_proof:
            raise AamarvaError("FLOOR execution failed: missing grant or verified proof in platform response.", code="FLOOR_EXECUTION_FAILED")

        # Validate toolId binding
        if "tool" in data and data["tool"] is not None and not isinstance(data["tool"], dict):
            raise AamarvaError("FLOOR execution failed: malformed tool object in response.", code="FLOOR_EXECUTION_FAILED")
        tool_obj = data.get("tool") if isinstance(data.get("tool"), dict) else None

        def _read_req_str(obj: Optional[Dict[str, Any]], field: str, label: str) -> Optional[str]:
            if obj is None or field not in obj or obj[field] is None:
                return None
            val = obj[field]
            if not isinstance(val, str) or not val.strip():
                raise AamarvaError(f"FLOOR execution failed: malformed {label} in platform response.", code="FLOOR_EXECUTION_FAILED")
            return val.strip()

        top_tool_id = _read_req_str(data, "toolId", "toolId")
        nested_tool_id = _read_req_str(tool_obj, "id", "tool.id")
        grant_tool_id = _read_req_str(grant, "toolId", "grant.toolId")
        verified_tool_id = _read_req_str(verification_info, "toolId", "verificationInfo.toolId")

        tool_id_candidates = [c for c in [top_tool_id, nested_tool_id, grant_tool_id, verified_tool_id] if c]
        returned_tool_id = top_tool_id or nested_tool_id or ""
        if not returned_tool_id:
            raise AamarvaError("FLOOR execution failed: toolId is missing in platform response.", code="FLOOR_EXECUTION_FAILED")
        if any(tid != returned_tool_id for tid in tool_id_candidates) or returned_tool_id != clean_tool_id:
            raise AamarvaError("FLOOR execution failed: toolId mismatch across execution response.", code="FLOOR_EXECUTION_FAILED")

        # Validate present expiration timestamps
        _validate_iso_expiration(data.get("expiresAt"), "expiresAt" in data)
        _validate_iso_expiration(grant.get("expiresAt") if grant else None, bool(grant and "expiresAt" in grant))

        # Validate scope when present or required
        scope_sources: List[List[str]] = []
        for container, label in [
            (data, "data.scope"),
            (grant, "grant.scope"),
            (verification_info, "verificationInfo.scope"),
        ]:
            if container is not None and "scope" in container:
                scope_sources.append(_parse_and_validate_scope_tokens(container["scope"], label))
        if len(scope_sources) > 1:
            base_set = sorted(set(scope_sources[0]))
            for other in scope_sources[1:]:
                if sorted(set(other)) != base_set:
                    raise AamarvaError("FLOOR execution denied: conflicting scopes across response.", code="FLOOR_ACCESS_DENIED")
        req_scope = required_scope.strip() if isinstance(required_scope, str) and required_scope.strip() else ""
        if req_scope:
            granted_set = set(t for group in scope_sources for t in group)
            if not granted_set or (req_scope not in granted_set and "*" not in granted_set and "tool:*" not in granted_set):
                raise AamarvaError(f"FLOOR execution denied: required scope '{req_scope}' is not granted.", code="FLOOR_ACCESS_DENIED")

        # Validate agent identity, target-agent scoping, and fleet context
        returned_agent_fields: List[str] = []
        for obj, field, label in [
            (data, "agentId", "data.agentId"),
            (grant, "agentId", "grant.agentId"),
            (verification_info, "agentId", "verificationInfo.agentId"),
            (data, "targetAgentId", "data.targetAgentId"),
            (grant, "targetAgentId", "grant.targetAgentId"),
            (verification_info, "targetAgentId", "verificationInfo.targetAgentId"),
        ]:
            val = _read_req_str(obj, field, label)
            if val:
                returned_agent_fields.append(val)

        if expected_agent:
            if not returned_agent_fields:
                raise AamarvaError("FLOOR execution failed: authorized agent identity missing in platform response.", code="FLOOR_EXECUTION_FAILED")
            expected_upper = expected_agent.upper()
            for returned_id in returned_agent_fields:
                if returned_id.upper() != expected_upper:
                    raise AamarvaError("FLOOR execution failed: agent fleet context mismatch in platform response.", code="FLOOR_EXECUTION_FAILED")
        elif len(returned_agent_fields) > 1:
            first_upper = returned_agent_fields[0].upper()
            if any(rid.upper() != first_upper for rid in returned_agent_fields):
                raise AamarvaError("FLOOR execution failed: conflicting agent identities in platform response.", code="FLOOR_EXECUTION_FAILED")

        fleet_ids: List[str] = []
        for obj, label in [
            (data, "data.fleetId"),
            (grant, "grant.fleetId"),
            (verification_info, "verificationInfo.fleetId"),
        ]:
            fid = _read_req_str(obj, "fleetId", label)
            if fid:
                fleet_ids.append(fid)
        expected_fleet_id = fleet_id.strip() if isinstance(fleet_id, str) and fleet_id.strip() else ""
        if expected_fleet_id and (not fleet_ids or any(f.upper() != expected_fleet_id.upper() for f in fleet_ids)):
            raise AamarvaError("FLOOR execution failed: fleet context mismatch in platform response.", code="FLOOR_EXECUTION_FAILED")
        if len(fleet_ids) > 1 and any(f.upper() != fleet_ids[0].upper() for f in fleet_ids):
            raise AamarvaError("FLOOR execution failed: conflicting fleet identifiers in platform response.", code="FLOOR_EXECUTION_FAILED")

        master_ids: List[str] = []
        for obj, label in [
            (data, "data.masterId"),
            (grant, "grant.masterId"),
            (verification_info, "verificationInfo.masterId"),
        ]:
            mid = _read_req_str(obj, "masterId", label)
            if mid:
                master_ids.append(mid)
        if len(master_ids) > 1 and any(m.upper() != master_ids[0].upper() for m in master_ids):
            raise AamarvaError("FLOOR execution failed: conflicting master agent identifiers in platform response.", code="FLOOR_EXECUTION_FAILED")

        # Validate approvedArguments binding
        data_approved_args: Optional[Dict[str, Any]] = None
        if "approvedArguments" in data and data["approvedArguments"] is not None:
            if not isinstance(data["approvedArguments"], dict):
                raise AamarvaError("FLOOR execution failed: malformed approvedArguments in response.", code="FLOOR_EXECUTION_FAILED")
            data_approved_args = data["approvedArguments"]

        grant_approved_args: Optional[Dict[str, Any]] = None
        if grant is not None and "approvedArguments" in grant and grant["approvedArguments"] is not None:
            if not isinstance(grant["approvedArguments"], dict):
                raise AamarvaError("FLOOR execution failed: malformed grant.approvedArguments in response.", code="FLOOR_EXECUTION_FAILED")
            grant_approved_args = grant["approvedArguments"]

        if data_approved_args is not None and grant_approved_args is not None:
            if not _deep_equal_values(data_approved_args, grant_approved_args):
                raise AamarvaError("FLOOR execution failed: conflicting approvedArguments in execution response.", code="FLOOR_EXECUTION_FAILED")

        approved_args = data_approved_args if data_approved_args is not None else grant_approved_args
        if require_approved_arguments and approved_args is None:
            raise AamarvaError("FLOOR execution failed: approvedArguments missing in execution response.", code="FLOOR_EXECUTION_FAILED")
        if approved_args is not None:
            if not _deep_equal_values(approved_args, submitted_args):
                raise AamarvaError("FLOOR execution failed: execution arguments do not match approved arguments.", code="FLOOR_EXECUTION_FAILED")

        # Require platform-mediated execution result
        has_result = ("result" in data and data["result"] is not None) or ("output" in data and data["output"] is not None)
        if not has_result:
            raise AamarvaError("FLOOR execution failed: platform response omitted execution result.", code="FLOOR_EXECUTION_FAILED")
        execution_result = data["result"] if ("result" in data and data["result"] is not None) else data["output"]

        return FloorToolInvokeResult(
            status=raw_status if raw_status in ("executed", "completed") else "approved",
            invocationId=expected_iid,
            toolId=clean_tool_id,
            result=execution_result,
            message=data.get("message") if isinstance(data.get("message"), str) else None,
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


def _validate_iso_expiration(raw_value: Any, is_present: bool) -> Optional[str]:
    if not is_present:
        return None
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise AamarvaError("FLOOR authorization denied: malformed grant expiration timestamp.", code="FLOOR_ACCESS_DENIED")
    trimmed = raw_value.strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}", trimmed):
        raise AamarvaError("FLOOR authorization denied: malformed grant expiration timestamp.", code="FLOOR_ACCESS_DENIED")
    try:
        exp_str = trimmed[:-1] + "+00:00" if trimmed.endswith("Z") else trimmed
        exp_dt = datetime.datetime.fromisoformat(exp_str)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        raise AamarvaError("FLOOR authorization denied: malformed grant expiration timestamp.", code="FLOOR_ACCESS_DENIED")
    if exp_dt <= datetime.datetime.now(datetime.timezone.utc):
        raise AamarvaError("FLOOR authorization denied: execution grant has expired.", code="FLOOR_ACCESS_DENIED")
    return trimmed


def _parse_and_validate_scope_tokens(raw_scope: Any, label: str) -> List[str]:
    denied_tokens = {"none", "denied", "revoked", "expired", "invalid", "unauthorized"}
    tokens: List[str] = []
    if isinstance(raw_scope, str):
        trimmed = raw_scope.strip()
        if not trimmed:
            raise AamarvaError(f"FLOOR authorization denied: {label} is empty.", code="FLOOR_ACCESS_DENIED")
        tokens = [t for t in re.split(r"[\s,]+", trimmed) if t]
    elif isinstance(raw_scope, list):
        if len(raw_scope) == 0:
            raise AamarvaError(f"FLOOR authorization denied: {label} is empty.", code="FLOOR_ACCESS_DENIED")
        for item in raw_scope:
            if not isinstance(item, str) or not item.strip():
                raise AamarvaError(f"FLOOR authorization denied: {label} contains invalid entry.", code="FLOOR_ACCESS_DENIED")
            tokens.extend([t for t in re.split(r"[\s,]+", item.strip()) if t])
    else:
        raise AamarvaError(f"FLOOR authorization denied: {label} is invalid.", code="FLOOR_ACCESS_DENIED")

    if not tokens or any(t.lower() in denied_tokens for t in tokens):
        raise AamarvaError(f"FLOOR authorization denied: {label} is not permitted for execution.", code="FLOOR_ACCESS_DENIED")
    return tokens


def _deep_equal_values(a: Any, b: Any) -> bool:
    if type(a) is bool or type(b) is bool:
        return type(a) is type(b) and a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        if math.isnan(a) or math.isnan(b):
            return False
        return a == b
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        if set(a.keys()) != set(b.keys()):
            return False
        return all(_deep_equal_values(a[k], b[k]) for k in a)
    if isinstance(a, list):
        if len(a) != len(b):
            return False
        return all(_deep_equal_values(x, y) for x, y in zip(a, b))
    return a == b

