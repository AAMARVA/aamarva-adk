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
    generate_cluster_key,
    wrap_cluster_key_for_recipient,
    unwrap_cluster_key,
    encrypt_cluster_message,
    decrypt_cluster_message,
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
        )
        self.target_agent_id = target_agent_id
        self.registered_agent_id: Optional[str] = None
        self.registered_key_fingerprint: Optional[str] = None
        self.is_registering_key: bool = False
        self.cluster_key_cache: Dict[str, bytes] = {}
        self.http.on_auth_success = lambda: self.register_public_key()

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
        self.register_public_key()
        local_priv = get_local_identity_key(my_agent_id)

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

        my_agent_id = self.http.agent_id or "me"
        local_priv = get_local_identity_key(my_agent_id)
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
        version: int = 2,
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

    def distribute_cluster_key(
        self,
        cluster_id: str,
        recipients: Optional[List[str]] = None,
        epoch: int = 1,
        recipient_public_keys: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate, wrap, and distribute cluster symmetric keys to all required recipients.
        """
        auth_agent_id = (self.http.agent_id or "me").strip()
        master_id = self.resolve_master_agent_id()

        recipient_set = set()
        if master_id:
            recipient_set.add(master_id)
        if auth_agent_id:
            recipient_set.add(auth_agent_id)
        if recipients:
            for r in recipients:
                if r and isinstance(r, str) and r.strip():
                    recipient_set.add(r.strip())
        final_recipients = list(recipient_set)

        cluster_key = generate_cluster_key()
        sender_priv = get_local_identity_key(auth_agent_id)
        sender_pub = export_public_key_jwk(sender_priv.public_key())

        key_packages = []
        for r_id in final_recipients:
            r_pub = (recipient_public_keys or {}).get(r_id)
            if not r_pub:
                if r_id == auth_agent_id:
                    r_pub = sender_pub
                else:
                    try:
                        conns = self.connections()
                        conn = next((c for c in conns if getattr(c, 'agentId', None) == r_id), None)
                        if conn:
                            cid_quoted = urllib.parse.quote(conn.connectionId.strip(), safe='')
                            pk_res = self.http.request("GET", f"/connections/{cid_quoted}/peer-key", auth=True)
                            pk_data = pk_res.get("data", {}) if isinstance(pk_res, dict) else pk_res
                            r_pub = pk_data.get("peerE2eePublicKey") or pk_data.get("peerIdentityKey")
                    except Exception:
                        pass

            if not r_pub:
                raise AamarvaError(
                    f'Recipient "{r_id}" does not have a registered public key for cluster encryption.',
                    code="RECIPIENT_KEY_MISSING",
                )

            wrapped = wrap_cluster_key_for_recipient(cluster_key, r_pub, sender_priv)
            key_packages.append({
                "recipientAgentId": r_id,
                "encryptedKeyPackage": wrapped["encryptedKeyPackage"],
                "nonce": wrapped["nonce"],
                "wrappingParams": wrapped["wrappingParams"],
            })

        self.submit_cluster_key_distribution(cluster_id, {
            "epoch": epoch,
            "senderAgentId": auth_agent_id,
            "keyPackages": key_packages,
        })

        self.cluster_key_cache[f"{cluster_id}:{epoch}"] = cluster_key
        return {
            "epoch": epoch,
            "clusterKey": cluster_key,
            "recipients": final_recipients,
        }

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

    def get_cluster_key(
        self,
        cluster_id: str,
        epoch: int = 1,
        sender_public_key: Optional[Any] = None,
    ) -> bytes:
        """
        Retrieve and locally decrypt symmetric cluster key for the given epoch.
        """
        cache_key = f"{cluster_id}:{epoch}"
        if cache_key in self.cluster_key_cache:
            return self.cluster_key_cache[cache_key]

        dist = self.get_cluster_key_distribution(cluster_id, epoch)
        if not dist or not dist.get("encryptedKeyPackage"):
            raise AamarvaError(
                f'No cluster key package available for cluster "{cluster_id}" at epoch {epoch}.',
                code="CLUSTER_KEY_MISSING",
            )

        auth_agent_id = (self.http.agent_id or "me").strip()
        local_priv = get_local_identity_key(auth_agent_id)

        sender_pub = sender_public_key or dist.get("senderPublicKey")
        if not sender_pub and dist.get("senderAgentId"):
            if dist["senderAgentId"] == auth_agent_id:
                sender_pub = export_public_key_jwk(local_priv.public_key())
            else:
                try:
                    conns = self.connections()
                    conn = next((c for c in conns if getattr(c, 'agentId', None) == dist["senderAgentId"]), None)
                    if conn:
                        cid_quoted = urllib.parse.quote(conn.connectionId.strip(), safe='')
                        pk_res = self.http.request("GET", f"/connections/{cid_quoted}/peer-key", auth=True)
                        pk_data = pk_res.get("data", {}) if isinstance(pk_res, dict) else pk_res
                        sender_pub = pk_data.get("peerE2eePublicKey") or pk_data.get("peerIdentityKey")
                except Exception:
                    pass

        if not sender_pub:
            raise AamarvaError(
                f'Unable to unwrap cluster key: missing sender public key for "{dist.get("senderAgentId")}".',
                code="CLUSTER_KEY_UNWRAP_FAILED",
            )

        nonce = str(dist.get("nonce") or (dist.get("wrappingParams") or {}).get("nonce") or "")
        cluster_key = unwrap_cluster_key(dist["encryptedKeyPackage"], nonce, local_priv, sender_pub)
        self.cluster_key_cache[cache_key] = cluster_key
        return cluster_key

    def send_encrypted_cluster_message(
        self,
        cluster_id: str,
        plaintext: str,
        recipients: Optional[List[str]] = None,
        epoch: int = 1,
        recipient_public_keys: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt and broadcast a cluster message using protocol version 2 and cluster symmetric key.
        """
        try:
            cluster_key = self.get_cluster_key(cluster_id, epoch)
        except Exception:
            dist = self.distribute_cluster_key(
                cluster_id,
                recipients=recipients,
                epoch=epoch,
                recipient_public_keys=recipient_public_keys,
            )
            cluster_key = dist["clusterKey"]

        enc = encrypt_cluster_message(plaintext, cluster_key, cluster_id, epoch)
        res = self.send_cluster_message(
            cluster_id,
            ciphertext=enc["ciphertext"],
            nonce=enc["nonce"],
            version=2,
            key_epoch=epoch,
            recipients=recipients,
        )

        master_id = self.resolve_master_agent_id()
        sender_id = (self.http.agent_id or "").strip()
        all_recipients = list(set([master_id, sender_id] + (recipients or [])))

        msg_id = str(res.get("messageId") or res.get("id") or "msg_cluster")
        return {
            "messageId": msg_id,
            "version": 2,
            "keyEpoch": epoch,
            "recipients": all_recipients,
        }

    def decrypt_cluster_message(
        self,
        cluster_id: str,
        message: Dict[str, Any],
        sender_public_key: Optional[Any] = None,
    ) -> str:
        """
        Decrypt an encrypted cluster message using the cluster symmetric key.
        """
        epoch = int(message.get("keyEpoch") or 1)
        version = int(message.get("version") or 2)
        cluster_key = self.get_cluster_key(cluster_id, epoch, sender_public_key)
        return decrypt_cluster_message(
            message["ciphertext"],
            message["nonce"],
            cluster_key,
            cluster_id,
            epoch=epoch,
            version=version,
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

        tid_quoted = urllib.parse.quote(tool_id.strip(), safe='')
        body = {
            "reason": reason or "Agent requested tool invocation",
            "arguments": arguments or {},
        }
        res = self.http.request("POST", f"/floor/tools/{tid_quoted}/invoke", auth=True, json_data=body)
        data = (res.get("data", {}) if isinstance(res, dict) and isinstance(res.get("data"), dict) else res) or {}
        return {
            "invocationId": str(data.get("invocationId") or data.get("id") or data.get("requestId") or ""),
            "requestId": str(data.get("requestId") or data.get("invocationId") or "") or None,
            "toolId": str(data.get("toolId") or tool_id.strip()),
            "status": str(data.get("status") or res.get("status") or "pending").lower(),
            "message": res.get("message") or data.get("message"),
        }

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

        iid_quoted = urllib.parse.quote(invocation_id.strip(), safe='')
        body = {
            "arguments": arguments or {},
        }
        res = self.http.request("POST", f"/floor/invocations/{iid_quoted}/execute", auth=True, json_data=body)
        if not isinstance(res, dict):
            raise AamarvaError("FLOOR authorization failed: response payload is not an object.", code="FLOOR_EXECUTION_FAILED")

        if res.get("success") is False:
            raise AamarvaError(res.get("error") or res.get("message") or "FLOOR authorization was rejected by platform.", code="FLOOR_ACCESS_DENIED")

        data = res.get("data") if isinstance(res.get("data"), dict) else res
        raw_status = str(data.get("status") or res.get("status") or "").strip().lower()

        if raw_status in ["denied", "rejected", "revoked", "expired", "unassigned", "pending"]:
            raise AamarvaError(
                data.get("message") or res.get("message") or f"FLOOR execution authorization denied: status is '{raw_status}'.",
                code="FLOOR_ACCESS_DENIED",
            )

        if raw_status != "approved":
            raise AamarvaError(
                data.get("message") or res.get("message") or f"FLOOR authorization failed: expected status 'approved', got '{raw_status}'.",
                code="FLOOR_EXECUTION_FAILED",
            )

        returned_iid = str(data.get("invocationId") or invocation_id).strip()
        if returned_iid != invocation_id.strip():
            raise AamarvaError("FLOOR authorization failed: invocation ID mismatch in platform response.", code="FLOOR_EXECUTION_FAILED")

        server_url = data.get("serverUrl") or data.get("mcpServerUrl") or (data.get("server") or {}).get("url")
        if not server_url or not isinstance(server_url, str) or not server_url.strip():
            raise AamarvaError("FLOOR authorization failed: valid MCP serverUrl is missing in response.", code="FLOOR_EXECUTION_FAILED")

        grant = data.get("grant")
        if not grant or not isinstance(grant, dict):
            raise AamarvaError("FLOOR authorization failed: grant details missing in response.", code="FLOOR_EXECUTION_FAILED")

        return {
            "invocationId": returned_iid,
            "toolId": str(data.get("toolId") or ""),
            "status": "approved",
            "serverUrl": server_url.strip(),
            "auth": data.get("auth") or data.get("authentication"),
            "grant": grant,
        }

    def execute_floor_tool(
        self,
        tool_id: str,
        arguments: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        invocation_id: Optional[str] = None,
    ) -> FloorToolInvokeResult:
        """
        Execute a FLOOR tool via the platform's 5-step zero-trust governance sequence:
        Discovery -> Access evaluation -> Execute authorization -> External MCP invocation -> Return result.
        """
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")

        # Step A: Tool discovery
        tools = self.get_floor_tools()
        tool = next((t for t in tools if t.id == tool_id.strip()), None)
        if not tool:
            raise AamarvaError(f'Tool "{tool_id}" not found in available fleet tools.', code="FLOOR_TOOL_NOT_FOUND")

        # Step B: Access evaluation
        access_status = (tool.accessStatus or "").strip().lower()
        has_grant = access_status in ["authorized", "granted", "approved"]

        resolved_invocation_id = invocation_id
        if not has_grant and not resolved_invocation_id:
            inv_res = self.create_floor_invocation(tool_id.strip(), reason=reason or "Agent requested execution", arguments=arguments)
            if inv_res["status"] == "pending":
                req_id = inv_res.get("requestId") or inv_res.get("invocationId")
                raise AamarvaError(
                    f'Agent is not authorized to execute tool "{tool_id}". Access request {req_id} is pending human approval.',
                    code="FLOOR_ACCESS_DENIED",
                )
            if inv_res["status"] in ["denied", "rejected", "revoked", "expired"]:
                raise AamarvaError(
                    f'Agent access to tool "{tool_id}" was denied (status: {inv_res["status"]}).',
                    code="FLOOR_ACCESS_DENIED",
                )
            resolved_invocation_id = inv_res["invocationId"]

        if not resolved_invocation_id:
            inv_res = self.create_floor_invocation(tool_id.strip(), reason=reason or "Authorized execution run", arguments=arguments)
            resolved_invocation_id = inv_res["invocationId"]

        # Step C & D: Obtain execution authorization from platform
        auth_details = self.obtain_floor_execution_authorization(resolved_invocation_id, arguments=arguments)

        if auth_details["status"] != "approved":
            raise AamarvaError(f"FLOOR execution denied: status is '{auth_details['status']}'.", code="FLOOR_ACCESS_DENIED")

        if auth_details.get("toolId") and auth_details["toolId"].strip() != tool_id.strip():
            raise AamarvaError(
                f'FLOOR execution authorization mismatch: authorized tool "{auth_details["toolId"]}" does not match requested tool "{tool_id}".',
                code="FLOOR_EXECUTION_FAILED",
            )

        # Step E: Actual MCP tool execution over verified connection
        mcp_result = invoke_external_mcp_tool(
            server_url=auth_details["serverUrl"],
            tool_id=tool_id.strip(),
            args=arguments,
            auth=auth_details.get("auth"),
            input_schema=tool.inputSchema,
        )

        return FloorToolInvokeResult(
            status="approved",
            invocationId=resolved_invocation_id,
            toolId=tool_id.strip(),
            result=mcp_result,
            serverUrl=auth_details["serverUrl"],
        )

    def request_floor_access(self, tool_id: str, reason: Optional[str] = None) -> FloorToolInvokeResult:
        """
        Request access to a FLOOR tool.
        Maps to POST /api/floor/tools/:tool_id/invoke
        """
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")

        try:
            tools = self.get_floor_tools()
            existing = next((t for t in tools if t.id == tool_id.strip()), None)
            if existing and (existing.accessStatus or "").lower() in ["authorized", "granted", "approved"]:
                return FloorToolInvokeResult(
                    status="approved",
                    toolId=tool_id.strip(),
                    message="Tool access is already granted via persistent access policy.",
                )
        except Exception:
            pass

        inv = self.create_floor_invocation(tool_id.strip(), reason=reason)
        return FloorToolInvokeResult(
            status=inv.get("status") or "pending",
            requestId=inv.get("requestId") or inv.get("invocationId"),
            invocationId=inv.get("invocationId"),
            toolId=tool_id.strip(),
            message=inv.get("message") or "Access request submitted for approval.",
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

    def health(self) -> Dict[str, Any]:
        """
        Alias for get_adk_metadata(). Verifies API connectivity.
        Maps to GET /api/adk
        """
        return self.get_adk_metadata()

    def get_connection(self, connection_id: str) -> 'AamarvaConnection':
        """
        Retrieve a specific connection channel abstraction by ID.
        """
        conns = self.connections()
        for c in conns:
            if c.connectionId == connection_id:
                return c
        return AamarvaConnection(
            client=self,
            connectionId=connection_id,
            agentId="",
            status="active",
            createdAt=""
        )





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

