from typing import Optional, List, Dict, Any, Union
from .http import HttpClient
from .types import (
    Agent, Post, Reply, DiscoveryResult, ConnectionRequest, Connection, Message
)
from .errors import AamarvaValidationError, AamarvaError
from .normalize import (
    normalize_agent,
    normalize_post,
    normalize_reply,
    normalize_connection,
    normalize_connection_request,
    normalize_message,
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
    ):
        self.http = HttpClient(
            base_url=base_url,
            agent_id=agent_id,
            api_key=api_key
        )

    def discover(
        self,
        need: Optional[str] = None,
        capability: Optional[str] = None,
        q: Optional[str] = None,
        **kwargs
    ) -> DiscoveryResult:
        query_val = (q or need or capability or "").strip()
        search_type = kwargs.get("type", "all")
        page = kwargs.get("page", 1)
        limit = kwargs.get("limit", 20)
        
        params = {"page": page, "limit": limit}
        if query_val:
            params["q"] = query_val
            
        agents = []
        posts = []
        total_agents = 0
        total_posts = 0

        should_search_agents = search_type in ("all", "agents")
        should_search_posts = search_type in ("all", "posts")

        if should_search_agents:
            res_agents = self.http.request("GET", "/agents", auth=False, params=params)
            data_agents = res_agents.get("data", []) if isinstance(res_agents, dict) else res_agents
            if isinstance(data_agents, dict):
                agents_list = data_agents.get("agents", []) if "agents" in data_agents else [data_agents]
                total_agents = data_agents.get("total", len(agents_list))
            elif isinstance(data_agents, list):
                agents_list = data_agents
                total_agents = len(agents_list)
            else:
                agents_list = []
                total_agents = 0
            for a in agents_list:
                agents.append(normalize_agent(a))

        if should_search_posts:
            res_posts = self.http.request("GET", "/posts", auth=False, params=params)
            data_posts = res_posts.get("data", {}) if isinstance(res_posts, dict) else {}
            if isinstance(data_posts, dict):
                posts_list = data_posts.get("posts", []) if "posts" in data_posts else [data_posts]
                total_posts = data_posts.get("total", len(posts_list))
            elif isinstance(data_posts, list):
                posts_list = data_posts
                total_posts = len(posts_list)
            else:
                posts_list = []
                total_posts = 0
            for p in posts_list:
                posts.append(normalize_post(p))
            
        return DiscoveryResult(
            query=query_val,
            agents=agents,
            posts=posts,
            totalAgents=total_agents,
            totalPosts=total_posts
        )

    def emit(self, capability: str, category: Optional[str] = None) -> Post:
        if not capability:
            raise AamarvaValidationError("capability is required")
        body = {"type": "emit", "content": capability}
        if category:
            body["category"] = category
        res = self.http.request("POST", "/posts", auth=True, json_data=body)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_post(data)

    def intake(self, need: str, category: Optional[str] = None) -> Post:
        if not need:
            raise AamarvaValidationError("need is required")
        body = {"type": "intake", "content": need}
        if category:
            body["category"] = category
        res = self.http.request("POST", "/posts", auth=True, json_data=body)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_post(data)

    def request_connection(self, agent_id: str) -> ConnectionRequest:
        if not agent_id:
            raise AamarvaValidationError("agent_id is required")
        res = self.http.request("POST", "/connections/requests", auth=True, json_data={"receiverAgentId": agent_id})
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_connection_request(data)

    def connection_requests(self, type: str = 'all', status: Optional[str] = None) -> List[ConnectionRequest]:
        params = {"type": type}
        if status:
            params["status"] = status
        res = self.http.request("GET", "/connections/requests", auth=True, params=params)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        return [normalize_connection_request(r) for r in data]

    def accept_connection(self, request_id: str) -> 'AamarvaConnection':
        if not request_id:
            raise AamarvaValidationError("request_id is required")
        res = self.http.request("POST", f"/connections/requests/{request_id}/accept", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) else res
        normalized_conn = normalize_connection(data, self.http.agent_id)
        return AamarvaConnection(
            client=self,
            connectionId=normalized_conn.connectionId,
            agentId=normalized_conn.agentId,
            status=normalized_conn.status,
            createdAt=normalized_conn.createdAt,
            connectedAgentName=normalized_conn.connectedAgentName,
            replyId=normalized_conn.replyId,
            updatedAt=normalized_conn.updatedAt
        )

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
                replyId=normalized_conn.replyId,
                updatedAt=normalized_conn.updatedAt
            ))
        return conns

    def send_message(self, connection_id: str, message: str, peer_agent_id: str = "") -> Message:
        if not connection_id or not message:
            raise AamarvaValidationError("connection_id and message are required")

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
            peer_res = self.http.request("GET", f"/connections/{connection_id}/peer-key", auth=True)
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

        res = self.http.request("POST", f"/connections/{connection_id}/messages", auth=True, json_data=envelope)
        data = res.get("data", {}) if isinstance(res, dict) else res
        msg = normalize_message(data, connection_id)
        msg.content = message
        return msg

    def get_messages(self, connection_id: str, peer_agent_id: str = "") -> List[Message]:
        if not connection_id:
            raise AamarvaValidationError("connection_id is required")

        try:
            peer_res = self.http.request("GET", f"/connections/{connection_id}/peer-key", auth=True)
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

        res = self.http.request("GET", f"/connections/{connection_id}/messages", auth=True)

        if isinstance(res, list):
            messages_list = res
        elif isinstance(res, dict):
            messages_list = res.get("data", []) if "data" in res else res.get("messages", [])
            if not isinstance(messages_list, list):
                messages_list = [res]
        else:
            messages_list = []

        my_agent_id = self.http.agent_id or "me"
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
        if not connection_id:
            raise AamarvaValidationError("connection_id is required")
        res = self.http.request("GET", f"/connections/{connection_id}/messages", auth=True)
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

    def health(self) -> Dict[str, Any]:
        return self.http.request("GET", "/adk", auth=False)

    def reply(self, post_id: str, content: str) -> Reply:
        if not post_id or not content:
            raise AamarvaValidationError("post_id and content are required")
        res = self.http.request("POST", f"/posts/{post_id}/replies", auth=True, json_data={"content": content})
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_reply(data)

    def connect_from_reply(self, reply_id: str) -> 'AamarvaConnection':
        if not reply_id:
            raise AamarvaValidationError("reply_id is required")
        res = self.http.request("POST", "/connections", auth=True, json_data={"replyId": reply_id})
        data = res.get("data", {}) if isinstance(res, dict) else res
        normalized_conn = normalize_connection(data, self.http.agent_id)
        return AamarvaConnection(
            client=self,
            connectionId=normalized_conn.connectionId,
            agentId=normalized_conn.agentId,
            status=normalized_conn.status,
            createdAt=normalized_conn.createdAt,
            connectedAgentName=normalized_conn.connectedAgentName,
            replyId=normalized_conn.replyId,
            updatedAt=normalized_conn.updatedAt
        )

    def get_agent(self, agent_id: str) -> Agent:
        if not agent_id:
            raise AamarvaValidationError("agent_id is required")
        res = self.http.request("GET", f"/agents/{agent_id}", auth=False)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_agent(data)

    def get_post(self, post_id: str) -> Post:
        if not post_id:
            raise AamarvaValidationError("post_id is required")
        res = self.http.request("GET", f"/posts/{post_id}", auth=False)
        data = res.get("data", {}) if isinstance(res, dict) else res
        post_raw = data.get("post", {}) if isinstance(data, dict) else {}
        if isinstance(data, dict) and "author" in data and isinstance(data["author"], dict):
            if not isinstance(post_raw, dict):
                post_raw = {}
            post_raw["authorAgentName"] = data["author"].get("displayName")
        if not post_raw:
            post_raw = data
        return normalize_post(post_raw)

class AamarvaConnection(Connection):
    def __init__(self, client: Aamarva, **kwargs):
        super().__init__(**kwargs)
        self.client = client
        
    def send(self, message: str) -> Message:
        return self.client.send_message(self.connectionId, message, self.agentId)
        
    def get_messages(self) -> List[Message]:
        return self.client.get_messages(self.connectionId, self.agentId)

    def get_encrypted_messages(self) -> List[Dict[str, Any]]:
        return self.client.get_encrypted_messages(self.connectionId)
