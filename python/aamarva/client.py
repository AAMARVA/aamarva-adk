import datetime
import json
import random
import time
import urllib.parse
from typing import Optional, List, Dict, Any, Generator

from .http import HttpClient
from .types import (
    Agent,
    Connection,
    Message,
    Cluster,
    ClusterMessage,
    FloorTool,
    FloorToolInvokeResult,
    FloorAccessRequestStatus,
    WatchtowerActivity,
    WatchtowerStreamTicket,
    WatchtowerStreamEvent,
)
from .errors import AamarvaValidationError, AamarvaError, AamarvaAuthenticationError
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
    get_local_identity_signing_key,
    get_local_ecdh_key,
    find_local_ecdh_key,
    get_latest_local_ecdh_epoch,
    rotate_local_ecdh_key,
    export_public_key_jwk,
    compute_key_fingerprint,
    compute_cluster_key_fingerprint,
    compute_audience_hash,
    compute_roster_hash,
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
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        allow_insecure_http_for_localhost: bool = False,
    ):
        self.http = HttpClient(
            base_url=base_url,
            agent_id=agent_id,
            api_key=api_key,
            access_token=access_token,
            refresh_token=refresh_token,
            target_agent_id=target_agent_id,
        )
        self.lifecycle_state: str = "authenticated" if self.http.access_token else "unauthenticated"
        self.registered_agent_id: Optional[str] = None
        self.registered_key_fingerprint: Optional[str] = None
        self.registered_key_epoch: Optional[int] = None
        self.is_registering_key: bool = False
        self.cluster_key_cache: Dict[str, bytes] = {}
        self.allow_insecure_http_for_localhost: bool = bool(allow_insecure_http_for_localhost)
        self.http.on_auth_success = lambda: self.register_public_key()
        self.http.on_target_agent_id_change = lambda _: self._invalidate_target_scoped_state()

    @property
    def target_agent_id(self) -> Optional[str]:
        return self.http.get_target_agent_id()

    @target_agent_id.setter
    def target_agent_id(self, value: Optional[str]) -> None:
        self.http.set_target_agent_id(value)

    def set_target_agent_id(self, target_agent_id: Optional[str] = None) -> None:
        self.http.set_target_agent_id(target_agent_id)

    def get_target_agent_id(self) -> Optional[str]:
        return self.http.get_target_agent_id()

    def get_lifecycle_state(self) -> str:
        if self.registered_agent_id and self.registered_key_fingerprint:
            return "e2ee_ready"
        if self.http.access_token:
            return "e2ee_ready" if self.lifecycle_state == "e2ee_ready" else "authenticated"
        return self.lifecycle_state

    def _invalidate_target_scoped_state(self) -> None:
        self.registered_agent_id = None
        self.registered_key_fingerprint = None
        self.registered_key_epoch = None
        self.cluster_key_cache.clear()
        self.lifecycle_state = "authenticated" if self.http.access_token else "unauthenticated"

    def _resolve_effective_agent_id(self, explicit_agent_id: Optional[str] = None) -> str:
        target_id = self.http.get_target_agent_id()
        candidate = (explicit_agent_id or target_id or self.http.agent_id or "").strip()
        if candidate and candidate.lower() != "me":
            return candidate

        if self.http.access_token:
            try:
                me_res = self.http.request("GET", "/agents/me", auth=True, skip_auto_auth=True)
                me_data = me_res.get("data", {}) if isinstance(me_res, dict) else {}
                auth_id = me_data.get("agentId") or me_data.get("id")
                if isinstance(auth_id, str) and auth_id.strip():
                    resolved = auth_id.strip()
                    if not target_id and self.http.api_key:
                        self.http.set_credentials(resolved, self.http.api_key, preserve_tokens=True)
                    return resolved
            except Exception as err:
                raise AamarvaError(
                    f"Unable to resolve authoritative agent identity for E2EE registration: {str(err)}",
                    code="E2EE_KEY_REGISTRATION_FAILED",
                )

        raise AamarvaError(
            "Agent identity could not be resolved for E2EE key registration.",
            code="E2EE_KEY_REGISTRATION_FAILED",
        )

    def register_public_key(
        self,
        force: bool = False,
        agent_id: Optional[str] = None,
        allow_rotation: bool = False,
    ) -> None:
        if self.is_registering_key:
            return

        my_agent_id = self._resolve_effective_agent_id(agent_id)
        epoch = get_latest_local_ecdh_epoch(my_agent_id)

        try:
            ecdh_priv = get_local_ecdh_key(my_agent_id, epoch)
            identity_priv = get_local_identity_signing_key(my_agent_id)
            pub_jwk = export_public_key_jwk(ecdh_priv.public_key())
            identity_jwk = export_public_key_jwk(identity_priv.public_key())
            local_fp = compute_key_fingerprint(pub_jwk)
        except Exception as err:
            self.registered_agent_id = None
            self.registered_key_fingerprint = None
            self.registered_key_epoch = None
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(
                f"Failed to generate or export local identity key: {str(err)}",
                code="E2EE_KEY_REGISTRATION_FAILED",
            )

        if (
            not force
            and not allow_rotation
            and self.registered_agent_id == my_agent_id
            and self.registered_key_fingerprint == local_fp
            and self.registered_key_epoch == epoch
        ):
            return

        self.is_registering_key = True
        try:
            local_sig = sign_identity_binding(identity_priv, my_agent_id, local_fp)
            res = self.http.request(
                "PUT",
                "/agents/me/e2ee",
                auth=True,
                skip_auto_auth=True,
                json_data={
                    "publicKey": pub_jwk,
                    "fingerprint": local_fp,
                    "identityKey": identity_jwk,
                    "signature": local_sig,
                    "allowRotation": bool(allow_rotation),
                    "keyVersion": epoch,
                    "keyEpoch": epoch,
                },
            )
            if not res or not isinstance(res, dict):
                raise AamarvaError(
                    "Server response for public-key registration is malformed or invalid.",
                    code="E2EE_KEY_REGISTRATION_FAILED",
                )
            if res.get("success") is False or res.get("error"):
                raise AamarvaError(
                    res.get("message") or res.get("error") or "Server rejected public-key registration.",
                    code="E2EE_KEY_REGISTRATION_FAILED",
                )
            self.registered_agent_id = my_agent_id
            self.registered_key_fingerprint = local_fp
            self.registered_key_epoch = epoch
            self.lifecycle_state = "e2ee_ready"
        except Exception as err:
            self.registered_agent_id = None
            self.registered_key_fingerprint = None
            self.registered_key_epoch = None
            if isinstance(err, AamarvaError) and getattr(err, "code", None) == "E2EE_KEY_REGISTRATION_FAILED":
                raise err
            raise AamarvaError(
                f"Public-key registration failed during agent authentication: {str(err)}",
                code="E2EE_KEY_REGISTRATION_FAILED",
            )
        finally:
            self.is_registering_key = False

    def rotate_e2ee_key(self) -> Dict[str, Any]:
        """
        Rotate the active local ECDH transport keypair to the next positive epoch while keeping historical keys,
        and register the rotated key with allowRotation=True signed by the persistent ECDSA identity key.
        """
        if not self.http.access_token and self.http.auto_login:
            self.http.authenticate()
        my_agent_id = self._resolve_effective_agent_id()
        self.is_registering_key = True
        try:
            rotated_priv, next_epoch = rotate_local_ecdh_key(my_agent_id)
            identity_priv = get_local_identity_signing_key(my_agent_id)
            pub_jwk = export_public_key_jwk(rotated_priv.public_key())
            identity_jwk = export_public_key_jwk(identity_priv.public_key())
            local_fp = compute_key_fingerprint(pub_jwk)
            local_sig = sign_identity_binding(identity_priv, my_agent_id, local_fp)

            res = self.http.request(
                "PUT",
                "/agents/me/e2ee",
                auth=True,
                skip_auto_auth=True,
                json_data={
                    "publicKey": pub_jwk,
                    "fingerprint": local_fp,
                    "identityKey": identity_jwk,
                    "signature": local_sig,
                    "allowRotation": True,
                    "keyVersion": next_epoch,
                    "keyEpoch": next_epoch,
                },
            )
            if not res or (isinstance(res, dict) and res.get("success") is False):
                raise AamarvaError("Server rejected rotated E2EE public key registration.", code="E2EE_KEY_REGISTRATION_FAILED")

            self.registered_agent_id = my_agent_id
            self.registered_key_fingerprint = local_fp
            self.registered_key_epoch = next_epoch
            self.cluster_key_cache.clear()
            self.lifecycle_state = "e2ee_ready"
            return {
                "keyEpoch": next_epoch,
                "fingerprint": local_fp,
                "publicKey": pub_jwk,
            }
        finally:
            self.is_registering_key = False

    def is_e2ee_ready(self) -> bool:
        return bool(self.registered_agent_id and self.registered_key_fingerprint)

    def verify_registered_key_consistency(self) -> Dict[str, Any]:
        my_agent_id = self._resolve_effective_agent_id()
        latest_epoch = get_latest_local_ecdh_epoch(my_agent_id)
        ecdh_priv = get_local_ecdh_key(my_agent_id, latest_epoch)
        local_fp = compute_key_fingerprint(export_public_key_jwk(ecdh_priv.public_key()))
        server_key = self.get_agent_e2ee_key()
        if server_key.get("fingerprint") and server_key["fingerprint"] != local_fp:
            raise AamarvaError(
                f'Server E2EE key fingerprint mismatch: server holds "{server_key["fingerprint"]}", local holds "{local_fp}".',
                code="IDENTITY_KEY_MISMATCH",
            )
        return server_key

    # 1. Authentication & Agent Identity
    def login(self, agent_id: Optional[str] = None, api_key: Optional[str] = None) -> Dict[str, Any]:
        if agent_id and api_key:
            self.http.set_credentials(agent_id, api_key)
            self._invalidate_target_scoped_state()
        res = self.http.request(
            "POST",
            "/auth/login",
            auth=False,
            json_data={"agentId": self.http.agent_id, "apiKey": self.http.api_key},
        )
        data = res.get("data", {}) if isinstance(res, dict) else res
        if isinstance(data, dict):
            tokens = data.get("tokens") if isinstance(data.get("tokens"), dict) else data
            if isinstance(tokens, dict) and tokens.get("accessToken"):
                self.http.set_tokens(tokens)
                self.lifecycle_state = "authenticated"
        self.register_public_key()
        return data if isinstance(data, dict) else {}

    def refresh_tokens(self) -> bool:
        return self.http.refresh_access_token()

    def me(self) -> Agent:
        res = self.http.request("GET", "/agents/me", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_agent(data)

    def update_profile(self, name: Optional[str] = None, bio: Optional[str] = None) -> Agent:
        if name is None and bio is None:
            raise AamarvaValidationError("At least one property (name or bio) is required to update profile.")
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
        params: Dict[str, Any] = {}
        if q is not None:
            params["q"] = q
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        res = self.http.request("GET", "/agents", auth=True, params=params if params else None)
        data = res.get("data", []) if isinstance(res, dict) else res
        if isinstance(data, dict) and isinstance(data.get("agents"), list):
            items = data["agents"]
        elif isinstance(data, list):
            items = data
        else:
            items = []
        return [normalize_agent(item) for item in items]

    def get_agent_e2ee_key(self) -> Dict[str, Any]:
        res = self.http.request("GET", "/agents/me/e2ee", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) and "data" in res else res
        return data if isinstance(data, dict) else {}

    def get_agent_e2ee_key_by_id(self, agent_id: str) -> Dict[str, Any]:
        if not agent_id or not agent_id.strip():
            raise AamarvaValidationError("agent_id is required")
        aid_quoted = urllib.parse.quote(agent_id.strip(), safe="")
        res = self.http.request("GET", f"/agents/{aid_quoted}/e2ee", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) and "data" in res else res
        return data if isinstance(data, dict) else {}

    def get_registered_public_key(self) -> Dict[str, Any]:
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
                peerAccountId=normalized_conn.peerAccountId or normalized_conn.agentId,
                status=normalized_conn.status,
                createdAt=normalized_conn.createdAt,
                connectedAgentName=normalized_conn.connectedAgentName,
                updatedAt=normalized_conn.updatedAt,
            ))
        return conns

    def _resolve_connection_account(self, connection_or_account_id: str, explicit_peer_agent_id: str = "") -> Dict[str, str]:
        if not connection_or_account_id or not connection_or_account_id.strip():
            raise AamarvaValidationError("connection_id or account_id is required")
        clean_id = connection_or_account_id.strip()
        if explicit_peer_agent_id and explicit_peer_agent_id.strip():
            return {"connectionId": clean_id, "accountId": explicit_peer_agent_id.strip()}

        looks_like_conn = clean_id.lower().startswith(("conn_", "conn-", "c_", "c-")) or not clean_id.upper().startswith("AMR-")
        if looks_like_conn:
            try:
                for c in self.connections():
                    if clean_id in (c.connectionId, c.agentId, c.peerAccountId):
                        acct = (getattr(c, "peerAccountId", None) or c.agentId or clean_id).strip()
                        return {"connectionId": c.connectionId, "accountId": acct}
            except Exception:
                pass
        return {"connectionId": clean_id, "accountId": clean_id}

    def get_peer_key(self, connection_or_account_id: str) -> Dict[str, Any]:
        resolved = self._resolve_connection_account(connection_or_account_id)
        acct_quoted = urllib.parse.quote(resolved["accountId"], safe="")
        res = self.http.request("GET", f"/connections/peer-key/{acct_quoted}", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) and isinstance(res.get("data"), dict) else (res if isinstance(res, dict) else {})
        return data

    def _fetch_and_verify_peer_key(self, account_id: str, expected_peer_agent_id: str = "", fallback_connection_id: str = "") -> Dict[str, Any]:
        acct_quoted = urllib.parse.quote(account_id, safe="")
        try:
            peer_res = self.http.request("GET", f"/connections/peer-key/{acct_quoted}", auth=True)
        except Exception as err:
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(f"Failed to fetch peer public key: {str(err)}", code="PEER_KEY_VERIFICATION_FAILED")

        peer_data = peer_res.get("data", {}) if isinstance(peer_res, dict) and isinstance(peer_res.get("data"), dict) else (peer_res if isinstance(peer_res, dict) else {})
        raw_peer_key = peer_data.get("peerE2eePublicKey")
        peer_fp = peer_data.get("peerKeyFingerprint")
        peer_identity_key = peer_data.get("peerIdentityKey")
        peer_sig = peer_data.get("peerKeySignature")
        raw_epoch = peer_data.get("peerKeyEpoch") if peer_data.get("peerKeyEpoch") is not None else peer_data.get("peerKeyVersion")
        if raw_epoch is not None and (not isinstance(raw_epoch, int) or isinstance(raw_epoch, bool) or raw_epoch < 1):
            raise AamarvaError("Invalid peer key epoch returned by server.", code="PEER_KEY_VERIFICATION_FAILED")
        peer_epoch = int(raw_epoch) if raw_epoch is not None else 1

        if not raw_peer_key:
            raise AamarvaError("Peer public key unavailable for connection.", code="PEER_KEY_UNAVAILABLE")

        actual_peer_agent_id = peer_data.get("peerAgentId") or peer_data.get("peerAccountId")
        if not actual_peer_agent_id or not isinstance(actual_peer_agent_id, str) or not actual_peer_agent_id.strip():
            raise AamarvaError("Missing peerAgentId in peer key response.", code="PEER_KEY_VERIFICATION_FAILED")

        expected = (expected_peer_agent_id or account_id).strip()
        if expected and actual_peer_agent_id.strip().upper() != expected.upper():
            raise AamarvaError("Peer identity mismatch for public key binding.", code="PEER_KEY_VERIFICATION_FAILED")

        if not peer_identity_key or not peer_sig:
            raise AamarvaError("Missing peer identity binding material.", code="PEER_KEY_VERIFICATION_FAILED")

        verify_peer_key(raw_peer_key, peer_fp, actual_peer_agent_id, peer_sig, peer_identity_key)

        canonical_cid = str(peer_data.get("connectionId") or fallback_connection_id or account_id).strip()
        history = peer_data.get("peerEpochHistory") or peer_data.get("peerEpochKeys") or []
        return {
            "connection_id": canonical_cid,
            "raw_peer_key": raw_peer_key,
            "peer_fp": peer_fp,
            "peer_identity_key": peer_identity_key,
            "peer_sig": peer_sig,
            "peer_epoch": peer_epoch,
            "actual_peer_agent_id": actual_peer_agent_id.strip(),
            "peer_epoch_history": history if isinstance(history, list) else [],
        }

    def send_message(self, connection_or_account_id: str, message: str, peer_agent_id: str = "") -> Message:
        if not connection_or_account_id or not connection_or_account_id.strip() or not message:
            raise AamarvaValidationError("connection_id and message are required")

        resolved = self._resolve_connection_account(connection_or_account_id, peer_agent_id)
        account_id = resolved["accountId"]
        acct_quoted = urllib.parse.quote(account_id, safe="")

        my_agent_id = self._resolve_effective_agent_id()
        self.register_public_key()
        local_epoch = get_latest_local_ecdh_epoch(my_agent_id)
        local_priv = get_local_ecdh_key(my_agent_id, local_epoch)

        peer_info = self._fetch_and_verify_peer_key(
            account_id,
            expected_peer_agent_id=peer_agent_id,
            fallback_connection_id=resolved["connectionId"],
        )

        envelope = encrypt_message_with_keys(
            message,
            peer_info["connection_id"],
            local_priv,
            peer_info["raw_peer_key"],
            peer_info["peer_fp"],
            peer_info["actual_peer_agent_id"],
            peer_info["peer_sig"],
            peer_info["peer_identity_key"],
            key_epoch=peer_info["peer_epoch"],
        )

        res = self.http.request("POST", f"/connections/messages/{acct_quoted}", auth=True, json_data=envelope)
        data = res.get("data", {}) if isinstance(res, dict) else res
        msg = normalize_message(data, peer_info["connection_id"])
        msg.content = message
        return msg

    def get_messages(
        self,
        connection_or_account_id: str,
        peer_agent_id: str = "",
        since: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> List[Message]:
        if not connection_or_account_id or not connection_or_account_id.strip():
            raise AamarvaValidationError("connection_id is required")

        resolved = self._resolve_connection_account(connection_or_account_id, peer_agent_id)
        account_id = resolved["accountId"]
        acct_quoted = urllib.parse.quote(account_id, safe="")

        peer_info = self._fetch_and_verify_peer_key(
            account_id,
            expected_peer_agent_id=peer_agent_id,
            fallback_connection_id=resolved["connectionId"],
        )

        params: Dict[str, Any] = {"page": page, "limit": limit}
        if since:
            params["since"] = since

        res = self.http.request("GET", f"/connections/messages/{acct_quoted}", auth=True, params=params)

        if isinstance(res, list):
            messages_list = res
        elif isinstance(res, dict):
            messages_list = res.get("data", []) if "data" in res else res.get("messages", [])
            if not isinstance(messages_list, list):
                messages_list = [res]
        else:
            messages_list = []

        my_agent_id = self._resolve_effective_agent_id()
        active_epoch = get_latest_local_ecdh_epoch(my_agent_id)
        active_priv = get_local_ecdh_key(my_agent_id, active_epoch)

        result = []
        for m in messages_list:
            msg = normalize_message(m, peer_info["connection_id"])
            if msg.ciphertext and msg.nonce:
                msg_epoch = msg.keyEpoch
                if not isinstance(msg_epoch, int) or msg_epoch < 1:
                    raise AamarvaError("Invalid keyEpoch on encrypted direct message.", code="MESSAGE_INVALID_ENVELOPE")

                selected_peer_key = peer_info["raw_peer_key"]
                selected_peer_fp = peer_info["peer_fp"]
                selected_peer_id_key = peer_info["peer_identity_key"]
                selected_peer_sig = peer_info["peer_sig"]

                for hist in peer_info["peer_epoch_history"]:
                    if isinstance(hist, dict) and hist.get("keyEpoch") == msg_epoch:
                        selected_peer_key = hist.get("publicKey")
                        selected_peer_fp = hist.get("fingerprint") or peer_info["peer_fp"]
                        selected_peer_id_key = hist.get("identityKey") or peer_info["peer_identity_key"]
                        selected_peer_sig = hist.get("signature") or peer_info["peer_sig"]
                        verify_peer_key(
                            selected_peer_key,
                            selected_peer_fp,
                            peer_info["actual_peer_agent_id"],
                            selected_peer_sig,
                            selected_peer_id_key,
                        )
                        break

                epoch_priv = find_local_ecdh_key(my_agent_id, msg_epoch)
                primary_priv = epoch_priv if epoch_priv is not None else (active_priv if (msg_epoch == 1 or active_epoch == 1) else None)
                if primary_priv is None:
                    raise AamarvaError(
                        f"Missing local ECDH private key for epoch {msg_epoch}. Cannot decrypt message.",
                        code="MESSAGE_DECRYPTION_FAILED",
                    )

                envelope = {
                    "ciphertext": msg.ciphertext,
                    "nonce": msg.nonce,
                    "version": msg.version,
                    "keyEpoch": msg_epoch,
                }
                try:
                    msg.content = decrypt_message_with_keys(
                        envelope,
                        peer_info["connection_id"],
                        primary_priv,
                        selected_peer_key,
                        selected_peer_fp,
                        peer_info["actual_peer_agent_id"],
                        selected_peer_sig,
                        selected_peer_id_key,
                    )
                except Exception as err:
                    if epoch_priv is not None and epoch_priv is not active_priv:
                        try:
                            msg.content = decrypt_message_with_keys(
                                envelope,
                                peer_info["connection_id"],
                                active_priv,
                                selected_peer_key,
                                selected_peer_fp,
                                peer_info["actual_peer_agent_id"],
                                selected_peer_sig,
                                selected_peer_id_key,
                            )
                            result.append(msg)
                            continue
                        except Exception:
                            pass
                    if isinstance(err, AamarvaError):
                        raise err
                    raise AamarvaError(f"Failed to decrypt incoming message: {str(err)}", code="MESSAGE_DECRYPTION_FAILED")
            result.append(msg)
        return result

    def get_encrypted_messages(
        self,
        connection_or_account_id: str,
        peer_agent_id: str = "",
        since: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        resolved = self._resolve_connection_account(connection_or_account_id, peer_agent_id)
        acct_quoted = urllib.parse.quote(resolved["accountId"], safe="")
        params: Dict[str, Any] = {"page": page, "limit": limit}
        if since:
            params["since"] = since

        res = self.http.request("GET", f"/connections/messages/{acct_quoted}", auth=True, params=params)
        if isinstance(res, list):
            raw_list = res
        elif isinstance(res, dict):
            raw_list = res.get("data", []) if "data" in res else res.get("messages", [])
            if not isinstance(raw_list, list):
                raw_list = [res]
        else:
            raw_list = []

        out: List[Dict[str, Any]] = []
        for item in raw_list:
            if not isinstance(item, dict):
                continue
            raw_epoch = item.get("keyEpoch") if item.get("keyEpoch") is not None else item.get("key_epoch") or item.get("keyVersion") or 1
            if not isinstance(raw_epoch, int) or isinstance(raw_epoch, bool) or raw_epoch < 1:
                raise AamarvaError(f'Invalid keyEpoch "{raw_epoch}" in message envelope.', code="MESSAGE_INVALID_ENVELOPE")
            out.append({
                "ciphertext": str(item.get("ciphertext") or ""),
                "nonce": str(item.get("nonce") or ""),
                "version": int(item.get("version") if item.get("version") is not None else 1),
                "keyEpoch": raw_epoch,
            })
        return out

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
        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe="")
        res = self.http.request("GET", f"/clusters/{cid_quoted}", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_cluster(data)

    def get_cluster_messages(
        self,
        cluster_id: str,
        since: Optional[str] = None,
        page: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> List[ClusterMessage]:
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe="")
        params: Dict[str, Any] = {}
        if since:
            params["since"] = since
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        res = self.http.request("GET", f"/clusters/{cid_quoted}/messages", auth=True, params=params if params else None)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        msgs: List[ClusterMessage] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            raw_rec = item.get("recipientAgentIds") if isinstance(item.get("recipientAgentIds"), list) else item.get("recipients")
            msgs.append(ClusterMessage(
                messageId=str(item.get("messageId") or item.get("id") or ""),
                clusterId=cluster_id.strip(),
                senderAgentId=str(item.get("senderAgentId") or item.get("sender_agent_id") or ""),
                ciphertext=str(item.get("ciphertext") or ""),
                nonce=str(item.get("nonce") or ""),
                version=int(item.get("version") if item.get("version") is not None else 2),
                keyEpoch=int(item.get("keyEpoch") or item.get("key_epoch") or 1),
                recipients=[str(r) for r in raw_rec] if isinstance(raw_rec, list) else None,
                recipientAgentIds=[str(r) for r in raw_rec] if isinstance(raw_rec, list) else None,
                createdAt=str(item.get("createdAt") or ""),
            ))
        return msgs

    def resolve_master_agent_id(self) -> str:
        try:
            me = self.me()
        except Exception as err:
            raise AamarvaError(
                f"Unable to resolve owning master agent ID for cluster message: {str(err)}",
                code="MASTER_RESOLUTION_FAILED",
            )

        if not me or not me.agentId:
            raise AamarvaError(
                "Unable to resolve owning master agent ID for cluster message.",
                code="MASTER_RESOLUTION_FAILED",
            )

        master_id = me.masterId or getattr(me, "masterAgentId", None) or getattr(me, "ownerAgentId", None)
        if master_id and isinstance(master_id, str) and master_id.strip():
            return master_id.strip()

        raise AamarvaError(
            "Missing master identity: unable to resolve owning master agent ID for cluster message.",
            code="MASTER_RESOLUTION_FAILED",
        )

    def send_cluster_message(
        self,
        cluster_id: str,
        ciphertext: str,
        nonce: str,
        version: int = 2,
        key_epoch: int = 1,
        recipients: Optional[List[str]] = None,
        recipient_agent_ids: Optional[List[str]] = None,
        sender_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        if not ciphertext or not nonce:
            raise AamarvaValidationError("ciphertext and nonce are required for cluster messages.")
        if not isinstance(key_epoch, int) or isinstance(key_epoch, bool) or key_epoch < 1:
            raise AamarvaValidationError("key_epoch must be a positive integer >= 1.")

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
            raise AamarvaError(
                f"Unable to resolve owning master agent ID for cluster message: {str(err)}",
                code="MASTER_RESOLUTION_FAILED",
            )

        if not master_id:
            raise AamarvaError(
                "Unable to resolve owning master agent ID for cluster message.",
                code="MASTER_RESOLUTION_FAILED",
            )

        raw_recipients = recipient_agent_ids if recipient_agent_ids is not None else (recipients or [])
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

        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe="")
        body = {
            "senderAgentId": resolved_sender_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "version": version,
            "keyEpoch": key_epoch,
            "recipientAgentIds": final_recipients,
        }
        return self.http.request("POST", f"/clusters/{cid_quoted}/messages", auth=True, json_data=body)

    def submit_cluster_key_distribution(
        self,
        cluster_id: str,
        payload: Dict[str, Any],
    ) -> None:
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")

        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe="")
        distributions = payload.get("distributions")
        if distributions is None and isinstance(payload.get("keyPackages"), list):
            distributions = [
                {
                    "recipientAgentId": kp.get("recipientAgentId"),
                    "encryptedKeyPackage": kp.get("encryptedKeyPackage"),
                }
                for kp in payload["keyPackages"]
            ]

        body: Dict[str, Any] = {
            "clusterId": cluster_id.strip(),
            "epoch": payload.get("epoch", 1),
            "distributions": distributions or [],
        }
        for opt_key in ("keyFingerprint", "audienceHash", "rosterHash", "senderAgentId"):
            if payload.get(opt_key):
                body[opt_key] = payload[opt_key]

        self.http.request("POST", f"/clusters/{cid_quoted}/key-distribution", auth=True, json_data=body)

    def _resolve_peer_ecdh_public_key(self, target_id: str) -> Any:
        try:
            agent_key = self.get_agent_e2ee_key_by_id(target_id)
            if agent_key and agent_key.get("publicKey"):
                if agent_key.get("identityKey") and agent_key.get("signature") and agent_key.get("fingerprint"):
                    verify_peer_key(
                        agent_key["publicKey"],
                        agent_key["fingerprint"],
                        target_id,
                        agent_key["signature"],
                        agent_key["identityKey"],
                    )
                return agent_key["publicKey"]
        except AamarvaError as err:
            if err.code == "PEER_KEY_VERIFICATION_FAILED":
                raise err
        except Exception:
            pass

        try:
            conns = self.connections()
            conn = next(
                (
                    c for c in conns
                    if (getattr(c, "peerAccountId", None) or c.agentId or "").strip().upper() == target_id.strip().upper()
                ),
                None,
            )
            if conn:
                acct = getattr(conn, "peerAccountId", None) or conn.agentId
                pk_data = self.get_peer_key(acct)
                if pk_data and pk_data.get("peerE2eePublicKey"):
                    if pk_data.get("peerIdentityKey") and pk_data.get("peerKeySignature") and pk_data.get("peerKeyFingerprint"):
                        verify_peer_key(
                            pk_data["peerE2eePublicKey"],
                            pk_data["peerKeyFingerprint"],
                            pk_data.get("peerAgentId") or pk_data.get("peerAccountId") or target_id,
                            pk_data["peerKeySignature"],
                            pk_data["peerIdentityKey"],
                        )
                    return pk_data["peerE2eePublicKey"]
        except AamarvaError as err:
            if err.code == "PEER_KEY_VERIFICATION_FAILED":
                raise err
        except Exception:
            pass
        return None

    def distribute_cluster_key(
        self,
        cluster_id: str,
        recipients: Optional[List[str]] = None,
        epoch: int = 1,
        recipient_public_keys: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise AamarvaValidationError("epoch must be a positive integer >= 1.")

        effective_agent_id = self._resolve_effective_agent_id()
        master_id = self.resolve_master_agent_id()

        cluster_members: List[str] = []
        try:
            cluster = self.get_cluster(cluster_id)
            if cluster.members:
                cluster_members = [str(m) for m in cluster.members]
                member_upper = {m.strip().upper() for m in cluster_members}
                if recipients:
                    for r in recipients:
                        if r and isinstance(r, str) and r.strip() and r.strip().upper() not in member_upper:
                            raise AamarvaError(
                                f'Recipient "{r}" is not a verified member of cluster "{cluster_id}".',
                                code="CLUSTER_MEMBERSHIP_INVALID",
                            )
        except AamarvaError as err:
            if err.code == "CLUSTER_MEMBERSHIP_INVALID":
                raise err
        except Exception:
            pass

        recipient_set = set()
        if master_id:
            recipient_set.add(master_id)
        if effective_agent_id:
            recipient_set.add(effective_agent_id)
        if recipients:
            for r in recipients:
                if r and isinstance(r, str) and r.strip():
                    recipient_set.add(r.strip())
        final_recipients = list(recipient_set)
        roster_members = cluster_members if cluster_members else final_recipients

        cluster_key = generate_cluster_key()
        local_epoch = get_latest_local_ecdh_epoch(effective_agent_id)
        sender_priv = get_local_ecdh_key(effective_agent_id, local_epoch)
        sender_pub = export_public_key_jwk(sender_priv.public_key())

        distributions = []
        for r_id in final_recipients:
            r_pub = (recipient_public_keys or {}).get(r_id)
            if not r_pub:
                if r_id.strip().upper() == effective_agent_id.upper():
                    r_pub = sender_pub
                else:
                    r_pub = self._resolve_peer_ecdh_public_key(r_id)

            if not r_pub:
                raise AamarvaError(
                    f'Recipient "{r_id}" does not have a registered public key for cluster encryption.',
                    code="RECIPIENT_KEY_MISSING",
                )

            wrapped = wrap_cluster_key_for_recipient(
                cluster_key,
                r_pub,
                sender_priv,
                cluster_id=cluster_id.strip(),
                epoch=epoch,
            )
            distributions.append({
                "recipientAgentId": r_id,
                "encryptedKeyPackage": wrapped["encryptedKeyPackage"],
            })

        self.submit_cluster_key_distribution(cluster_id, {
            "epoch": epoch,
            "keyFingerprint": compute_cluster_key_fingerprint(cluster_key),
            "audienceHash": compute_audience_hash(final_recipients),
            "rosterHash": compute_roster_hash(roster_members),
            "senderAgentId": effective_agent_id,
            "distributions": distributions,
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
        if not cluster_id or not cluster_id.strip():
            raise AamarvaValidationError("cluster_id is required")

        cid_quoted = urllib.parse.quote(cluster_id.strip(), safe="")
        params = {}
        if epoch is not None:
            params["epoch"] = epoch

        res = self.http.request(
            "GET",
            f"/clusters/{cid_quoted}/key-distribution",
            auth=True,
            params=params if params else None,
        )
        data = res.get("data", {}) if isinstance(res, dict) and "data" in res else res
        return data if isinstance(data, dict) else {}

    def get_cluster_key(
        self,
        cluster_id: str,
        epoch: int = 1,
        sender_public_key: Optional[Any] = None,
    ) -> bytes:
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise AamarvaValidationError("epoch must be a positive integer >= 1.")
        cache_key = f"{cluster_id}:{epoch}"
        if cache_key in self.cluster_key_cache:
            return self.cluster_key_cache[cache_key]

        dist = self.get_cluster_key_distribution(cluster_id, epoch)
        if not dist or not dist.get("encryptedKeyPackage"):
            raise AamarvaError(
                f'No cluster key package available for cluster "{cluster_id}" at epoch {epoch}.',
                code="CLUSTER_KEY_MISSING",
            )

        if dist.get("epoch") is not None and int(dist["epoch"]) != epoch:
            raise AamarvaError(
                f'Cluster key distribution epoch mismatch: expected {epoch}, got {dist["epoch"]}.',
                code="CLUSTER_KEY_UNWRAP_FAILED",
            )

        effective_agent_id = self._resolve_effective_agent_id()
        latest_epoch = get_latest_local_ecdh_epoch(effective_agent_id)
        local_priv = get_local_ecdh_key(effective_agent_id, latest_epoch)

        target_fp = dist.get("recipientKeyFingerprint")
        if target_fp:
            matched = False
            for e in range(latest_epoch, 0, -1):
                candidate = find_local_ecdh_key(effective_agent_id, e)
                if candidate is not None and compute_key_fingerprint(export_public_key_jwk(candidate.public_key())) == target_fp:
                    local_priv = candidate
                    matched = True
                    break
            if not matched:
                raise AamarvaError(
                    f'No local ECDH private key matches cluster distribution recipientKeyFingerprint "{target_fp}".',
                    code="CLUSTER_KEY_UNWRAP_FAILED",
                )

        sender_pub = sender_public_key or dist.get("senderPublicKey")
        if not sender_pub and dist.get("senderAgentId"):
            if str(dist["senderAgentId"]).strip().upper() == effective_agent_id.upper():
                sender_pub = export_public_key_jwk(local_priv.public_key())
            else:
                sender_pub = self._resolve_peer_ecdh_public_key(str(dist["senderAgentId"]))

        cluster_key = unwrap_cluster_key(
            dist["encryptedKeyPackage"],
            None,
            local_priv,
            sender_pub,
            expected_cluster_id=cluster_id.strip(),
            expected_epoch=epoch,
        )

        if dist.get("keyFingerprint") and compute_cluster_key_fingerprint(cluster_key) != dist["keyFingerprint"]:
            raise AamarvaError(
                "Unwrapped cluster key fingerprint does not match distribution metadata.",
                code="CLUSTER_KEY_UNWRAP_FAILED",
            )

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
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise AamarvaValidationError("epoch must be a positive integer >= 1.")

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
            recipient_agent_ids=recipients,
        )

        master_id = self.resolve_master_agent_id()
        sender_id = (self.http.agent_id or "").strip()
        all_recipients = list(set([master_id, sender_id] + (recipients or [])))

        data = res.get("data", {}) if isinstance(res, dict) and isinstance(res.get("data"), dict) else res
        msg_id = str(
            (data.get("messageId") if isinstance(data, dict) else None)
            or (res.get("messageId") if isinstance(res, dict) else None)
            or (data.get("id") if isinstance(data, dict) else None)
            or "msg_cluster"
        )
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
        if not isinstance(message, dict):
            raise AamarvaValidationError("message dict is required")
        epoch = message.get("keyEpoch")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise AamarvaError(
                f"Missing or invalid keyEpoch on cluster message: {epoch}",
                code="CLUSTER_MESSAGE_DECRYPTION_FAILED",
            )
        version = int(message.get("version") if message.get("version") is not None else 2)
        cluster_key = self.get_cluster_key(cluster_id, epoch, sender_public_key)
        return decrypt_cluster_message(
            message["ciphertext"],
            message["nonce"],
            cluster_key,
            cluster_id,
            epoch=epoch,
            version=version,
        )

    # 4. Watchtower & Fleet Telemetry
    def get_watchtower_activity(
        self,
        limit: Optional[int] = None,
        before: Optional[str] = None,
    ) -> List[WatchtowerActivity]:
        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if before:
            params["before"] = before
        res = self.http.request("GET", "/watchtower/activity", auth=True, params=params if params else None)
        data = res.get("data", []) if isinstance(res, dict) else res
        if not isinstance(data, list):
            data = []
        return [normalize_watchtower_activity(item) for item in data]

    def get_watchtower_stream_ticket(self) -> WatchtowerStreamTicket:
        res = self.http.request("POST", "/watchtower/stream-ticket", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) and isinstance(res.get("data"), dict) else {}
        res_dict = res if isinstance(res, dict) else {}
        ticket = str(res_dict.get("ticket") or data.get("ticket") or "")
        expires_at = str(res_dict.get("expiresAt") or data.get("expiresAt") or "")
        if not ticket:
            raise AamarvaError("Watchtower stream-ticket endpoint did not return a valid ticket.", code="WATCHTOWER_TICKET_FAILED")
        return WatchtowerStreamTicket(
            ticket=ticket,
            streamUrl=f"{self.http.base_url}/watchtower/stream?ticket={urllib.parse.quote(ticket, safe='')}",
            expiresAt=expires_at,
        )

    def get_watchtower_stream_url(self, ticket: Optional[str] = None) -> str:
        qs = f"?ticket={urllib.parse.quote(ticket, safe='')}" if ticket else ""
        return f"{self.http.base_url}/watchtower/stream{qs}"

    def stream_watchtower_events(
        self,
        ticket: Optional[str] = None,
        max_reconnects: int = 5,
        deduplicate: bool = True,
    ) -> Generator[WatchtowerStreamEvent, None, None]:
        seen_ids = set()
        reconnects = 0
        current_ticket = ticket

        while True:
            try:
                if not current_ticket:
                    current_ticket = self.get_watchtower_stream_ticket().ticket

                with self.http.open_stream("/watchtower/stream", params={"ticket": current_ticket}, auth=True) as resp:
                    reconnects = 0
                    event_name = "message"
                    event_id: Optional[str] = None
                    data_lines: List[str] = []

                    def _flush() -> Optional[WatchtowerStreamEvent]:
                        nonlocal event_name, event_id, data_lines
                        if not data_lines:
                            event_name = "message"
                            event_id = None
                            return None
                        raw_data = "\n".join(data_lines)
                        data_lines = []
                        try:
                            parsed = json.loads(raw_data)
                        except Exception:
                            parsed = raw_data
                        ev = WatchtowerStreamEvent(
                            event=event_name or "message",
                            data=parsed,
                            id=event_id,
                            rawData=raw_data,
                        )
                        event_name = "message"
                        event_id = None
                        return ev

                    for raw_line in resp:
                        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                        if line == "":
                            ev = _flush()
                            if ev is not None:
                                if deduplicate and ev.id:
                                    if ev.id in seen_ids:
                                        continue
                                    seen_ids.add(ev.id)
                                yield ev
                            continue
                        if line.startswith(":"):
                            continue
                        if ":" in line:
                            field, val = line.split(":", 1)
                            if val.startswith(" "):
                                val = val[1:]
                        else:
                            field, val = line, ""
                        if field == "event":
                            event_name = val
                        elif field == "id":
                            event_id = val
                        elif field == "data":
                            data_lines.append(val)

                    trailing = _flush()
                    if trailing is not None and (not deduplicate or not trailing.id or trailing.id not in seen_ids):
                        if trailing.id:
                            seen_ids.add(trailing.id)
                        yield trailing

                if max_reconnects <= 0:
                    return
                reconnects += 1
                if reconnects > max_reconnects:
                    return
                current_ticket = None
            except AamarvaAuthenticationError:
                raise
            except Exception:
                reconnects += 1
                if reconnects > max_reconnects:
                    raise
                current_ticket = None
            time.sleep(min((2 ** reconnects) * 0.25, 5.0) + random.uniform(0.0, 0.1))

    def get_footprints(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"agentId": agent_id} if agent_id else None
        res = self.http.request("GET", "/agent/footprints", auth=True, params=params)
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

    def get_floor_tool_policy(self, tool_id: str) -> Dict[str, Any]:
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")
        tid_quoted = urllib.parse.quote(tool_id.strip(), safe="")
        res = self.http.request("GET", f"/floor/tools/{tid_quoted}/policy", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) and isinstance(res.get("data"), dict) else res
        return data if isinstance(data, dict) else {}

    def create_floor_invocation(
        self,
        tool_id: str,
        reason: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        request_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")

        tid_quoted = urllib.parse.quote(tool_id.strip(), safe="")
        body: Dict[str, Any] = {
            "reason": reason or "Agent requested tool invocation",
            "arguments": arguments or {},
        }
        if request_type:
            body["requestType"] = request_type

        res = self.http.request("POST", f"/floor/tools/{tid_quoted}/invoke", auth=True, json_data=body)
        raw_data = res.get("data") if isinstance(res, dict) else res
        data = raw_data if isinstance(raw_data, dict) else (res if isinstance(res, dict) else {})
        res_dict = res if isinstance(res, dict) else {}
        status = str(data.get("status") or res_dict.get("status") or "").strip().lower()
        req_id = data.get("requestId") or res_dict.get("requestId") or data.get("invocationId")
        inv_id = str(data.get("invocationId") or data.get("id") or req_id or "")

        has_immediate_output = (
            status in ("completed", "executed")
            or (
                res_dict.get("success") is True
                and not inv_id
                and status not in ("pending", "denied", "rejected", "approved")
            )
        )
        if has_immediate_output:
            return {
                "invocationId": inv_id,
                "requestId": str(req_id) if req_id else None,
                "toolId": str(data.get("toolId") or tool_id.strip()),
                "status": "executed",
                "directResult": data.get("result") if "result" in data else raw_data,
                "message": res_dict.get("message") or data.get("message"),
            }

        return {
            "invocationId": inv_id,
            "requestId": str(req_id) if req_id else None,
            "toolId": str(data.get("toolId") or tool_id.strip()),
            "status": status or "pending",
            "message": res_dict.get("message") or data.get("message"),
        }

    def wait_for_floor_request_approval(
        self,
        request_id: str,
        interval_s: float = 1.0,
        timeout_s: float = 30.0,
    ) -> FloorAccessRequestStatus:
        if not request_id or not request_id.strip():
            raise AamarvaValidationError("request_id is required")
        interval = max(0.05, interval_s)
        deadline = time.monotonic() + max(interval, timeout_s)
        while True:
            st = self.get_floor_request_status(request_id)
            norm = (st.status or "").strip().lower()
            if norm in ("approved", "accepted", "granted"):
                return st
            if norm in ("denied", "rejected", "revoked", "expired"):
                raise AamarvaError(
                    f'FLOOR request "{request_id}" was not approved (status: {norm}).',
                    code="FLOOR_ACCESS_DENIED",
                )
            if time.monotonic() >= deadline:
                raise AamarvaError(
                    f'Timed out waiting for FLOOR request "{request_id}" approval.',
                    code="FLOOR_APPROVAL_TIMEOUT",
                )
            time.sleep(interval)

    def obtain_floor_execution_authorization(
        self,
        invocation_id: str,
        arguments: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        use_access_endpoint: bool = False,
    ) -> Dict[str, Any]:
        if not invocation_id or not invocation_id.strip():
            raise AamarvaValidationError("invocation_id is required")

        iid_quoted = urllib.parse.quote(invocation_id.strip(), safe="")
        suffix = "access" if use_access_endpoint else "execute"
        body: Dict[str, Any] = {"arguments": arguments or {}}
        if reason:
            body["reason"] = reason

        res = self.http.request("POST", f"/floor/invocations/{iid_quoted}/{suffix}", auth=True, json_data=body)
        if not isinstance(res, dict):
            raise AamarvaError("FLOOR authorization failed: response payload is not an object.", code="FLOOR_EXECUTION_FAILED")

        if res.get("success") is False:
            err_field = res.get("error")
            err_msg = err_field.get("message") if isinstance(err_field, dict) else err_field
            raise AamarvaError(err_msg or res.get("message") or "FLOOR authorization was rejected by platform.", code="FLOOR_ACCESS_DENIED")

        if "data" in res and not isinstance(res.get("data"), dict):
            raise AamarvaError("FLOOR authorization failed: malformed response data payload.", code="FLOOR_EXECUTION_FAILED")

        data = res.get("data") if isinstance(res.get("data"), dict) else res
        raw_status = str(data.get("status") or res.get("status") or "").strip().lower()

        if raw_status in ["denied", "rejected", "revoked", "expired", "unassigned", "pending"]:
            raise AamarvaError(
                data.get("message") or res.get("message") or f"FLOOR execution authorization denied: status is '{raw_status}'.",
                code="FLOOR_ACCESS_DENIED",
            )

        ver_info = data.get("verificationInfo")
        auth_cfg = data.get("authConfig")
        has_verified_platform_grant = (
            isinstance(ver_info, dict)
            and ver_info.get("verified") is True
            and isinstance(auth_cfg, dict)
        )

        if raw_status != "approved" and not (raw_status == "" and has_verified_platform_grant):
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

        expires_at = data.get("expiresAt") or (data.get("grant") or {}).get("expiresAt")
        if isinstance(expires_at, str) and expires_at.strip():
            try:
                iso = expires_at.strip().replace("Z", "+00:00")
                exp_dt = datetime.datetime.fromisoformat(iso)
                now_dt = datetime.datetime.now(datetime.timezone.utc) if exp_dt.tzinfo else datetime.datetime.utcnow()
                if exp_dt <= now_dt:
                    raise AamarvaError("FLOOR execution authorization grant has expired.", code="FLOOR_ACCESS_DENIED")
            except AamarvaError:
                raise
            except Exception:
                pass

        if isinstance(ver_info, dict):
            if ver_info.get("verified") is not True:
                raise AamarvaError("FLOOR authorization failed: verificationInfo.verified is not true.", code="FLOOR_EXECUTION_FAILED")
            if ver_info.get("toolId") and data.get("toolId") and ver_info.get("toolId") != data.get("toolId"):
                raise AamarvaError("FLOOR authorization failed: verificationInfo.toolId mismatch.", code="FLOOR_EXECUTION_FAILED")
            expected_agent = (self.http.get_target_agent_id() or self.http.agent_id or "").strip()
            if expected_agent and ver_info.get("agentId") and str(ver_info["agentId"]).strip().upper() != expected_agent.upper():
                raise AamarvaError("FLOOR authorization failed: verificationInfo.agentId mismatch.", code="FLOOR_ACCESS_DENIED")

        grant = data.get("grant")
        has_legacy_grant = isinstance(grant, dict)
        if not has_legacy_grant and not has_verified_platform_grant:
            raise AamarvaError("FLOOR authorization failed: grant details missing in response.", code="FLOOR_EXECUTION_FAILED")

        mapped_auth = None
        if isinstance(auth_cfg, dict):
            a_type = str(auth_cfg.get("authType") or "none").strip().lower()
            hdr_val = auth_cfg.get("headerValue") if auth_cfg.get("headerValue") is not None else (data.get("accessToken") or data.get("grantToken"))
            if a_type != "none" and (not hdr_val or not isinstance(hdr_val, str) or not hdr_val.strip()):
                raise AamarvaError(f'FLOOR authorization failed: missing credential for authType "{a_type}".', code="FLOOR_EXECUTION_FAILED")
            mapped_auth = {
                "type": a_type,
                "authType": a_type,
                "headerName": auth_cfg.get("authHeaderName"),
                "headerValue": hdr_val,
                "token": hdr_val if a_type == "bearer" else None,
                "apiKey": hdr_val if a_type in ("api_key", "apikey") else None,
            }
        else:
            mapped_auth = data.get("auth") or data.get("authentication")

        return {
            "invocationId": returned_iid,
            "toolId": str(data.get("toolId") or ""),
            "status": "approved",
            "serverUrl": server_url.strip(),
            "auth": mapped_auth,
            "authConfig": auth_cfg,
            "verificationInfo": ver_info,
            "grantToken": data.get("grantToken"),
            "accessToken": data.get("accessToken"),
            "scope": data.get("scope"),
            "expiresAt": expires_at,
            "approvedArguments": data.get("approvedArguments"),
            "grant": grant,
        }

    def execute_floor_tool(
        self,
        tool_id: str,
        arguments: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        invocation_id: Optional[str] = None,
        wait_for_approval: bool = False,
        approval_timeout_s: float = 30.0,
        use_access_endpoint: bool = False,
    ) -> FloorToolInvokeResult:
        if not tool_id or not tool_id.strip():
            raise AamarvaValidationError("tool_id is required")

        tools = self.get_floor_tools()
        tool = next((t for t in tools if t.id == tool_id.strip()), None)
        if not tool:
            raise AamarvaError(f'Tool "{tool_id}" not found in available fleet tools.', code="FLOOR_TOOL_NOT_FOUND")

        access_status = (tool.accessStatus or "").strip().lower()
        has_grant = access_status in ["authorized", "granted", "approved"]

        resolved_invocation_id = invocation_id
        if not resolved_invocation_id:
            inv_res = self.create_floor_invocation(
                tool_id.strip(),
                reason=reason or ("Authorized execution run" if has_grant else "Agent requested execution"),
                arguments=arguments,
            )
            if inv_res.get("status") == "executed" and "directResult" in inv_res:
                return FloorToolInvokeResult(
                    status="executed",
                    invocationId=inv_res.get("invocationId") or None,
                    toolId=tool_id.strip(),
                    result=inv_res["directResult"],
                    serverUrl=tool.serverUrl,
                )
            if inv_res.get("status") == "pending":
                req_id = inv_res.get("requestId") or inv_res.get("invocationId")
                if wait_for_approval and req_id:
                    approved = self.wait_for_floor_request_approval(req_id, timeout_s=approval_timeout_s)
                    resolved_invocation_id = approved.invocationId or inv_res.get("invocationId")
                else:
                    raise AamarvaError(
                        f'Agent is not authorized to execute tool "{tool_id}". Access request {req_id} is pending human approval.',
                        code="FLOOR_ACCESS_DENIED",
                    )
            elif inv_res.get("status") in ["denied", "rejected", "revoked", "expired"]:
                raise AamarvaError(
                    f'Agent access to tool "{tool_id}" was denied (status: {inv_res["status"]}).',
                    code="FLOOR_ACCESS_DENIED",
                )
            else:
                resolved_invocation_id = inv_res.get("invocationId")

        if not resolved_invocation_id:
            raise AamarvaError("FLOOR invocation creation failed to return a valid invocationId.", code="FLOOR_EXECUTION_FAILED")

        auth_details = self.obtain_floor_execution_authorization(
            resolved_invocation_id,
            arguments=arguments,
            reason=reason,
            use_access_endpoint=use_access_endpoint,
        )

        if auth_details["status"] != "approved":
            raise AamarvaError(f"FLOOR execution denied: status is '{auth_details['status']}'.", code="FLOOR_ACCESS_DENIED")

        if auth_details.get("toolId") and auth_details["toolId"].strip() != tool_id.strip():
            raise AamarvaError(
                f'FLOOR execution authorization mismatch: authorized tool "{auth_details["toolId"]}" does not match requested tool "{tool_id}".',
                code="FLOOR_EXECUTION_FAILED",
            )

        exec_args = (
            auth_details.get("approvedArguments")
            if auth_details.get("approvedArguments") and not arguments
            else arguments
        )

        mcp_result = invoke_external_mcp_tool(
            server_url=auth_details["serverUrl"],
            tool_id=tool_id.strip(),
            args=exec_args,
            auth=auth_details.get("auth"),
            input_schema=tool.inputSchema,
            allow_insecure_http_for_localhost=self.allow_insecure_http_for_localhost,
        )

        return FloorToolInvokeResult(
            status="approved",
            invocationId=resolved_invocation_id,
            toolId=tool_id.strip(),
            result=mcp_result,
            serverUrl=auth_details["serverUrl"],
        )

    def request_floor_access(self, tool_id: str, reason: Optional[str] = None) -> FloorToolInvokeResult:
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

        inv = self.create_floor_invocation(tool_id.strip(), reason=reason, request_type="access")
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
        rid_quoted = urllib.parse.quote(request_id.strip(), safe="")
        res = self.http.request("GET", f"/floor/requests/{rid_quoted}", auth=True)
        data = res.get("data", {}) if isinstance(res, dict) else res
        return normalize_floor_request_status(data)

    def get_adk_metadata(self) -> Dict[str, Any]:
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
        peerAccountId: Optional[str] = None,
    ):
        self.client = client
        self.connectionId = connectionId
        self.agentId = agentId
        self.peerAccountId = peerAccountId or agentId
        self.status = status
        self.createdAt = createdAt
        self.connectedAgentName = connectedAgentName
        self.replyId = replyId
        self.updatedAt = updatedAt

    def send(self, message: str) -> Message:
        acct = self.peerAccountId or self.agentId or self.connectionId
        return self.client.send_message(acct, message, self.agentId)

    def messages(self, since: Optional[str] = None, page: int = 1, limit: int = 50) -> List[Message]:
        acct = self.peerAccountId or self.agentId or self.connectionId
        return self.client.get_messages(acct, self.agentId, since=since, page=page, limit=limit)

    def get_messages(self, since: Optional[str] = None, page: int = 1, limit: int = 50) -> List[Message]:
        return self.messages(since=since, page=page, limit=limit)

    def get_encrypted_messages(self, since: Optional[str] = None, page: int = 1, limit: int = 50) -> List[Dict[str, Any]]:
        acct = self.peerAccountId or self.agentId or self.connectionId
        return self.client.get_encrypted_messages(acct, self.agentId, since=since, page=page, limit=limit)
