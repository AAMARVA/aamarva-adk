import unittest
from unittest.mock import MagicMock
from aamarva import Aamarva, AamarvaConnection, Agent, Connection, Message
from aamarva.errors import (
    AamarvaError,
    AamarvaAPIError,
    AamarvaAuthenticationError,
    AamarvaValidationError
)
from aamarva.crypto import (
    compute_key_fingerprint,
    export_public_key_jwk,
    sign_identity_binding
)
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    ec = None
    serialization = None
    HAS_CRYPTOGRAPHY = False

class TestAamarvaFleetClient(unittest.TestCase):
    def setUp(self):
        self.client = Aamarva(agent_id="AMR-TEST-1111", api_key="sk_amr_test_123")
        self.client.http.request = MagicMock()
        if HAS_CRYPTOGRAPHY:
            self.peer_priv = ec.generate_private_key(ec.SECP256R1())
            self.peer_pub_jwk = export_public_key_jwk(self.peer_priv.public_key())
            self.peer_fp = compute_key_fingerprint(self.peer_priv.public_key())
            
            self.peer_identity_priv = ec.generate_private_key(ec.SECP256R1())
            self.peer_identity_pub_jwk = export_public_key_jwk(self.peer_identity_priv.public_key())
            self.peer_sig = sign_identity_binding(self.peer_identity_priv, "AMR-PEER-2222", self.peer_fp)
        else:
            self.peer_priv = None
            self.peer_pub_jwk = None
            self.peer_fp = None
            self.peer_identity_priv = None
            self.peer_identity_pub_jwk = None
            self.peer_sig = None

    def test_health(self):
        self.client.http.request.return_value = {"success": True, "status": "ok"}
        res = self.client.health()
        self.assertEqual(res.get("status"), "ok")
        self.client.http.request.assert_called_with("GET", "/health", auth=False)

    def test_me(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {"agentId": "AMR-TEST-1111", "name": "Fleet Commander"}
        }
        agent = self.client.me()
        self.assertEqual(agent.agentId, "AMR-TEST-1111")
        self.assertEqual(agent.name, "Fleet Commander")
        self.client.http.request.assert_called_with("GET", "/agents/me", auth=True)

    def test_get_connections(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": [{"connectionId": "conn_1", "agentId": "AMR-PEER-2222", "status": "active", "createdAt": "2026-01-01"}]
        }
        conns = self.client.connections()
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].connectionId, "conn_1")
        self.client.http.request.assert_called_with("GET", "/connections", auth=True)

    def test_get_connection(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {"connectionId": "conn_1", "agentId": "AMR-PEER-2222", "status": "active", "createdAt": "2026-01-01"}
        }
        conn = self.client.get_connection("conn_1")
        self.assertEqual(conn.connectionId, "conn_1")
        self.client.http.request.assert_called_with("GET", "/connections/conn_1", auth=True)

    def test_clusters(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {"clusterId": "cluster_1", "name": "Arbitrage Fleet"}
        }
        cluster = self.client.create_cluster(name="Arbitrage Fleet", description="L2 liquidity")
        self.assertEqual(cluster.clusterId, "cluster_1")
        self.assertEqual(cluster.name, "Arbitrage Fleet")
        self.client.http.request.assert_called_with(
            "POST", "/clusters", auth=True, json_data={"name": "Arbitrage Fleet", "description": "L2 liquidity"}
        )

    def test_watchtower_activity(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": [{"id": "act_1", "type": "connection.created", "summary": "Direct channel formed", "timestamp": "2026-01-01"}]
        }
        acts = self.client.get_watchtower_activity(limit=10)
        self.assertEqual(len(acts), 1)
        self.assertEqual(acts[0].summary, "Direct channel formed")
        self.client.http.request.assert_called_with("GET", "/watchtower/activity", auth=True, params={"limit": 10})

    def test_floor_tools(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": [{"id": "tool_sec", "name": "SEC Extractor", "description": "10-K data", "inputSchema": {}, "accessStatus": "authorized"}]
        }
        tools = self.client.get_floor_tools()
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].id, "tool_sec")
        self.assertEqual(tools[0].accessStatus, "authorized")

    def test_floor_access_request(self):
        self.client.http.request.return_value = {
            "success": True,
            "status": "pending",
            "data": {"status": "pending", "requestId": "req_tool_99"}
        }
        res = self.client.request_floor_access("tool_orderbook", "Need market depth data")
        self.assertEqual(res.status, "pending")
        self.assertEqual(res.requestId, "req_tool_99")
        self.client.http.request.assert_called_with(
            "POST", "/floor/tools/tool_orderbook/request-access", auth=True,
            json_data={"reason": "Need market depth data"}
        )

    def test_floor_execute(self):
        self.client.http.request.return_value = {
            "success": True,
            "status": "executed",
            "data": {"status": "executed", "result": {"data": 123}}
        }
        res = self.client.execute_floor_tool("tool_sec", {"ticker": "AAPL"})
        self.assertEqual(res.status, "executed")
        self.assertEqual(res.result, {"data": 123})
        self.client.http.request.assert_called_with(
            "POST", "/floor/tools/tool_sec/execute", auth=True,
            json_data={"arguments": {"ticker": "AAPL"}}
        )

    def test_legacy_removal_on_client(self):
        # Assert obsolete methods do not exist
        self.assertFalse(hasattr(self.client, "discover"))
        self.assertFalse(hasattr(self.client, "emit"))
        self.assertFalse(hasattr(self.client, "intake"))
        self.assertFalse(hasattr(self.client, "reply"))
        self.assertFalse(hasattr(self.client, "submit_review"))
        self.assertFalse(hasattr(self.client, "get_posts"))
        self.assertFalse(hasattr(self.client, "create_post"))
        self.assertFalse(hasattr(self.client, "establish_connection"))
        self.assertFalse(hasattr(self.client, "get_floor_temporary_access"))
        self.assertFalse(hasattr(self.client, "invoke_floor_tool"))

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library not installed in environment")
    def test_login_auto_registers_public_key(self):
        calls = []
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            calls.append((method, path, json_data))
            if path == "/auth/login":
                return {"success": True, "data": {"accessToken": "at_1", "refreshToken": "rt_1"}}
            if path == "/agents/me/e2ee":
                return {"success": True, "message": "Key registered"}
            return {}
        self.client.http.request.side_effect = mock_req
        res = self.client.login("AMR-TEST-1111", "sk_amr_test_123")
        self.assertEqual(res.get("accessToken"), "at_1")
        # Ensure login triggered PUT /agents/me/e2ee
        e2ee_calls = [c for c in calls if c[1] == "/agents/me/e2ee"]
        self.assertEqual(len(e2ee_calls), 1)

    def test_floor_execute_fail_closed_missing_status(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {"result": {"some": "data"}}
        }
        with self.assertRaises(AamarvaError) as ctx:
            self.client.execute_floor_tool("tool_sec", {"ticker": "AAPL"})
        self.assertEqual(ctx.exception.code, "FLOOR_EXECUTION_FAILED")

    def test_floor_execute_fail_closed_unknown_status(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {"status": "in_progress", "result": {"some": "data"}}
        }
        with self.assertRaises(AamarvaError) as ctx:
            self.client.execute_floor_tool("tool_sec", {"ticker": "AAPL"})
        self.assertEqual(ctx.exception.code, "FLOOR_EXECUTION_FAILED")

    def test_floor_execute_fail_closed_malformed_data(self):
        # 1. data is null
        self.client.http.request.return_value = {"success": True, "data": None}
        with self.assertRaises(AamarvaError) as ctx1:
            self.client.execute_floor_tool("tool_sec", {})
        self.assertEqual(ctx1.exception.code, "FLOOR_EXECUTION_FAILED")

        # 2. data is string
        self.client.http.request.return_value = {"success": True, "data": "unexpected_string"}
        with self.assertRaises(AamarvaError) as ctx2:
            self.client.execute_floor_tool("tool_sec", {})
        self.assertEqual(ctx2.exception.code, "FLOOR_EXECUTION_FAILED")

        # 3. data is list
        self.client.http.request.return_value = {"success": True, "data": [1, 2, 3]}
        with self.assertRaises(AamarvaError) as ctx3:
            self.client.execute_floor_tool("tool_sec", {})
        self.assertEqual(ctx3.exception.code, "FLOOR_EXECUTION_FAILED")

        # 4. response itself is string
        self.client.http.request.return_value = "raw_non_json_string"
        with self.assertRaises(AamarvaError) as ctx4:
            self.client.execute_floor_tool("tool_sec", {})
        self.assertEqual(ctx4.exception.code, "FLOOR_EXECUTION_FAILED")

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library not installed in environment")
    def test_registration_cache_identity_aware(self):
        put_calls = []
        fail_next = False
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            nonlocal put_calls, fail_next
            if path == "/agents/me/e2ee" and method == "PUT":
                put_calls.append(json_data)
                if fail_next:
                    return {"success": False, "message": "Server error"}
                return {"success": True, "message": "Registered"}
            return {}

        self.client.http.request.side_effect = mock_req
        self.client.http.agent_id = "AMR-IDENT-1"

        # 1. Initial registration for AMR-IDENT-1
        self.client.register_public_key()
        self.assertEqual(len(put_calls), 1)
        self.assertEqual(self.client.registered_agent_id, "AMR-IDENT-1")
        initial_fp = self.client.registered_key_fingerprint
        self.assertIsNotNone(initial_fp)

        # 2. Repeated call with same identity and fingerprint is cached (no new call)
        self.client.register_public_key()
        self.assertEqual(len(put_calls), 1)

        # 3. Switching agent ID with same fingerprint MUST trigger registration for new identity
        self.client.http.agent_id = "AMR-IDENT-2"
        self.client.register_public_key()
        self.assertEqual(len(put_calls), 2)
        self.assertEqual(self.client.registered_agent_id, "AMR-IDENT-2")

        # 4. Failed registration attempt is not cached as successful and is retried
        fail_next = True
        self.client.http.agent_id = "AMR-IDENT-FAIL"
        with self.assertRaises(AamarvaError):
            self.client.register_public_key()

        self.assertIsNone(self.client.registered_agent_id)
        self.assertIsNone(self.client.registered_key_fingerprint)

        # Retrying succeeds and records cache
        fail_next = False
        self.client.register_public_key()
        self.assertEqual(self.client.registered_agent_id, "AMR-IDENT-FAIL")
        self.assertEqual(self.client.registered_key_fingerprint, initial_fp)

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library not installed in environment")
    def test_register_public_key_malformed_response_fails_and_retries(self):
        response_data = None
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            if path == "/agents/me/e2ee":
                return response_data
            return {}

        self.client.http.request.side_effect = mock_req
        self.client.http.agent_id = "AMR-MALFORMED-1"

        # 1. Non-dict (string) response raises E2EE_KEY_REGISTRATION_FAILED
        response_data = "invalid_string_response"
        with self.assertRaises(AamarvaError) as ctx1:
            self.client.register_public_key()
        self.assertEqual(ctx1.exception.code, "E2EE_KEY_REGISTRATION_FAILED")
        self.assertIsNone(self.client.registered_agent_id)

        # 2. Response with success=False raises E2EE_KEY_REGISTRATION_FAILED
        response_data = {"success": False, "message": "Key fingerprint rejected"}
        with self.assertRaises(AamarvaError) as ctx2:
            self.client.register_public_key()
        self.assertEqual(ctx2.exception.code, "E2EE_KEY_REGISTRATION_FAILED")
        self.assertIsNone(self.client.registered_agent_id)

        # 3. Valid success response succeeds and sets cache
        response_data = {"success": True, "message": "Key registered"}
        self.client.register_public_key()
        self.assertEqual(self.client.registered_agent_id, "AMR-MALFORMED-1")

    def test_set_credentials_preserves_tokens(self):
        self.client.http.access_token = "at_valid"
        self.client.http.refresh_token = "rt_valid"
        # Preserving existing tokens
        self.client.http.set_credentials("AMR-TEST-NEW", "sk_new", preserve_tokens=True)
        self.assertEqual(self.client.http.agent_id, "AMR-TEST-NEW")
        self.assertEqual(self.client.http.api_key, "sk_new")
        self.assertEqual(self.client.http.access_token, "at_valid")
        self.assertEqual(self.client.http.refresh_token, "rt_valid")

        # Not preserving clears tokens
        self.client.http.set_credentials("AMR-TEST-NEW", "sk_new", preserve_tokens=False)
        self.assertIsNone(self.client.http.access_token)
        self.assertIsNone(self.client.http.refresh_token)

    def test_register_installs_credentials_and_tokens_before_key_registration(self):
        state_during_e2ee = {}
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            if path == "/auth/register":
                return {
                    "success": True,
                    "data": {
                        "agentId": "AMR-REG-777",
                        "apiKey": "sk_reg_777",
                        "tokens": {
                            "accessToken": "at_reg_777",
                            "refreshToken": "rt_reg_777"
                        }
                    }
                }
            if path == "/agents/me/e2ee":
                state_during_e2ee["agent_id"] = self.client.http.agent_id
                state_during_e2ee["api_key"] = self.client.http.api_key
                state_during_e2ee["access_token"] = self.client.http.access_token
                state_during_e2ee["refresh_token"] = self.client.http.refresh_token
                state_during_e2ee["skip_auto_auth"] = skip_auto_auth
                return {"success": True, "message": "Key registered"}
            return {}

        self.client.http.request.side_effect = mock_req
        res = self.client.register(email="agent777@aamarva.com", name="Agent 777")
        self.assertEqual(res.get("agentId"), "AMR-REG-777")
        self.assertEqual(self.client.http.agent_id, "AMR-REG-777")
        self.assertEqual(self.client.http.api_key, "sk_reg_777")
        self.assertEqual(self.client.http.access_token, "at_reg_777")
        self.assertEqual(self.client.http.refresh_token, "rt_reg_777")
        if HAS_CRYPTOGRAPHY:
            self.assertEqual(state_during_e2ee.get("agent_id"), "AMR-REG-777")
            self.assertEqual(state_during_e2ee.get("access_token"), "at_reg_777")
            self.assertTrue(state_during_e2ee.get("skip_auto_auth"))

    def test_register_public_key_server_rejection_raises(self):
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            if path == "/auth/register":
                return {
                    "success": True,
                    "data": {
                        "agentId": "AMR-REG-REJECT",
                        "apiKey": "sk_reg_reject",
                        "tokens": {
                            "accessToken": "at_reject",
                            "refreshToken": "rt_reject"
                        }
                    }
                }
            if path == "/agents/me/e2ee":
                return {"success": False, "message": "Key signature verification failed"}
            return {}

        self.client.http.request.side_effect = mock_req
        if HAS_CRYPTOGRAPHY:
            with self.assertRaises(AamarvaError) as ctx:
                self.client.register(email="reject@aamarva.com", name="Reject Agent")
            self.assertEqual(ctx.exception.code, "E2EE_KEY_REGISTRATION_FAILED")

    def test_send_cluster_message_enforces_sender_and_master(self):
        last_body = {}
        def mock_req(method, path, auth=False, params=None, json_data=None):
            nonlocal last_body
            if path == "/agents/me":
                return {"success": True, "data": {"agentId": "AMR-TEST-1111", "masterId": "AMR-MASTER-AUTH"}}
            last_body = json_data or {}
            return {"success": True, "messageId": "msg_c_1"}
        self.client.http.request.side_effect = mock_req
        self.client.target_agent_id = "AMR-SLAVE-TARGET-99"

        res = self.client.send_cluster_message(
            cluster_id="c_1",
            ciphertext="cipher_123",
            nonce="nonce_123",
            recipients=["AMR-WORKER-1", "AMR-WORKER-1"]
        )
        self.assertEqual(last_body.get("senderAgentId"), "AMR-TEST-1111")
        recipients = last_body.get("recipients", [])
        self.assertIn("AMR-MASTER-AUTH", recipients)
        self.assertNotIn("AMR-SLAVE-TARGET-99", recipients)
        self.assertIn("AMR-TEST-1111", recipients)
        self.assertIn("AMR-WORKER-1", recipients)
        self.assertEqual(recipients.count("AMR-WORKER-1"), 1)

    def test_send_cluster_message_fails_if_master_unresolvable(self):
        def mock_req(method, path, auth=False, params=None, json_data=None):
            if path == "/agents/me":
                raise AamarvaAPIError("Profile corrupt", status_code=500)
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx:
            self.client.send_cluster_message(
                cluster_id="c_1",
                ciphertext="cipher",
                nonce="nonce"
            )
        self.assertEqual(ctx.exception.code, "MASTER_RESOLUTION_FAILED")

    def test_send_cluster_message_rejects_spoofed_sender(self):
        with self.assertRaises(AamarvaValidationError):
            self.client.send_cluster_message(
                cluster_id="c_1",
                ciphertext="cipher",
                nonce="nonce",
                sender_agent_id="AMR-SPOOFED"
            )

    def test_master_identity_aliases(self):
        for field in ["masterId", "master_id", "masterAgentId", "master_agent_id", "ownerAgentId", "owner_agent_id"]:
            last_body = {}
            def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False):
                nonlocal last_body
                if path == "/agents/me":
                    return {"success": True, "data": {"agentId": "AMR-SLAVE-1", field: "AMR-MASTER-ALIAS"}}
                last_body = json_data or {}
                return {"success": True, "messageId": "msg_c_1"}
            self.client.http.request.side_effect = mock_req
            self.client.send_cluster_message("c_1", "cipher", "nonce")
            self.assertIn("AMR-MASTER-ALIAS", last_body.get("recipients", []))

    def test_conflicting_master_identity_fails_closed(self):
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False):
            if path == "/agents/me":
                return {
                    "success": True,
                    "data": {
                        "agentId": "AMR-SLAVE-1",
                        "masterId": "AMR-MASTER-A",
                        "ownerAgentId": "AMR-MASTER-B"
                    }
                }
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx:
            self.client.send_cluster_message("c_1", "cipher", "nonce")
        self.assertEqual(ctx.exception.code, "MASTER_RESOLUTION_FAILED")

    def test_missing_master_identity_fails_closed(self):
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False):
            if path == "/agents/me":
                return {
                    "success": True,
                    "data": {
                        "agentId": "AMR-ORPHAN-SLAVE"
                    }
                }
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx:
            self.client.send_cluster_message("c_1", "cipher", "nonce")
        self.assertEqual(ctx.exception.code, "MASTER_RESOLUTION_FAILED")

    def test_floor_execute_denied_status_raises(self):
        self.client.http.request.return_value = {
            "success": False,
            "status": "denied",
            "data": {"status": "denied", "message": "Access not granted"}
        }
        with self.assertRaises(AamarvaError) as ctx:
            self.client.execute_floor_tool("tool_denied", {})
        self.assertEqual(ctx.exception.code, "FLOOR_ACCESS_DENIED")

    def test_floor_listing_and_request_never_execute(self):
        calls = []
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False):
            calls.append((method, path))
            if "/floor/agent/tools" in path:
                return {"success": True, "data": []}
            if "request-access" in path:
                return {"success": True, "status": "pending", "data": {"status": "pending", "requestId": "req_1"}}
            if "/floor/requests/" in path:
                return {"success": True, "data": {"status": "pending", "requestId": "req_1"}}
            return {}
        self.client.http.request.side_effect = mock_req
        self.client.get_floor_tools()
        self.client.request_floor_access("tool_1", "testing")
        self.client.get_floor_request_status("req_1")

        # Verify no execute path was ever called
        execute_calls = [c for c in calls if "execute" in c[1]]
        self.assertEqual(len(execute_calls), 0)

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library not installed in environment")
    def test_get_messages_rejects_plaintext(self):
        def mock_req(method, path, auth=False, params=None, json_data=None):
            if path == "/connections/conn-1/peer-key":
                return {
                    "success": True,
                    "data": {
                        "peerAgentId": "AMR-PEER-2222",
                        "peerE2eePublicKey": self.peer_pub_jwk,
                        "peerKeyFingerprint": self.peer_fp,
                        "peerIdentityKey": self.peer_identity_pub_jwk,
                        "peerKeySignature": self.peer_sig,
                        "peerKeyEpoch": 1
                    }
                }
            if path == "/connections/conn-1/messages":
                return [
                    "Unencrypted raw message plaintext string"
                ]
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx:
            self.client.get_messages("conn-1", "AMR-PEER-2222")
        self.assertEqual(ctx.exception.code, "PLAINTEXT_MESSAGE_RECEIVED")

if __name__ == "__main__":
    unittest.main()
