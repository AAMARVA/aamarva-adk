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
    get_local_identity_key,
    reset_local_identity_key,
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

    def test_unapproved_endpoint_rejection(self):
        from aamarva.http import HttpClient
        http = HttpClient()
        with self.assertRaises(AamarvaError) as ctx1:
            http.request("GET", "/health", auth=False)
        self.assertEqual(ctx1.exception.code, "ENDPOINT_NOT_ALLOWED")

        with self.assertRaises(AamarvaError) as ctx2:
            http.request("POST", "/auth/register", auth=False)
        self.assertEqual(ctx2.exception.code, "ENDPOINT_NOT_ALLOWED")

        with self.assertRaises(AamarvaError) as ctx3:
            http.request("POST", "/clusters", auth=True)
        self.assertEqual(ctx3.exception.code, "ENDPOINT_NOT_ALLOWED")

        with self.assertRaises(AamarvaError) as ctx4:
            http.request("POST", "/agents/me/e2ee", auth=True)
        self.assertEqual(ctx4.exception.code, "ENDPOINT_NOT_ALLOWED")

        from aamarva.http import is_approved_endpoint
        self.assertTrue(is_approved_endpoint("GET", "/agents/me/e2ee"))
        self.assertTrue(is_approved_endpoint("PUT", "/agents/me/e2ee"))
        self.assertFalse(is_approved_endpoint("POST", "/agents/me/e2ee"))

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

        paged_conns = self.client.connections(page=2, limit=25)
        self.assertEqual(len(paged_conns), 1)
        self.client.http.request.assert_called_with("GET", "/connections", auth=True, params={"page": 2, "limit": 25})

    def test_clusters(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": [{"clusterId": "cluster_1", "name": "Arbitrage Fleet"}]
        }
        clusters = self.client.get_clusters()
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].clusterId, "cluster_1")
        self.client.http.request.assert_called_with("GET", "/clusters", auth=True)

    def test_get_agents(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": [{"agentId": "AMR-TEST-1111", "name": "Fleet Commander"}]
        }
        agents = self.client.get_agents(q="Fleet", page=1, limit=10)
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0].agentId, "AMR-TEST-1111")
        self.client.http.request.assert_called_with("GET", "/agents", auth=True, params={"q": "Fleet", "page": 1, "limit": 10})

    def test_get_agent_e2ee_key(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {"fingerprint": "SHA256:abc", "keyEpoch": 1}
        }
        key_data = self.client.get_agent_e2ee_key()
        self.assertEqual(key_data.get("fingerprint"), "SHA256:abc")
        self.client.http.request.assert_called_with("GET", "/agents/me/e2ee", auth=True)

        alias_key_data = self.client.get_registered_public_key()
        self.assertEqual(alias_key_data.get("fingerprint"), "SHA256:abc")

    def test_get_cluster_key_distribution(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {"clusterId": "cluster_1", "epoch": 2, "encryptedKeyPackage": "pkg_123"}
        }
        res = self.client.get_cluster_key_distribution("cluster_1", epoch=2)
        self.assertEqual(res.get("clusterId"), "cluster_1")
        self.assertEqual(res.get("epoch"), 2)
        self.client.http.request.assert_called_with("GET", "/clusters/cluster_1/key-distribution", auth=True, params={"epoch": 2})

        res_aud = self.client.get_cluster_key_distribution("cluster_1", epoch=2, audience_hash="aud_sha256_abc")
        self.assertEqual(res_aud.get("clusterId"), "cluster_1")
        self.client.http.request.assert_called_with(
            "GET",
            "/clusters/cluster_1/key-distribution",
            auth=True,
            params={"epoch": 2, "audienceHash": "aud_sha256_abc"},
        )

        self.client.get_cluster_key_distribution("cluster_1", audience_hash="aud_only")
        self.client.http.request.assert_called_with(
            "GET",
            "/clusters/cluster_1/key-distribution",
            auth=True,
            params={"audienceHash": "aud_only"},
        )

        self.client.get_cluster_key_distribution("cluster_1")
        self.client.http.request.assert_called_with(
            "GET",
            "/clusters/cluster_1/key-distribution",
            auth=True,
            params=None,
        )


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
        def mock_req(method, path, **kwargs):
            if path == "/floor/agent/tools":
                return {"success": True, "data": [{"id": "tool_orderbook", "name": "Orderbook", "description": "", "inputSchema": {}, "accessStatus": "required"}]}
            if path == "/floor/tools/tool_orderbook/invoke":
                return {"success": True, "status": "pending", "data": {"status": "pending", "requestId": "req_tool_99", "invocationId": "req_tool_99"}}
            return {}
        self.client.http.request.side_effect = mock_req
        res = self.client.request_floor_access("tool_orderbook", "Need market depth data")
        self.assertEqual(res.status, "pending")
        self.assertEqual(res.requestId, "req_tool_99")

    def test_floor_execute(self):
        def mock_req(method, path, **kwargs):
            if path == "/floor/agent/tools":
                return {"success": True, "data": [{"id": "tool_sec", "name": "SEC Extractor", "description": "", "inputSchema": {"properties": {"ticker": {"type": "string"}}}, "accessStatus": "authorized"}]}
            if path == "/floor/tools/tool_sec/invoke":
                return {"success": True, "data": {"invocationId": "inv_123", "status": "approved"}}
            if path == "/floor/invocations/inv_123/execute":
                return {"success": True, "data": {"status": "approved", "invocationId": "inv_123", "toolId": "tool_sec", "serverUrl": "http://127.0.0.1:4000/mcp", "auth": {"type": "bearer", "token": "tok"}, "grant": {"grantId": "g1"}}}
            return {}
        self.client.http.request.side_effect = mock_req
        with unittest.mock.patch("aamarva.client.invoke_external_mcp_tool", return_value={"data": 123}):
            res = self.client.execute_floor_tool("tool_sec", {"ticker": "AAPL"})
            self.assertEqual(res.status, "approved")
            self.assertEqual(res.result, {"data": 123})

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
        def mock_req(method, path, **kwargs):
            if path == "/floor/agent/tools":
                return {"success": True, "data": [{"id": "tool_sec", "name": "SEC", "description": "", "inputSchema": {}, "accessStatus": "authorized"}]}
            if path == "/floor/tools/tool_sec/invoke":
                return {"success": True, "data": {"invocationId": "inv_1", "status": "approved"}}
            if path == "/floor/invocations/inv_1/execute":
                return {"success": True, "data": {"result": {"some": "data"}}}
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx:
            self.client.execute_floor_tool("tool_sec", {"ticker": "AAPL"})
        self.assertEqual(ctx.exception.code, "FLOOR_EXECUTION_FAILED")

    def test_floor_execute_fail_closed_unknown_status(self):
        def mock_req(method, path, **kwargs):
            if path == "/floor/agent/tools":
                return {"success": True, "data": [{"id": "tool_sec", "name": "SEC", "description": "", "inputSchema": {}, "accessStatus": "authorized"}]}
            if path == "/floor/tools/tool_sec/invoke":
                return {"success": True, "data": {"invocationId": "inv_1", "status": "approved"}}
            if path == "/floor/invocations/inv_1/execute":
                return {"success": True, "data": {"status": "in_progress", "result": {"some": "data"}}}
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx:
            self.client.execute_floor_tool("tool_sec", {"ticker": "AAPL"})
        self.assertEqual(ctx.exception.code, "FLOOR_EXECUTION_FAILED")

    def test_floor_execute_fail_closed_malformed_data(self):
        def mock_req(method, path, **kwargs):
            if path == "/floor/agent/tools":
                return {"success": True, "data": [{"id": "tool_sec", "name": "SEC", "description": "", "inputSchema": {}, "accessStatus": "authorized"}]}
            if path == "/floor/tools/tool_sec/invoke":
                return {"success": True, "data": {"invocationId": "inv_1", "status": "approved"}}
            if path == "/floor/invocations/inv_1/execute":
                return {"success": True, "data": None}
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx1:
            self.client.execute_floor_tool("tool_sec", {})
        self.assertEqual(ctx1.exception.code, "FLOOR_EXECUTION_FAILED")

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library not installed in environment")
    def test_registration_cache_identity_aware(self):
        reset_local_identity_key()
        self.addCleanup(reset_local_identity_key)
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
        self.assertEqual(initial_fp, put_calls[-1]["fingerprint"])
        self.assertNotIn("keyVersion", put_calls[-1])
        self.assertEqual(put_calls[-1]["keyEpoch"], 1)

        # 2. Repeated call with same identity and fingerprint is cached (no new call)
        self.client.register_public_key()
        self.assertEqual(len(put_calls), 1)

        # 3. Switching agent ID generates per-identity key/fingerprint and triggers registration
        self.client.http.agent_id = "AMR-IDENT-2"
        self.client.register_public_key()
        self.assertEqual(len(put_calls), 2)
        self.assertEqual(self.client.registered_agent_id, "AMR-IDENT-2")
        ident2_fp = self.client.registered_key_fingerprint
        self.assertNotEqual(ident2_fp, initial_fp)
        self.assertEqual(ident2_fp, put_calls[-1]["fingerprint"])

        # 4. Failed registration attempt is not cached and keeps existing local keys intact
        ident1_priv_before = get_local_identity_key("AMR-IDENT-1")
        ident2_priv_before = get_local_identity_key("AMR-IDENT-2")
        fail_next = True
        self.client.http.agent_id = "AMR-IDENT-FAIL"
        with self.assertRaises(AamarvaError):
            self.client.register_public_key()

        self.assertIsNone(self.client.registered_agent_id)
        self.assertIsNone(self.client.registered_key_fingerprint)
        self.assertIs(get_local_identity_key("AMR-IDENT-1"), ident1_priv_before)
        self.assertIs(get_local_identity_key("AMR-IDENT-2"), ident2_priv_before)
        fail_identity_fp = compute_key_fingerprint(export_public_key_jwk(get_local_identity_key("AMR-IDENT-FAIL").public_key()))

        # Retrying succeeds and records AMR-IDENT-FAIL's own key fingerprint
        fail_next = False
        self.client.register_public_key()
        self.assertEqual(self.client.registered_agent_id, "AMR-IDENT-FAIL")
        self.assertEqual(self.client.registered_key_fingerprint, fail_identity_fp)
        self.assertEqual(self.client.registered_key_fingerprint, put_calls[-1]["fingerprint"])
        self.assertNotEqual(self.client.registered_key_fingerprint, initial_fp)

        # Explicit agent_id failure for another identity does not corrupt active registered identity state
        fail_next = True
        with self.assertRaises(AamarvaError):
            self.client.register_public_key(agent_id="AMR-OTHER-FAIL")
        self.assertEqual(self.client.registered_agent_id, "AMR-IDENT-FAIL")
        self.assertEqual(self.client.registered_key_fingerprint, fail_identity_fp)

    def test_register_public_key_payload_and_failure_isolation_mocked_crypto(self):
        put_calls = []
        fail_next = False
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            nonlocal fail_next
            self.assertTrue(skip_auto_auth)
            if path == "/agents/me/e2ee" and method == "PUT":
                put_calls.append(json_data)
                if fail_next:
                    return {"success": False, "message": "Rejected"}
                return {"success": True, "message": "Registered"}
            return {}

        self.client.http.request.side_effect = mock_req

        class _FakePriv:
            def __init__(self, label):
                self.label = label
            def public_key(self):
                return f"pub:{self.label}"

        with (
            unittest.mock.patch("aamarva.client.get_local_identity_key", side_effect=lambda aid: _FakePriv(aid)),
            unittest.mock.patch("aamarva.client.export_public_key_jwk", side_effect=lambda pub: {"kty": "EC", "crv": "P-256", "x": f"x_{pub}", "y": f"y_{pub}"}),
            unittest.mock.patch("aamarva.client.compute_key_fingerprint", side_effect=lambda jwk: f"SHA256:{jwk['x']}"),
            unittest.mock.patch("aamarva.client.sign_identity_binding", side_effect=lambda priv, aid, fp: f"sig:{aid}:{fp}"),
        ):
            self.client.http.agent_id = "AMR-MOCK-1"
            self.client.register_public_key()
            self.assertEqual(len(put_calls), 1)
            payload = put_calls[-1]
            self.assertEqual(set(payload.keys()), {"publicKey", "fingerprint", "identityKey", "signature", "allowRotation", "keyEpoch"})
            self.assertNotIn("keyVersion", payload)
            self.assertEqual(payload["keyEpoch"], 1)
            self.assertEqual(payload["allowRotation"], True)
            self.assertEqual(self.client.registered_agent_id, "AMR-MOCK-1")
            self.assertEqual(self.client.registered_key_fingerprint, "SHA256:x_pub:AMR-MOCK-1")

            # Failure for explicit different agent_id preserves active identity cache
            fail_next = True
            with self.assertRaises(AamarvaError):
                self.client.register_public_key(agent_id="AMR-MOCK-OTHER")
            self.assertEqual(self.client.registered_agent_id, "AMR-MOCK-1")
            self.assertEqual(self.client.registered_key_fingerprint, "SHA256:x_pub:AMR-MOCK-1")

            # Failure after switching active agent_id clears stale cache until retry succeeds
            self.client.http.agent_id = "AMR-MOCK-2"
            with self.assertRaises(AamarvaError):
                self.client.register_public_key()
            self.assertIsNone(self.client.registered_agent_id)
            self.assertIsNone(self.client.registered_key_fingerprint)

            fail_next = False
            self.client.register_public_key()
            self.assertEqual(self.client.registered_agent_id, "AMR-MOCK-2")
            self.assertEqual(self.client.registered_key_fingerprint, "SHA256:x_pub:AMR-MOCK-2")

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

    def test_update_profile_avatar_and_target_header_scoping(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {"agentId": "AMR-TEST-1111", "name": "Master", "bio": "Fleet lead", "avatar": "https://example.com/a.png"}
        }
        updated = self.client.update_profile(name="Master", bio="Fleet lead", avatar="https://example.com/a.png")
        self.assertEqual(updated.avatar, "https://example.com/a.png")
        self.client.http.request.assert_called_with(
            "PATCH",
            "/agents/me",
            auth=True,
            json_data={"name": "Master", "bio": "Fleet lead", "avatar": "https://example.com/a.png"},
        )

        with self.assertRaises(AamarvaValidationError):
            self.client.update_profile()

        # Verify HttpClient injects x-target-agent-id when target_agent_id is configured
        from aamarva.http import HttpClient
        real_http = HttpClient(agent_id="AMR-MASTER", api_key="sk_m", target_agent_id="AMR-SLAVE-01")
        real_http.access_token = "tok_123"
        captured_headers = {}
        class _DummyResp:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return b'{"success": true, "data": {}}'

        def fake_urlopen(req, timeout=None):
            captured_headers.update({k.lower(): v for k, v in req.header_items()})
            return _DummyResp()

        with unittest.mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            real_http.request("PATCH", "/agents/me", auth=True, json_data={"avatar": "https://example.com/x.png"})
        self.assertEqual(captured_headers.get("x-target-agent-id"), "AMR-SLAVE-01")

    def test_send_cluster_message_enforces_sender_and_master(self):
        last_body = {}
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
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
            nonce="MTIzNDU2Nzg5MDEy",
            recipients=["AMR-WORKER-1", "AMR-WORKER-1"]
        )
        self.assertEqual(last_body.get("senderAgentId"), "AMR-TEST-1111")
        self.assertEqual(last_body.get("version"), 2)
        self.assertEqual(last_body.get("keyEpoch"), 1)
        recipients = last_body.get("recipients", [])
        self.assertIn("AMR-MASTER-AUTH", recipients)
        self.assertNotIn("AMR-SLAVE-TARGET-99", recipients)
        self.assertIn("AMR-TEST-1111", recipients)
        self.assertIn("AMR-WORKER-1", recipients)
        self.assertEqual(recipients.count("AMR-WORKER-1"), 1)

    def test_send_cluster_message_validation_rejects_before_http(self):
        invalid_cases = [
            {"version": 1, "key_epoch": 1, "nonce": "MTIzNDU2Nzg5MDEy"},
            {"version": 3, "key_epoch": 1, "nonce": "MTIzNDU2Nzg5MDEy"},
            {"version": True, "key_epoch": 1, "nonce": "MTIzNDU2Nzg5MDEy"},
            {"version": 2, "key_epoch": 0, "nonce": "MTIzNDU2Nzg5MDEy"},
            {"version": 2, "key_epoch": -1, "nonce": "MTIzNDU2Nzg5MDEy"},
            {"version": 2, "key_epoch": 1.5, "nonce": "MTIzNDU2Nzg5MDEy"},
            {"version": 2, "key_epoch": True, "nonce": "MTIzNDU2Nzg5MDEy"},
            {"version": 2, "key_epoch": 1, "nonce": "not-base64!"},
            {"version": 2, "key_epoch": 1, "nonce": "bW9ja19ub25jZQ=="},
            {"version": 2, "key_epoch": 1, "nonce": "AAAAAAAAAAAAAAAAAAAAAA=="},
        ]
        for case in invalid_cases:
            with self.assertRaises(AamarvaValidationError, msg=f"Should reject {case}"):
                self.client.send_cluster_message(
                    cluster_id="c_1",
                    ciphertext="Y2lwaGVy",
                    nonce=case["nonce"],
                    version=case["version"],
                    key_epoch=case["key_epoch"],
                )
        self.assertEqual(self.client.http.request.call_count, 0)

    def test_send_cluster_message_fails_if_master_unresolvable(self):
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            if path == "/agents/me":
                raise AamarvaAPIError("Profile corrupt", status_code=500)
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx:
            self.client.send_cluster_message(
                cluster_id="c_1",
                ciphertext="cipher",
                nonce="MTIzNDU2Nzg5MDEy"
            )
        self.assertEqual(ctx.exception.code, "MASTER_RESOLUTION_FAILED")

    def test_send_cluster_message_rejects_spoofed_sender(self):
        with self.assertRaises(AamarvaValidationError):
            self.client.send_cluster_message(
                cluster_id="c_1",
                ciphertext="cipher",
                nonce="MTIzNDU2Nzg5MDEy",
                sender_agent_id="AMR-SPOOFED"
            )

    def test_master_identity_aliases(self):
        for field in ["masterId", "master_id", "masterAgentId", "master_agent_id", "ownerAgentId", "owner_agent_id"]:
            last_body = {}
            def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
                nonlocal last_body
                if path == "/agents/me":
                    return {"success": True, "data": {"agentId": "AMR-SLAVE-1", field: "AMR-MASTER-ALIAS"}}
                last_body = json_data or {}
                return {"success": True, "messageId": "msg_c_1"}
            self.client.http.request.side_effect = mock_req
            self.client.send_cluster_message("c_1", "cipher", "MTIzNDU2Nzg5MDEy")
            self.assertIn("AMR-MASTER-ALIAS", last_body.get("recipients", []))

    def test_conflicting_master_identity_fails_closed(self):
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
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
            self.client.send_cluster_message("c_1", "cipher", "MTIzNDU2Nzg5MDEy")
        self.assertEqual(ctx.exception.code, "MASTER_RESOLUTION_FAILED")

    def test_missing_master_identity_fails_closed(self):
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
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
            self.client.send_cluster_message("c_1", "cipher", "MTIzNDU2Nzg5MDEy")
        self.assertEqual(ctx.exception.code, "MASTER_RESOLUTION_FAILED")

    def test_floor_execute_denied_status_raises(self):
        def mock_req(method, path, **kwargs):
            if path == "/floor/agent/tools":
                return {"success": True, "data": [{"id": "tool_denied", "name": "Denied Tool", "description": "", "inputSchema": {}, "accessStatus": "denied"}]}
            if path == "/floor/tools/tool_denied/invoke":
                return {"success": False, "status": "denied", "data": {"status": "denied", "message": "Access not granted"}}
            return {}
        self.client.http.request.side_effect = mock_req
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
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
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

    def test_workflow1_and_workflow2_pure_helpers_and_endpoints(self):
        from aamarva.http import is_approved_endpoint
        from aamarva.crypto import (
            WORKFLOW_HKDF_SALT,
            normalize_agent_id,
            canonical_member_set,
            compute_roster_hash,
            compute_audience_hash,
            create_direct_message_aad_v1,
            create_cluster_wrap_aad_v2,
            create_cluster_message_aad_v2,
            create_cluster_signing_payload_v2,
        )
        self.assertTrue(is_approved_endpoint("GET", "/connections/peer-key/AMR-1234"))
        self.assertTrue(is_approved_endpoint("GET", "/clusters/public/clu_1/members"))
        self.assertTrue(is_approved_endpoint("POST", "/clusters/clu_1/rotate-key"))

        self.assertEqual(WORKFLOW_HKDF_SALT, "aamarva-e2ee-channel-v1")
        self.assertEqual(normalize_agent_id("  amr-node-1 "), "AMR-NODE-1")
        self.assertEqual(canonical_member_set(["amr-b", "AMR-A", "amr-b"]), ["AMR-A", "AMR-B"])

        self.assertEqual(
            create_direct_message_aad_v1("conn_1", "amr-alice"),
            "AAMARVA:E2EE:v1:conn_1:AMR-ALICE",
        )
        roster = ["AMR-MASTER", "AMR-ALICE", "AMR-BOB"]
        rst1 = compute_roster_hash(["amr-bob", "amr-alice", "amr-master"])
        rst2 = compute_roster_hash(roster)
        self.assertTrue(rst1.startswith("RST:") and len(rst1) == 36)
        self.assertEqual(rst1, rst2)

        self.assertEqual(compute_audience_hash([], roster), "ALL")
        self.assertEqual(compute_audience_hash(["AMR-BOB", "AMR-MASTER", "AMR-ALICE"], roster), "ALL")
        aud = compute_audience_hash(["amr-bob", "amr-alice"], roster)
        self.assertTrue(aud.startswith("AUD:") and len(aud) == 36)
        self.assertEqual(aud, compute_audience_hash(["AMR-ALICE", "AMR-BOB"], roster))

        self.assertEqual(create_cluster_wrap_aad_v2("clu_1", 2, "ALL"), "aamarva-cluster-group-key:clu_1:2")
        self.assertEqual(create_cluster_wrap_aad_v2("clu_1", 2, aud), f"aamarva-cluster-group-key:clu_1:2:{aud}")
        self.assertEqual(create_cluster_message_aad_v2("clu_1", "amr-alice", 2, "ALL"), "AAMARVA:E2EE:v2:clu_1:AMR-ALICE:2")
        self.assertEqual(create_cluster_message_aad_v2("clu_1", "amr-alice", 2, aud), f"AAMARVA:E2EE:v2:clu_1:AMR-ALICE:2:{aud}")
        self.assertEqual(
            create_cluster_signing_payload_v2("clu_1", 2, "amr-alice", aud, rst1, 9, "SHA256:FP", "iv_b64", "ct_b64"),
            f"AAMARVA:CLUSTER_MSG:v2|clu_1|2|AMR-ALICE|{aud}|{rst1}|9|SHA256:FP|iv_b64|ct_b64",
        )

    def test_workflow2_client_methods_and_409_rotation_mocked(self):
        calls = []
        race_triggered = False

        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            nonlocal race_triggered
            calls.append((method, path, params, json_data))
            if path == "/connections/peer-key/AMR-PEER-9":
                return {
                    "success": True,
                    "data": {
                        "peerAgentId": "AMR-PEER-9",
                        "peerE2eePublicKey": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
                        "peerKeyFingerprint": "SHA256:AA",
                        "peerKeyEpoch": 1,
                    },
                }
            if path == "/clusters/clu_wf2":
                return {
                    "success": True,
                    "data": {
                        "clusterId": "clu_wf2",
                        "name": "WF2",
                        "epoch": 1,
                        "keyEpoch": 1,
                        "rotationStatus": "ROTATION_REQUIRED_MEMBER_REMOVED",
                        "members": ["AMR-TEST-1111", "AMR-MASTER-AUTH", "AMR-PEER-9"],
                    },
                }
            if path == "/clusters/clu_wf2/rotate-key" and method == "POST":
                return {"success": True, "data": {"clusterId": "clu_wf2", "epoch": 2, "keyEpoch": 2, "rotationStatus": "NONE"}}
            if path == "/clusters/public/clu_wf2/members":
                return {
                    "success": True,
                    "data": [
                        {"agentId": "AMR-TEST-1111", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x1", "y": "y1"}, "keyFingerprint": "SHA256:11", "keyEpoch": 1},
                        {"agentId": "AMR-MASTER-AUTH", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x2", "y": "y2"}, "keyFingerprint": "SHA256:22", "keyEpoch": 1},
                        {"agentId": "AMR-PEER-9", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x3", "y": "y3"}, "keyFingerprint": "SHA256:33", "keyEpoch": 1},
                    ],
                }
            if path == "/agents/me":
                return {"success": True, "data": {"agentId": "AMR-TEST-1111", "masterId": "AMR-MASTER-AUTH"}}
            if path == "/clusters/clu_wf2/key-distribution" and method == "GET":
                if not race_triggered:
                    raise AamarvaAPIError("Not found", status_code=404)
                return {
                    "success": True,
                    "data": {
                        "clusterId": "clu_wf2",
                        "epoch": 2,
                        "audienceHash": (params or {}).get("audienceHash", "ALL"),
                        "keyFingerprint": "SHA256:SEALED",
                        "senderAgentId": "AMR-PEER-9",
                        "senderPublicKey": {"kty": "EC", "crv": "P-256", "x": "x3", "y": "y3"},
                        "encryptedKeyPackage": {"iv": "MTIzNDU2Nzg5MDEy", "key": "d3JhcHBlZF9rZXk="},
                    },
                }
            if path == "/clusters/clu_wf2/key-distribution" and method == "POST":
                race_triggered = True
                raise AamarvaAPIError("Epoch key already sealed", status_code=409, code="EPOCH_KEY_ALREADY_SEALED")
            if path == "/clusters/clu_wf2/messages" and method == "POST":
                return {"success": True, "data": {"messageId": "msg_wf2_1", **(json_data or {})}}
            return {}

        self.client.http.request.side_effect = mock_req

        # 1. Lookup & members endpoints
        pk = self.client.get_peer_key_by_agent("AMR-PEER-9")
        self.assertEqual(pk["peerAgentId"], "AMR-PEER-9")
        members = self.client.get_cluster_members("clu_wf2")
        self.assertEqual(len(members), 3)

        # 2. auto_rotate=False fails closed on ROTATION_REQUIRED_*
        with self.assertRaises(AamarvaError) as ctx:
            self.client.send_encrypted_cluster_message("clu_wf2", "hello", auto_rotate=False)
        self.assertEqual(ctx.exception.code, "CLUSTER_ROTATION_REQUIRED")

        # 3. Auto-rotate + 409 EPOCH_KEY_ALREADY_SEALED race recovery + strictPreflight + Workflow 2 fields
        fake_key = b"\x11" * 32
        fake_priv = unittest.mock.MagicMock()
        with (
            unittest.mock.patch("aamarva.client.get_local_identity_key", return_value=fake_priv),
            unittest.mock.patch("aamarva.client.export_public_key_jwk", return_value={"kty": "EC", "crv": "P-256", "x": "x1", "y": "y1"}),
            unittest.mock.patch("aamarva.client.generate_cluster_key", return_value=fake_key),
            unittest.mock.patch("aamarva.client.compute_key_fingerprint", return_value="SHA256:11"),
            unittest.mock.patch("aamarva.client.compute_group_key_fingerprint", return_value="SHA256:SEALED"),
            unittest.mock.patch(
                "aamarva.client.wrap_cluster_key_for_recipient",
                return_value={
                    "encryptedKeyPackage": {"iv": "a", "key": "b"},
                    "nonce": "a",
                    "wrappingParams": {"kdf": "HKDF-SHA256"},
                },
            ),
            unittest.mock.patch("aamarva.client.unwrap_cluster_key", return_value=fake_key),
            unittest.mock.patch(
                "aamarva.client.encrypt_cluster_message",
                return_value={
                    "ciphertext": "Y2lwaGVydGV4dF93ZjI=",
                    "nonce": "MTIzNDU2Nzg5MDEy",
                    "version": 2,
                    "keyEpoch": 2,
                    "audienceHash": "ALL",
                },
            ),
            unittest.mock.patch("aamarva.client.sign_cluster_message_v2", return_value="cDEzNjNfc2lnX2Jhc2U2NA=="),
        ):
            sent = self.client.send_encrypted_cluster_message("clu_wf2", "Secret fleet directive")
            self.assertEqual(sent["messageId"], "msg_wf2_1")
            self.assertEqual(sent["ciphertext"], "Y2lwaGVydGV4dF93ZjI=")
            msg_posts = [c for c in calls if c[0] == "POST" and c[1] == "/clusters/clu_wf2/messages"]
            self.assertEqual(len(msg_posts), 1)
            body = msg_posts[0][3]
            self.assertEqual(body["keyEpoch"], 2)
            self.assertEqual(body["audienceHash"], "ALL")
            self.assertTrue(body["rosterHash"].startswith("RST:"))
            self.assertEqual(body["keyFingerprint"], "SHA256:SEALED")
            self.assertEqual(body["signature"], "cDEzNjNfc2lnX2Jhc2U2NA==")
            self.assertTrue(body["strictPreflight"])


if __name__ == "__main__":
    unittest.main()
