import base64
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
    compute_roster_hash,
    compute_audience_hash,
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
                return {
                    "success": True,
                    "data": {
                        "status": "approved",
                        "invocationId": "inv_123",
                        "toolId": "tool_sec",
                        "agentId": "AMR-TEST-1111",
                        "serverUrl": "http://127.0.0.1:4000/mcp",
                        "auth": {"type": "bearer", "token": "tok"},
                        "verificationInfo": {"verified": True, "toolId": "tool_sec", "agentId": "AMR-TEST-1111"},
                        "approvedArguments": {"ticker": "AAPL"},
                        "grant": {
                            "grantId": "g1",
                            "status": "active",
                            "agentId": "AMR-TEST-1111",
                            "toolId": "tool_sec",
                            "scope": "tool:invoke",
                            "expiresAt": "2099-01-01T00:00:00Z",
                        },
                    },
                }
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

    def test_floor_execute_reconciled_docs_contract_and_scoping(self):
        import json as _json
        call_order = []
        captured = {}

        def mock_req(method, path, **kwargs):
            if path == "/floor/agent/tools":
                call_order.append("floor:discover")
                return {"success": True, "data": [{"id": "tool_sec", "name": "SEC", "description": "", "inputSchema": {}, "accessStatus": "authorized"}]}
            if path == "/floor/invocations/inv_docs_1/execute":
                call_order.append("floor:execute")
                return {
                    "success": True,
                    "data": {
                        "invocationId": "inv_docs_1",
                        "toolId": "tool_sec",
                        "tool": {"id": "tool_sec", "name": "SEC"},
                        "serverUrl": "https://mcp.weather.internal/sse",
                        "authConfig": {
                            "authType": "bearer",
                            "authHeaderName": "Authorization",
                            "headerValue": "Bearer grant_sec_docs_991",
                        },
                        "verificationInfo": {
                            "verified": True,
                            "toolId": "tool_sec",
                            "agentId": "AMR-TEST-1111",
                        },
                        "grantToken": "grant_sec_docs_991",
                        "accessToken": "grant_sec_docs_991",
                        "scope": "tool:invoke",
                        "expiresAt": "2099-01-01T00:00:00Z",
                        "approvedArguments": {
                            "ticker": "AAPL",
                            "nested": {"b": 2, "a": [True, {"y": 9, "x": 8}]},
                        },
                    },
                }
            return {}

        class _FakeMcpResp:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def getcode(self):
                return 200
            def read(self):
                return _json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode("utf-8")

        def fake_urlopen(req, timeout=None):
            call_order.append("mcp:urlopen")
            captured["url"] = req.full_url
            captured["headers"] = {k.lower(): v for k, v in req.header_items()}
            captured["body"] = _json.loads(req.data.decode("utf-8"))
            return _FakeMcpResp()

        self.client.http.request.side_effect = mock_req
        submitted_args = {
            "nested": {"a": [True, {"x": 8, "y": 9}], "b": 2},
            "ticker": "AAPL",
        }
        with unittest.mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res = self.client.execute_floor_tool(
                "tool_sec",
                submitted_args,
                invocation_id="inv_docs_1",
                required_scope="tool:invoke",
                require_approved_arguments=True,
            )

        self.assertEqual(res.status, "approved")
        self.assertEqual(call_order, ["floor:discover", "floor:execute", "mcp:urlopen"])
        self.assertEqual(captured["url"], "https://mcp.weather.internal/sse")
        self.assertEqual(captured["headers"].get("authorization"), "Bearer grant_sec_docs_991")
        self.assertEqual(captured["body"]["params"]["name"], "tool_sec")

        # Target-agent (slave) scoping test
        slave_client = Aamarva(agent_id="AMR-MASTER-01", api_key="sk_m", target_agent_id="AMR-SLAVE-01")
        slave_client.http.request = MagicMock(side_effect=lambda method, path, **kw: (
            {"success": True, "data": [{"id": "tool_sec", "name": "SEC", "description": "", "inputSchema": {}, "accessStatus": "authorized"}]}
            if path == "/floor/agent/tools" else
            {
                "success": True,
                "data": {
                    "status": "approved",
                    "invocationId": "inv_slave_ok",
                    "toolId": "tool_sec",
                    "agentId": "AMR-SLAVE-01",
                    "serverUrl": "https://mcp.slave.internal/rpc",
                    "auth": {"type": "bearer", "token": "slave_tok"},
                    "verificationInfo": {"verified": True, "toolId": "tool_sec", "agentId": "AMR-SLAVE-01"},
                    "grant": {"status": "active", "agentId": "AMR-SLAVE-01", "toolId": "tool_sec", "expiresAt": "2099-01-01T00:00:00Z"},
                },
            }
        ))
        with unittest.mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            slave_res = slave_client.execute_floor_tool("tool_sec", {"ticker": "MSFT"}, invocation_id="inv_slave_ok")
        self.assertEqual(slave_res.status, "approved")

    def test_floor_execute_zero_mcp_requests_on_auth_failures(self):
        def valid_base():
            return {
                "status": "approved",
                "invocationId": "inv_1",
                "toolId": "tool_sec",
                "agentId": "AMR-TEST-1111",
                "serverUrl": "https://mcp.example.internal/rpc",
                "auth": {"type": "bearer", "token": "super_secret_mcp_token_do_not_leak"},
                "verificationInfo": {"verified": True, "toolId": "tool_sec", "agentId": "AMR-TEST-1111"},
                "grant": {
                    "grantId": "g_1",
                    "status": "active",
                    "agentId": "AMR-TEST-1111",
                    "toolId": "tool_sec",
                    "scope": "tool:invoke",
                    "expiresAt": "2099-01-01T00:00:00Z",
                },
                "approvedArguments": {"ticker": "AAPL", "flag": True, "nested": {"k1": "v1"}},
            }

        def mutated(**overrides):
            obj = valid_base()
            obj.update(overrides)
            return obj

        scenarios = [
            ("missing grant without docs proof", {"invocationId": "inv_1", "toolId": "tool_sec", "agentId": "AMR-TEST-1111", "status": "approved", "serverUrl": "https://mcp.example.internal/rpc", "auth": {"type": "bearer", "token": "secret_tok"}}, None, None, {}),
            ("empty grant object {}", mutated(grant={}), None, None, {}),
            ("missing grant.status (no fallback)", mutated(grant={"grantId": "g1", "agentId": "AMR-TEST-1111", "expiresAt": "2099-01-01T00:00:00Z"}), None, None, {}),
            ("pending status", mutated(status="pending", grant={**valid_base()["grant"], "status": "pending"}), None, None, {}),
            ("rejected status", mutated(status="rejected", grant={**valid_base()["grant"], "status": "rejected"}), None, None, {}),
            ("expired grant.expiresAt", mutated(grant={**valid_base()["grant"], "expiresAt": "2020-01-01T00:00:00Z"}), None, None, {}),
            ("expired top-level expiresAt", mutated(expiresAt="2020-01-01T00:00:00Z"), None, None, {}),
            ("malformed non-ISO expiresAt", mutated(grant={**valid_base()["grant"], "expiresAt": "9999"}), None, None, {}),
            ("null expiresAt", mutated(grant={**valid_base()["grant"], "expiresAt": None}), None, None, {}),
            ("revoked grant status", mutated(grant={**valid_base()["grant"], "status": "revoked"}), None, None, {}),
            ("revoked scope token", mutated(grant={**valid_base()["grant"], "scope": "revoked"}), None, None, {}),
            ("missing required_scope", valid_base(), None, None, {"required_scope": "admin:write"}),
            ("unsupported URL scheme ftp://", mutated(serverUrl="ftp://mcp.example.internal/rpc"), None, None, {}),
            ("malformed URL", mutated(serverUrl="not-a-valid-url"), None, None, {}),
            ("missing credentials", mutated(auth=None), None, None, {}),
            ("empty auth dict", mutated(auth={}), None, None, {}),
            ("verificationInfo.verified false", mutated(verificationInfo={"verified": False, "toolId": "tool_sec", "agentId": "AMR-TEST-1111"}), None, None, {}),
            ("verificationInfo.verified string true", mutated(verificationInfo={"verified": "true", "toolId": "tool_sec", "agentId": "AMR-TEST-1111"}), None, None, {}),
            ("missing verificationInfo when grant omitted", {"invocationId": "inv_1", "toolId": "tool_sec", "agentId": "AMR-TEST-1111", "serverUrl": "https://mcp.example.internal/rpc", "grantToken": "secret_tok"}, None, None, {}),
            ("missing agentId when client has agent_id", mutated(agentId=None, verificationInfo={"verified": True, "toolId": "tool_sec"}, grant={**valid_base()["grant"], "agentId": None}), None, None, {}),
            ("mismatched grant.agentId", mutated(grant={**valid_base()["grant"], "agentId": "AMR-HIJACKED"}), None, None, {}),
            ("master agentId returned instead of slave target_agent_id", mutated(agentId="AMR-MASTER-01", grant={**valid_base()["grant"], "agentId": "AMR-MASTER-01"}, verificationInfo={"verified": True, "toolId": "tool_sec", "agentId": "AMR-MASTER-01"}), None, ("AMR-MASTER-01", "AMR-SLAVE-01"), {}),
            ("fleetId mismatch", mutated(fleetId="fleet_other"), None, None, {"fleet_id": "fleet_prod"}),
            ("mismatched invocationId", mutated(invocationId="inv_WRONG"), None, None, {}),
            ("mismatched grant.toolId", mutated(grant={**valid_base()["grant"], "toolId": "wrong_tool"}), None, None, {}),
            ("tool mismatched", mutated(toolId="wrong_tool"), None, None, {}),
            ("modified nested argument", valid_base(), {"ticker": "AAPL", "flag": True, "nested": {"k1": "TAMPERED"}}, None, {}),
            ("boolean vs integer argument mismatch (True vs 1)", valid_base(), {"ticker": "AAPL", "flag": 1, "nested": {"k1": "v1"}}, None, {}),
            ("extra unauthorized argument", valid_base(), {"ticker": "AAPL", "flag": True, "nested": {"k1": "v1"}, "adminOverride": True}, None, {}),
            ("malformed approvedArguments list", mutated(approvedArguments=["bad"]), None, None, {}),
            ("missing approvedArguments when required", mutated(approvedArguments=None), None, None, {"require_approved_arguments": True}),
            ("post-discovery 403 revocation", "RAISE_403", None, None, {}),
        ]
        for name, resp_data, sub_args, client_ident, exec_kw in scenarios:
            mcp_called = [False]
            urlopen_called = [False]

            def mock_req(method, path, **kwargs):
                if path == "/floor/agent/tools":
                    return {"success": True, "data": [{"id": "tool_sec", "name": "SEC", "description": "", "inputSchema": {}, "accessStatus": "authorized"}]}
                if path == "/floor/tools/tool_sec/invoke":
                    return {"success": True, "data": {"invocationId": "inv_1", "status": "approved"}}
                if path == "/floor/invocations/inv_1/execute":
                    if resp_data == "RAISE_403":
                        raise AamarvaAPIError("Revoked", status_code=403)
                    return {"success": True, "data": resp_data}
                return {}

            test_client = (
                Aamarva(agent_id=client_ident[0], api_key="sk_m", target_agent_id=client_ident[1])
                if client_ident else self.client
            )
            test_client.http.request = MagicMock(side_effect=mock_req)
            args_to_send = sub_args if sub_args is not None else {"ticker": "AAPL", "flag": True, "nested": {"k1": "v1"}}

            with (
                unittest.mock.patch("urllib.request.urlopen", side_effect=lambda *a, **kw: urlopen_called.__setitem__(0, True)),
                unittest.mock.patch("aamarva.client.invoke_external_mcp_tool", side_effect=lambda *a, **kw: mcp_called.__setitem__(0, True)),
            ):
                with self.assertRaises(AamarvaError) as err_ctx:
                    test_client.execute_floor_tool("tool_sec", args_to_send, **exec_kw)
                self.assertFalse(urlopen_called[0], f"urllib.request.urlopen called for scenario '{name}'")
                self.assertFalse(mcp_called[0], f"MCP tool invoked for scenario '{name}'")
                self.assertNotIn("super_secret_mcp_token_do_not_leak", str(err_ctx.exception))
                self.assertNotIn("secret_tok", str(err_ctx.exception))

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

    def _wf2_defaults(self):
        fp1 = "SHA256:" + ":".join(["11"] * 32)
        fp2 = "SHA256:" + ":".join(["22"] * 32)
        fp3 = "SHA256:" + ":".join(["33"] * 32)
        fp_group = "SHA256:" + ":".join(["AA"] * 32)
        sig_64 = base64.b64encode(b"\x01" * 64).decode("ascii")
        return fp1, fp2, fp3, fp_group, sig_64

    def test_send_cluster_message_enforces_sender_and_master(self):
        fp1, fp2, fp3, fp_group, sig_64 = self._wf2_defaults()
        rst = compute_roster_hash(["AMR-TEST-1111", "AMR-MASTER-AUTH", "AMR-WORKER-1"])
        last_body = {}
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            nonlocal last_body
            if path == "/agents/me":
                return {"success": True, "data": {"agentId": "AMR-TEST-1111", "masterId": "AMR-MASTER-AUTH"}}
            if path == "/clusters/c_1":
                return {"success": True, "data": {"clusterId": "c_1", "name": "C1", "epoch": 1, "rotationStatus": "NONE", "members": ["AMR-TEST-1111", "AMR-MASTER-AUTH", "AMR-WORKER-1"]}}
            if path == "/clusters/public/c_1/members":
                return {"success": True, "data": [
                    {"agentId": "AMR-TEST-1111", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x1", "y": "y1"}, "keyFingerprint": fp1, "keyEpoch": 1},
                    {"agentId": "AMR-MASTER-AUTH", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x2", "y": "y2"}, "keyFingerprint": fp2, "keyEpoch": 1},
                    {"agentId": "AMR-WORKER-1", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x3", "y": "y3"}, "keyFingerprint": fp3, "keyEpoch": 1},
                ]}
            last_body = json_data or {}
            return {"success": True, "messageId": "msg_c_1"}
        self.client.http.request.side_effect = mock_req
        self.client.target_agent_id = "AMR-SLAVE-TARGET-99"

        with (
            unittest.mock.patch("aamarva.client.export_public_key_jwk", side_effect=lambda k=None: k),
            unittest.mock.patch("aamarva.client.compute_key_fingerprint", return_value=fp1),
            unittest.mock.patch("aamarva.client.verify_cluster_message_signature_v2", return_value=True),
        ):
            self.client.send_cluster_message(
                cluster_id="c_1",
                ciphertext="cipher_123",
                nonce="MTIzNDU2Nzg5MDEy",
                key_epoch=1,
                recipients=["AMR-WORKER-1", "AMR-WORKER-1"],
                audience_hash="ALL",
                roster_hash=rst,
                key_fingerprint=fp_group,
                signature=sig_64,
                strict_preflight=True,
            )
        self.assertEqual(last_body.get("senderAgentId"), "AMR-TEST-1111")
        self.assertEqual(last_body.get("version"), 2)
        self.assertEqual(last_body.get("keyEpoch"), 1)
        self.assertTrue(last_body.get("strictPreflight"))
        recipients = last_body.get("recipients", [])
        self.assertIn("AMR-MASTER-AUTH", recipients)
        self.assertNotIn("AMR-SLAVE-TARGET-99", recipients)
        self.assertIn("AMR-TEST-1111", recipients)
        self.assertIn("AMR-WORKER-1", recipients)
        self.assertEqual(recipients.count("AMR-WORKER-1"), 1)

    def test_send_cluster_message_validation_rejects_before_http(self):
        _, _, _, fp_group, sig_64 = self._wf2_defaults()
        rst = compute_roster_hash(["AMR-TEST-1111", "AMR-MASTER-AUTH"])
        base = {
            "version": 2,
            "key_epoch": 1,
            "nonce": "MTIzNDU2Nzg5MDEy",
            "audience_hash": "ALL",
            "roster_hash": rst,
            "key_fingerprint": fp_group,
            "signature": sig_64,
            "strict_preflight": True,
        }
        invalid_cases = [
            {**base, "version": 1},
            {**base, "version": 3},
            {**base, "version": True},
            {**base, "key_epoch": None},
            {**base, "key_epoch": 0},
            {**base, "key_epoch": -1},
            {**base, "key_epoch": 1.5},
            {**base, "key_epoch": True},
            {**base, "nonce": "not-base64!"},
            {**base, "nonce": "bW9ja19ub25jZQ=="},
            {**base, "nonce": "AAAAAAAAAAAAAAAAAAAAAA=="},
            {**base, "strict_preflight": False},
            {**base, "strict_preflight": None},
            {**base, "audience_hash": ""},
            {**base, "audience_hash": "INVALID_AUD"},
            {**base, "roster_hash": "INVALID_RST"},
            {**base, "key_fingerprint": "SHA256:short"},
            {**base, "signature": "c2hvcnQ="},
        ]
        for case in invalid_cases:
            with self.assertRaises(AamarvaValidationError, msg=f"Should reject {case}"):
                self.client.send_cluster_message(
                    cluster_id="c_1",
                    ciphertext="Y2lwaGVy",
                    nonce=case["nonce"],
                    version=case["version"],
                    key_epoch=case["key_epoch"],
                    audience_hash=case["audience_hash"],
                    roster_hash=case["roster_hash"],
                    key_fingerprint=case["key_fingerprint"],
                    signature=case["signature"],
                    strict_preflight=case["strict_preflight"],
                )
        self.assertEqual(self.client.http.request.call_count, 0)

    def test_send_cluster_message_fails_if_master_unresolvable(self):
        _, _, _, fp_group, sig_64 = self._wf2_defaults()
        rst = compute_roster_hash(["AMR-TEST-1111", "AMR-MASTER-AUTH"])
        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            if path == "/agents/me":
                raise AamarvaAPIError("Profile corrupt", status_code=500)
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx:
            self.client.send_cluster_message(
                cluster_id="c_1",
                ciphertext="cipher",
                nonce="MTIzNDU2Nzg5MDEy",
                key_epoch=1,
                audience_hash="ALL",
                roster_hash=rst,
                key_fingerprint=fp_group,
                signature=sig_64,
                strict_preflight=True,
            )
        self.assertEqual(ctx.exception.code, "MASTER_RESOLUTION_FAILED")

    def test_send_cluster_message_rejects_spoofed_sender(self):
        _, _, _, fp_group, sig_64 = self._wf2_defaults()
        rst = compute_roster_hash(["AMR-TEST-1111", "AMR-MASTER-AUTH"])
        with self.assertRaises(AamarvaValidationError) as ctx:
            self.client.send_cluster_message(
                cluster_id="c_1",
                ciphertext="cipher",
                nonce="MTIzNDU2Nzg5MDEy",
                key_epoch=1,
                sender_agent_id="AMR-SPOOFED",
                audience_hash="ALL",
                roster_hash=rst,
                key_fingerprint=fp_group,
                signature=sig_64,
                strict_preflight=True,
            )
        self.assertEqual(ctx.exception.code, "SENDER_IDENTITY_MISMATCH")

    def test_master_identity_aliases(self):
        fp1, fp2, _, fp_group, sig_64 = self._wf2_defaults()
        rst = compute_roster_hash(["AMR-SLAVE-1", "AMR-MASTER-ALIAS"])
        for field in ["masterId", "master_id", "masterAgentId", "master_agent_id", "ownerAgentId", "owner_agent_id"]:
            last_body = {}
            def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
                nonlocal last_body
                if path == "/agents/me":
                    return {"success": True, "data": {"agentId": "AMR-SLAVE-1", field: "AMR-MASTER-ALIAS"}}
                if path == "/clusters/c_1":
                    return {"success": True, "data": {"clusterId": "c_1", "name": "C1", "epoch": 1, "rotationStatus": "NONE", "members": ["AMR-SLAVE-1", "AMR-MASTER-ALIAS"]}}
                if path == "/clusters/public/c_1/members":
                    return {"success": True, "data": [
                        {"agentId": "AMR-SLAVE-1", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x1", "y": "y1"}, "keyFingerprint": fp1, "keyEpoch": 1},
                        {"agentId": "AMR-MASTER-ALIAS", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x2", "y": "y2"}, "keyFingerprint": fp2, "keyEpoch": 1},
                    ]}
                last_body = json_data or {}
                return {"success": True, "messageId": "msg_c_1"}
            self.client.http.request.side_effect = mock_req
            self.client.http.agent_id = "AMR-SLAVE-1"
            with (
                unittest.mock.patch("aamarva.client.export_public_key_jwk", side_effect=lambda k=None: k),
                unittest.mock.patch("aamarva.client.compute_key_fingerprint", return_value=fp1),
                unittest.mock.patch("aamarva.client.verify_cluster_message_signature_v2", return_value=True),
            ):
                self.client.send_cluster_message(
                    "c_1",
                    "cipher",
                    "MTIzNDU2Nzg5MDEy",
                    key_epoch=1,
                    audience_hash="ALL",
                    roster_hash=rst,
                    key_fingerprint=fp_group,
                    signature=sig_64,
                    strict_preflight=True,
                )
            self.assertIn("AMR-MASTER-ALIAS", last_body.get("recipients", []))

    def test_conflicting_master_identity_fails_closed(self):
        _, _, _, fp_group, sig_64 = self._wf2_defaults()
        rst = compute_roster_hash(["AMR-SLAVE-1", "AMR-MASTER-A"])
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
            self.client.send_cluster_message(
                "c_1",
                "cipher",
                "MTIzNDU2Nzg5MDEy",
                key_epoch=1,
                audience_hash="ALL",
                roster_hash=rst,
                key_fingerprint=fp_group,
                signature=sig_64,
                strict_preflight=True,
            )
        self.assertEqual(ctx.exception.code, "MASTER_RESOLUTION_FAILED")

    def test_missing_master_identity_fails_closed(self):
        _, _, _, fp_group, sig_64 = self._wf2_defaults()
        rst = compute_roster_hash(["AMR-ORPHAN-SLAVE"])
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
            self.client.send_cluster_message(
                "c_1",
                "cipher",
                "MTIzNDU2Nzg5MDEy",
                key_epoch=1,
                audience_hash="ALL",
                roster_hash=rst,
                key_fingerprint=fp_group,
                signature=sig_64,
                strict_preflight=True,
            )
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
        rotated = False
        fp1, fp2, fp3, fp_sealed, sig_64 = self._wf2_defaults()
        fp_peer_lookup = "SHA256:" + ":".join(["AA"] * 32)

        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
            nonlocal race_triggered, rotated
            calls.append((method, path, params, json_data))
            if path == "/connections/peer-key/AMR-PEER-9":
                return {
                    "success": True,
                    "data": {
                        "peerAgentId": "AMR-PEER-9",
                        "peerE2eePublicKey": {"kty": "EC", "crv": "P-256", "x": "x3", "y": "y3"},
                        "peerKeyFingerprint": fp_peer_lookup,
                        "peerKeyEpoch": 1,
                    },
                }
            if path == "/clusters/clu_wf2":
                return {
                    "success": True,
                    "data": {
                        "clusterId": "clu_wf2",
                        "name": "WF2",
                        "epoch": 2 if rotated else 1,
                        "keyEpoch": 2 if rotated else 1,
                        "rotationStatus": "NONE" if rotated else "ROTATION_REQUIRED_MEMBER_REMOVED",
                        "members": ["AMR-TEST-1111", "AMR-MASTER-AUTH", "AMR-PEER-9"],
                    },
                }
            if path == "/clusters/clu_wf2/rotate-key" and method == "POST":
                rotated = True
                return {"success": True, "data": {"clusterId": "clu_wf2", "epoch": 2, "keyEpoch": 2, "rotationStatus": "NONE"}}
            if path == "/clusters/public/clu_wf2/members":
                return {
                    "success": True,
                    "data": [
                        {"agentId": "AMR-TEST-1111", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x1", "y": "y1"}, "keyFingerprint": fp1, "keyEpoch": 1},
                        {"agentId": "AMR-MASTER-AUTH", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x2", "y": "y2"}, "keyFingerprint": fp2, "keyEpoch": 1},
                        {"agentId": "AMR-PEER-9", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x3", "y": "y3"}, "keyFingerprint": fp3, "keyEpoch": 1},
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
                        "keyFingerprint": fp_sealed,
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

        def fake_fp(k):
            x = k.get("x") if isinstance(k, dict) else None
            return {"x1": fp1, "x2": fp2, "x3": fp3}.get(x, fp1)

        with (
            unittest.mock.patch("aamarva.client.get_local_identity_key", return_value=fake_priv),
            unittest.mock.patch("aamarva.client.export_public_key_jwk", side_effect=lambda k=None: k if isinstance(k, dict) and "x" in k else {"kty": "EC", "crv": "P-256", "x": "x1", "y": "y1"}),
            unittest.mock.patch("aamarva.client.generate_cluster_key", return_value=fake_key),
            unittest.mock.patch("aamarva.client.compute_key_fingerprint", side_effect=fake_fp),
            unittest.mock.patch("aamarva.client.compute_group_key_fingerprint", return_value=fp_sealed),
            unittest.mock.patch(
                "aamarva.client.wrap_cluster_key_for_recipient",
                return_value={
                    "encryptedKeyPackage": {"iv": "MTIzNDU2Nzg5MDEy", "key": "d3JhcHBlZF9rZXk="},
                    "nonce": "MTIzNDU2Nzg5MDEy",
                    "wrappingParams": {"algorithm": "ECDH-ES+HKDF-256+A256GCM", "curve": "P-256", "hkdfHash": "SHA-256"},
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
            unittest.mock.patch("aamarva.client.sign_cluster_message_v2", return_value=sig_64),
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
            self.assertEqual(body["keyFingerprint"], fp_sealed)
            self.assertEqual(body["signature"], sig_64)
            self.assertTrue(body["strictPreflight"])

    def test_direct_connection_fail_closed_invariants(self):
        # 1. Missing or invalid peerKeyEpoch fails closed
        for bad_epoch in (None, 0, -1, True):
            self.client.http.request.side_effect = [
                {
                    "success": True,
                    "data": {
                        "peerAgentId": "AMR-PEER-2222",
                        "peerE2eePublicKey": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
                        "peerKeyFingerprint": "SHA256:" + ":".join(["11"] * 32),
                        **({"peerKeyEpoch": bad_epoch} if bad_epoch is not None else {}),
                    },
                }
            ]
            with self.assertRaises(AamarvaError) as ctx:
                self.client._fetch_verified_peer_key("conn-1", "AMR-PEER-2222")
            self.assertEqual(ctx.exception.code, "PEER_KEY_VERIFICATION_FAILED")

        # 2. connectionId mismatch on peer-key endpoint fails closed
        self.client.http.request.side_effect = [
            {
                "success": True,
                "data": {
                    "connectionId": "conn-OTHER",
                    "peerAgentId": "AMR-PEER-2222",
                    "peerE2eePublicKey": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
                    "peerKeyFingerprint": "SHA256:" + ":".join(["11"] * 32),
                    "peerKeyEpoch": 1,
                },
            }
        ]
        with self.assertRaises(AamarvaError) as ctx:
            self.client._fetch_verified_peer_key("conn-1", "AMR-PEER-2222")
        self.assertEqual(ctx.exception.code, "PEER_KEY_VERIFICATION_FAILED")

        # 3. get_encrypted_messages rejects plaintext & invalid keyEpoch
        self.client.http.request.side_effect = [[{"messageId": "m1", "content": "plain"}]]
        with self.assertRaises(AamarvaError) as ctx:
            self.client.get_encrypted_messages("conn-1")
        self.assertEqual(ctx.exception.code, "PLAINTEXT_MESSAGE_RECEIVED")

        self.client.http.request.side_effect = [[{
            "messageId": "m1",
            "connectionId": "conn-1",
            "senderAgentId": "AMR-PEER-2222",
            "ciphertext": "Y2lwaGVy",
            "nonce": "MTIzNDU2Nzg5MDEy",
            "version": 1,
            "keyEpoch": 0,
        }]]
        with self.assertRaises(AamarvaError) as ctx:
            self.client.get_encrypted_messages("conn-1")
        self.assertEqual(ctx.exception.code, "MESSAGE_INVALID_ENVELOPE")

        # 4. get_messages rejects connectionId mismatch & passes explicit keyEpoch to get_local_identity_key
        def mock_get_msgs_mismatch(method, path, **kwargs):
            if path == "/connections/conn-1/peer-key":
                return {"success": True, "data": {
                    "peerAgentId": "AMR-PEER-2222",
                    "peerE2eePublicKey": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
                    "peerKeyFingerprint": "SHA256:" + ":".join(["11"] * 32),
                    "peerIdentityKey": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
                    "peerKeySignature": "c2ln",
                    "peerKeyEpoch": 1,
                }}
            return {"success": True, "data": [{
                "messageId": "m1",
                "connectionId": "conn-WRONG",
                "senderAgentId": "AMR-PEER-2222",
                "ciphertext": "Y2lwaGVy",
                "nonce": "MTIzNDU2Nzg5MDEy",
                "version": 1,
                "keyEpoch": 1,
            }]}
        self.client.http.request.side_effect = mock_get_msgs_mismatch
        with unittest.mock.patch("aamarva.client.verify_peer_key", return_value=True):
            with self.assertRaises(AamarvaError) as ctx:
                self.client.get_messages("conn-1", "AMR-PEER-2222")
            self.assertEqual(ctx.exception.code, "MESSAGE_INVALID_ENVELOPE")

        seen_epochs = []
        def mock_get_msgs_ep3(method, path, **kwargs):
            if path == "/connections/conn-1/peer-key":
                return {"success": True, "data": {
                    "peerAgentId": "AMR-PEER-2222",
                    "peerE2eePublicKey": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
                    "peerKeyFingerprint": "SHA256:" + ":".join(["11"] * 32),
                    "peerIdentityKey": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
                    "peerKeySignature": "c2ln",
                    "peerKeyEpoch": 3,
                }}
            return {"success": True, "data": [{
                "messageId": "m1",
                "connectionId": "conn-1",
                "senderAgentId": "AMR-PEER-2222",
                "ciphertext": "Y2lwaGVy",
                "nonce": "MTIzNDU2Nzg5MDEy",
                "version": 1,
                "keyEpoch": 3,
            }]}
        self.client.http.request.side_effect = mock_get_msgs_ep3
        with (
            unittest.mock.patch("aamarva.client.verify_peer_key", return_value=True),
            unittest.mock.patch("aamarva.client.get_local_identity_key", side_effect=lambda aid, epoch=None: seen_epochs.append(epoch) or MagicMock()),
            unittest.mock.patch("aamarva.client.decrypt_message_with_keys", return_value="decrypted-ep3"),
        ):
            msgs = self.client.get_messages("conn-1", "AMR-PEER-2222")
            self.assertEqual(seen_epochs, [3])
            self.assertEqual(msgs[0].content, "decrypted-ep3")

    def test_cluster_fail_closed_invariants(self):
        fp1, fp2, fp3, fp_group, sig_64 = self._wf2_defaults()
        rst = compute_roster_hash(["AMR-TEST-1111", "AMR-MASTER-AUTH"])

        # 1. get_cluster_members rejects malformed payload & invalid member keyEpoch
        self.client.http.request.side_effect = [{"success": True, "data": {"unexpected": True}}]
        with self.assertRaises(AamarvaError) as ctx:
            self.client.get_cluster_members("c_1")
        self.assertEqual(ctx.exception.code, "CLUSTER_MEMBERSHIP_INVALID")

        self.client.http.request.side_effect = [{"success": True, "data": [{"agentId": "AMR-TEST-1111", "keyEpoch": 0}]}]
        with self.assertRaises(AamarvaError) as ctx:
            self.client.get_cluster_members("c_1")
        self.assertEqual(ctx.exception.code, "CLUSTER_MEMBERSHIP_INVALID")

        # 2. rotate_cluster_key rejects non-monotonic epoch and evicts older cache
        self.client.cluster_key_cache["c_1:1:ALL"] = {"key": b"old", "epoch": 1}
        self.client.http.request.side_effect = [{"success": True, "data": {"clusterId": "c_1", "epoch": 2, "keyEpoch": 2}}]
        with self.assertRaises(AamarvaError) as ctx:
            self.client.rotate_cluster_key("c_1", current_epoch=2)
        self.assertEqual(ctx.exception.code, "CLUSTER_ROTATION_FAILED")

        self.client.http.request.side_effect = [{"success": True, "data": {"clusterId": "c_1", "epoch": 3, "keyEpoch": 3}}]
        self.client.rotate_cluster_key("c_1", current_epoch=2)
        self.assertNotIn("c_1:1:ALL", self.client.cluster_key_cache)

        # 3. get_cluster_key requires explicit epoch
        with self.assertRaises(AamarvaValidationError) as ctx:
            self.client.get_cluster_key("c_1")
        self.assertEqual(ctx.exception.code, "CLUSTER_INVALID_EPOCH")

        # 4. send_cluster_message rejects non-member recipient, rotation-required, stale epoch, bad signature
        def base_cluster_mock(rotation_status="NONE", cluster_epoch=1):
            def _fn(method, path, **kwargs):
                if path == "/agents/me":
                    return {"success": True, "data": {"agentId": "AMR-TEST-1111", "masterId": "AMR-MASTER-AUTH"}}
                if path == "/clusters/c_1":
                    return {"success": True, "data": {"clusterId": "c_1", "name": "C1", "epoch": cluster_epoch, "rotationStatus": rotation_status}}
                if path == "/clusters/public/c_1/members":
                    return {"success": True, "data": [
                        {"agentId": "AMR-TEST-1111", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x1", "y": "y1"}, "keyFingerprint": fp1, "keyEpoch": 1},
                        {"agentId": "AMR-MASTER-AUTH", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x2", "y": "y2"}, "keyFingerprint": fp2, "keyEpoch": 1},
                    ]}
                return {"success": True, "data": {"messageId": "should-not-post"}}
            return _fn

        self.client.http.request.side_effect = base_cluster_mock()
        with self.assertRaises(AamarvaError) as ctx:
            self.client.send_cluster_message(
                "c_1", "cipher", "MTIzNDU2Nzg5MDEy",
                key_epoch=1, recipients=["AMR-OUTSIDER"],
                audience_hash="ALL", roster_hash=rst, key_fingerprint=fp_group, signature=sig_64, strict_preflight=True,
            )
        self.assertEqual(ctx.exception.code, "CLUSTER_MEMBERSHIP_INVALID")

        self.client.http.request.side_effect = base_cluster_mock(rotation_status="ROTATION_REQUIRED_MEMBER_REMOVED")
        with self.assertRaises(AamarvaError) as ctx:
            self.client.send_cluster_message(
                "c_1", "cipher", "MTIzNDU2Nzg5MDEy",
                key_epoch=1, audience_hash="ALL", roster_hash=rst, key_fingerprint=fp_group, signature=sig_64, strict_preflight=True,
            )
        self.assertEqual(ctx.exception.code, "CLUSTER_ROTATION_REQUIRED")

        self.client.http.request.side_effect = base_cluster_mock(cluster_epoch=2)
        with self.assertRaises(AamarvaError) as ctx:
            self.client.send_cluster_message(
                "c_1", "cipher", "MTIzNDU2Nzg5MDEy",
                key_epoch=1, audience_hash="ALL", roster_hash=rst, key_fingerprint=fp_group, signature=sig_64, strict_preflight=True,
            )
        self.assertEqual(ctx.exception.code, "CLUSTER_INVALID_EPOCH")

        self.client.http.request.side_effect = base_cluster_mock(cluster_epoch=1)
        with (
            unittest.mock.patch("aamarva.client.export_public_key_jwk", side_effect=lambda k=None: k),
            unittest.mock.patch("aamarva.client.compute_key_fingerprint", return_value=fp1),
            unittest.mock.patch("aamarva.client.verify_cluster_message_signature_v2", return_value=False),
        ):
            with self.assertRaises(AamarvaError) as ctx:
                self.client.send_cluster_message(
                    "c_1", "cipher", "MTIzNDU2Nzg5MDEy",
                    key_epoch=1, audience_hash="ALL", roster_hash=rst, key_fingerprint=fp_group, signature=sig_64, strict_preflight=True,
                )
            self.assertEqual(ctx.exception.code, "CLUSTER_SIGNATURE_INVALID")

        # 5. send_encrypted_cluster_message does NOT fall back to distribute_cluster_key on 403
        dist_calls = []
        def mock_403(method, path, **kwargs):
            if path == "/agents/me":
                return {"success": True, "data": {"agentId": "AMR-TEST-1111", "masterId": "AMR-MASTER-AUTH"}}
            if path == "/clusters/c_1":
                return {"success": True, "data": {"clusterId": "c_1", "name": "C1", "epoch": 1, "rotationStatus": "NONE"}}
            if path == "/clusters/public/c_1/members":
                return {"success": True, "data": [
                    {"agentId": "AMR-TEST-1111", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x1", "y": "y1"}, "keyFingerprint": fp1, "keyEpoch": 1},
                    {"agentId": "AMR-MASTER-AUTH", "publicKey": {"kty": "EC", "crv": "P-256", "x": "x2", "y": "y2"}, "keyFingerprint": fp2, "keyEpoch": 1},
                ]}
            if path == "/clusters/c_1/key-distribution" and method == "GET":
                raise AamarvaAPIError("Forbidden", status_code=403)
            if path == "/clusters/c_1/key-distribution" and method == "POST":
                dist_calls.append(path)
            return {}
        self.client.http.request.side_effect = mock_403
        with self.assertRaises(AamarvaAPIError):
            self.client.send_encrypted_cluster_message("c_1", "secret")
        self.assertEqual(len(dist_calls), 0)

        # 6. decrypt_cluster_message fail-closed checks
        valid_msg = {
            "version": 2,
            "keyEpoch": 1,
            "audienceHash": "ALL",
            "rosterHash": rst,
            "keyFingerprint": fp_group,
            "senderAgentId": "AMR-MASTER-AUTH",
            "nonce": "MTIzNDU2Nzg5MDEy",
            "ciphertext": "Y2lwaGVydGV4dA==",
            "signature": sig_64,
        }
        with self.assertRaises(AamarvaError) as ctx:
            self.client.decrypt_cluster_message("c_1", valid_msg, verify_signature=False)
        self.assertEqual(ctx.exception.code, "CLUSTER_SIGNATURE_INVALID")

        with self.assertRaises(AamarvaError) as ctx:
            self.client.decrypt_cluster_message("c_1", {**valid_msg, "version": 1})
        self.assertEqual(ctx.exception.code, "INVALID_CLUSTER_MESSAGE_VERSION")

        with self.assertRaises(AamarvaError) as ctx:
            self.client.decrypt_cluster_message("c_1", {**valid_msg, "signature": ""})
        self.assertEqual(ctx.exception.code, "CLUSTER_SIGNATURE_INVALID")

        self.client.http.request.side_effect = base_cluster_mock()
        with self.assertRaises(AamarvaError) as ctx:
            self.client.decrypt_cluster_message("c_1", {**valid_msg, "senderAgentId": "AMR-OUTSIDER"})
        self.assertEqual(ctx.exception.code, "CLUSTER_MEMBERSHIP_INVALID")

        def fp_by_x(k):
            x = k.get("x") if isinstance(k, dict) else None
            return {"x1": fp1, "x2": fp2, "x_evil": fp3}.get(x, fp2)

        self.client.http.request.side_effect = base_cluster_mock()
        with (
            unittest.mock.patch("aamarva.client.export_public_key_jwk", side_effect=lambda k=None: k),
            unittest.mock.patch("aamarva.client.compute_key_fingerprint", side_effect=fp_by_x),
        ):
            with self.assertRaises(AamarvaError) as ctx:
                self.client.decrypt_cluster_message("c_1", valid_msg, sender_public_key={"kty": "EC", "crv": "P-256", "x": "x_evil", "y": "y"})
            self.assertEqual(ctx.exception.code, "CLUSTER_SIGNATURE_INVALID")

        # 7. decrypt_cluster_message rejects sealed rosterHash mismatch
        wrong_rst = compute_roster_hash(["AMR-TEST-1111", "AMR-MASTER-AUTH", "AMR-EXTRA"])
        self.client.cluster_key_cache[self.client._cluster_cache_key("c_1", 1, "ALL")] = {
            "key": b"\x22" * 32,
            "keyFingerprint": fp_group,
            "rosterHash": wrong_rst,
            "audienceHash": "ALL",
            "epoch": 1,
        }
        self.client.http.request.side_effect = base_cluster_mock()
        with (
            unittest.mock.patch("aamarva.client.export_public_key_jwk", side_effect=lambda k=None: k),
            unittest.mock.patch("aamarva.client.compute_key_fingerprint", side_effect=fp_by_x),
            unittest.mock.patch("aamarva.client.verify_cluster_message_signature_v2", return_value=True),
        ):
            with self.assertRaises(AamarvaError) as ctx:
                self.client.decrypt_cluster_message("c_1", valid_msg)
            self.assertEqual(ctx.exception.code, "ROSTER_HASH_MISMATCH")


if __name__ == "__main__":
    unittest.main()
