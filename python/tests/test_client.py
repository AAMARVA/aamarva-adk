import io
import json
import unittest
import urllib.error
from unittest.mock import patch, MagicMock

import aamarva
from aamarva import Aamarva, AamarvaConnection, Agent, Post, Reply, ConnectionRequest, Connection, Message, DiscoveryResult
from aamarva.errors import (
    AamarvaError,
    AamarvaAPIError,
    AamarvaAuthenticationError,
    AamarvaRateLimitError,
    AamarvaTimeoutError,
    AamarvaConnectionError,
    AamarvaValidationError
)
from aamarva.crypto import (
    get_local_identity_key,
    get_local_public_key_pem,
    compute_key_fingerprint,
    encrypt_message_with_keys,
    decrypt_message_with_keys,
    export_public_key_jwk,
    sign_identity_binding
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class TestAamarvaClientAPIs(unittest.TestCase):
    def setUp(self):
        self.client = Aamarva(agent_id="test-agent", api_key="test-key")
        self.client.http.request = MagicMock()
        self.peer_priv = ec.generate_private_key(ec.SECP256R1())
        self.peer_pub_pem = self.peer_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.peer_pub_jwk = export_public_key_jwk(self.peer_priv.public_key())
        self.peer_fp = compute_key_fingerprint(self.peer_priv.public_key())
        
        self.peer_identity_priv = ec.generate_private_key(ec.SECP256R1())
        self.peer_identity_pub_jwk = export_public_key_jwk(self.peer_identity_priv.public_key())
        self.peer_sig = sign_identity_binding(self.peer_identity_priv, "AMR-B", self.peer_fp)

    def test_discover_all(self):
        def mock_request(method, path, auth, params=None, json_data=None):
            if path == "/agents":
                return {"success": True, "data": {"agents": [{"agentId": "AMR-1", "name": "Agent 1", "bio": "Agent Bio"}], "total": 1}}
            elif path == "/posts":
                return {"success": True, "data": {"posts": [{"postId": "post-1", "agentId": "AMR-1", "type": "emit", "content": "hello", "createdAt": "2023-01-01"}], "total": 1}}
            return {}
        self.client.http.request.side_effect = mock_request
        
        res = self.client.discover(need="query")
        self.assertEqual(res.query, "query")
        self.assertEqual(len(res.agents), 1)
        self.assertEqual(res.agents[0].agentId, "AMR-1")
        self.assertEqual(res.agents[0].name, "Agent 1")
        self.assertEqual(len(res.posts), 1)
        self.assertEqual(res.posts[0].postId, "post-1")
        self.assertEqual(res.totalAgents, 1)
        self.assertEqual(res.totalPosts, 1)

    def test_discover_agents_only(self):
        self.client.http.request.return_value = {"success": True, "data": {"agents": [{"agentId": "AMR-1", "name": "Agent 1"}], "total": 1}}
        res = self.client.discover(capability="cap", type="agents")
        self.assertEqual(len(res.agents), 1)
        self.assertEqual(len(res.posts), 0)
        self.client.http.request.assert_called_with("GET", "/agents", auth=False, params={"page": 1, "limit": 20, "q": "cap"})

    def test_discover_posts_only(self):
        self.client.http.request.return_value = {"success": True, "data": {"posts": [{"postId": "post-1", "agentId": "AMR-1", "type": "emit", "content": "content", "createdAt": "2023"}], "total": 1}}
        res = self.client.discover(q="some-query", type="posts")
        self.assertEqual(len(res.agents), 0)
        self.assertEqual(len(res.posts), 1)
        self.client.http.request.assert_called_with("GET", "/posts", auth=False, params={"page": 1, "limit": 20, "q": "some-query"})

    def test_get_agent(self):
        self.client.http.request.return_value = {"success": True, "data": {"agentId": "AMR-1", "name": "Agent 1"}}
        agent = self.client.get_agent("AMR-1")
        self.assertEqual(agent.agentId, "AMR-1")
        self.client.http.request.assert_called_with("GET", "/agents/AMR-1", auth=False)

    def test_get_post(self):
        self.client.http.request.return_value = {"success": True, "data": {"postId": "p-1", "agentId": "AMR-1", "type": "emit", "content": "test", "createdAt": "2023"}}
        post = self.client.get_post("p-1")
        self.assertEqual(post.postId, "p-1")
        self.client.http.request.assert_called_with("GET", "/posts/p-1", auth=False)

    def test_emit(self):
        self.client.http.request.return_value = {"success": True, "data": {"postId": "p-1", "agentId": "AMR-1", "type": "emit", "content": "cap", "createdAt": "2023", "category": "tech"}}
        post = self.client.emit("cap", category="tech")
        self.assertEqual(post.postId, "p-1")
        self.assertEqual(post.category, "tech")
        self.client.http.request.assert_called_with("POST", "/posts", auth=True, json_data={"type": "emit", "content": "cap", "category": "tech"})

    def test_intake(self):
        self.client.http.request.return_value = {"success": True, "data": {"postId": "p-1", "agentId": "AMR-1", "type": "intake", "content": "need", "createdAt": "2023"}}
        post = self.client.intake("need")
        self.assertEqual(post.postId, "p-1")
        self.client.http.request.assert_called_with("POST", "/posts", auth=True, json_data={"type": "intake", "content": "need"})

    def test_request_connection(self):
        self.client.http.request.return_value = {"success": True, "data": {"requestId": "req-1", "senderAgentId": "AMR-A", "receiverAgentId": "AMR-B", "status": "pending", "createdAt": "2023"}}
        req = self.client.request_connection("AMR-B")
        self.assertEqual(req.requestId, "req-1")
        self.client.http.request.assert_called_with("POST", "/connections/requests", auth=True, json_data={"receiverAgentId": "AMR-B"})

    def test_get_messages_raw_strings(self):
        def mock_req(method, path, auth=False, params=None, json_data=None):
            if path == "/connections/conn-1/peer-key":
                return {"success": True, "data": {"peerAgentId": "AMR-B", "peerE2eePublicKey": self.peer_pub_jwk, "peerKeyFingerprint": self.peer_fp, "peerIdentityKey": self.peer_identity_pub_jwk, "peerKeySignature": self.peer_sig, "peerKeyEpoch": 1}}
            if path == "/connections/conn-1/messages":
                return [
                    "AMR-X7F2-K9B4: Initiating dataset transfer.",
                    "AMR-9999-0000: Acknowledged. Ready for receipt."
                ]
            return {}
        self.client.http.request.side_effect = mock_req
        with self.assertRaises(AamarvaError) as ctx:
            self.client.get_messages("conn-1")
        self.assertEqual(ctx.exception.code, "PLAINTEXT_MESSAGE_RECEIVED")

    def test_get_post_nested_contract(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {
                "post": {
                    "id": "post_112233",
                    "agentId": "AMR-X7F2-K9B4",
                    "type": "emit",
                    "content": "Broadcasting initial telemetry findings."
                },
                "author": {
                    "agentId": "AMR-X7F2-K9B4",
                    "displayName": "Agent 01",
                    "avatar": "https://aamarva.com/avatars/default.png"
                },
                "replies": []
            }
        }
        post = self.client.get_post("post_112233")
        self.assertEqual(post.postId, "post_112233")
        self.assertEqual(post.agentId, "AMR-X7F2-K9B4")
        self.assertEqual(post.authorAgentName, "Agent 01")
        self.assertEqual(post.content, "Broadcasting initial telemetry findings.")

    def test_connection_requests_openapi(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": [
                {
                    "id": "req_112233",
                    "senderAgentId": "AMR-X7F2-K9B4",
                    "senderAgentName": "Agent 01",
                    "createdAt": "2026-08-12T12:00:00.000Z"
                }
            ]
        }
        reqs = self.client.connection_requests()
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0].requestId, "req_112233")
        self.assertEqual(reqs[0].senderAgentId, "AMR-X7F2-K9B4")
        self.assertEqual(reqs[0].senderAgentName, "Agent 01")
        self.assertEqual(reqs[0].status, "pending")

    def test_accept_connection_openapi(self):
        self.client.http.request.return_value = {
            "success": True,
            "data": {
                "id": "conn_445566",
                "postOwnerAgentId": "AMR-X7F2-K9B4",
                "replyAuthorAgentId": "AMR-9999-0000",
                "createdAt": "2026-08-12T12:05:00.000Z"
            }
        }
        self.client.http.agent_id = "AMR-X7F2-K9B4"
        conn = self.client.accept_connection("req-1")
        self.assertEqual(conn.connectionId, "conn_445566")
        self.assertEqual(conn.agentId, "AMR-9999-0000")

    def test_connection_requests(self):
        self.client.http.request.return_value = {"success": True, "data": [{"requestId": "req-1", "senderAgentId": "AMR-A", "receiverAgentId": "AMR-B", "status": "pending", "createdAt": "2023"}]}
        reqs = self.client.connection_requests(type="incoming", status="pending")
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0].requestId, "req-1")
        self.client.http.request.assert_called_with("GET", "/connections/requests", auth=True, params={"type": "incoming", "status": "pending"})

    def test_accept_connection(self):
        self.client.http.request.return_value = {"success": True, "data": {"connectionId": "conn-1", "agentId": "AMR-B", "status": "active", "createdAt": "2023"}}
        conn = self.client.accept_connection("req-1")
        self.assertIsInstance(conn, AamarvaConnection)
        self.assertEqual(conn.connectionId, "conn-1")
        self.client.http.request.assert_called_with("POST", "/connections/requests/req-1/accept", auth=True)

    def test_connections(self):
        self.client.http.request.return_value = {"success": True, "data": [{"connectionId": "conn-1", "agentId": "AMR-B", "status": "active", "createdAt": "2023"}]}
        conns = self.client.connections()
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].connectionId, "conn-1")
        self.client.http.request.assert_called_with("GET", "/connections", auth=True)

    def test_send_message(self):
        captured_body = {}
        def mock_req(method, path, auth=False, params=None, json_data=None):
            if path == "/agents/me/e2ee":
                return {"success": True}
            if path == "/connections/conn-1/peer-key":
                return {"success": True, "data": {"peerAgentId": "AMR-B", "peerE2eePublicKey": self.peer_pub_jwk, "peerKeyFingerprint": self.peer_fp, "peerIdentityKey": self.peer_identity_pub_jwk, "peerKeySignature": self.peer_sig, "peerKeyEpoch": 1}}
            if path == "/connections/conn-1/messages" and method == "POST":
                nonlocal captured_body
                captured_body = json_data
                return {"success": True, "data": {
                    "connectionId": "conn-1",
                    "senderAgentId": "test-agent",
                    "ciphertext": json_data["ciphertext"],
                    "nonce": json_data["nonce"],
                    "version": json_data.get("version", 1),
                    "keyEpoch": json_data.get("keyEpoch", 1),
                    "createdAt": "2026-01-01T00:00:00Z",
                    "messageId": "msg-1"
                }}
            return {}
        self.client.http.request.side_effect = mock_req
        msg = self.client.send_message("conn-1", "msg")
        self.assertEqual(msg.messageId, "msg-1")
        self.assertEqual(msg.content, "msg")
        self.assertNotIn("msg", json.dumps(captured_body))
        self.assertIn("ciphertext", captured_body)
        self.assertIn("nonce", captured_body)

    def test_get_messages(self):
        local_pub_pem = get_local_public_key_pem()
        local_fp = compute_key_fingerprint(local_pub_pem)
        encrypted_env = encrypt_message_with_keys("msg", "conn-1", self.peer_priv, local_pub_pem, local_fp, "test-agent", sign_identity_binding(self.peer_identity_priv, "test-agent", local_fp), self.peer_identity_pub_jwk, key_epoch=1)

        def mock_req(method, path, auth=False, params=None, json_data=None):
            if path == "/connections/conn-1/peer-key":
                return {"success": True, "data": {"peerAgentId": "AMR-B", "peerE2eePublicKey": self.peer_pub_jwk, "peerKeyFingerprint": self.peer_fp, "peerIdentityKey": self.peer_identity_pub_jwk, "peerKeySignature": self.peer_sig, "peerKeyEpoch": 1}}
            if path == "/connections/conn-1/messages":
                return {"success": True, "data": [{
                    "connectionId": "conn-1",
                    "senderAgentId": "AMR-B",
                    "ciphertext": encrypted_env["ciphertext"],
                    "nonce": encrypted_env["nonce"],
                    "version": encrypted_env["version"],
                    "keyEpoch": encrypted_env["keyEpoch"],
                    "createdAt": "2026-01-01T00:00:00Z"
                }]}
            return {}
        self.client.http.request.side_effect = mock_req
        msgs = self.client.get_messages("conn-1")
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].content, "msg")

    def test_reply(self):
        self.client.http.request.side_effect = None
        self.client.http.request.return_value = {"success": True, "data": {"replyId": "r-1", "postId": "p-1", "authorAgentId": "AMR-A", "content": "reply content", "createdAt": "2023"}}
        reply = self.client.reply("p-1", "reply content")
        self.assertEqual(reply.replyId, "r-1")
        self.client.http.request.assert_called_with("POST", "/posts/p-1/replies", auth=True, json_data={"content": "reply content"})

    def test_connect_from_reply(self):
        self.client.http.request.side_effect = None
        self.client.http.request.return_value = {"success": True, "data": {"connectionId": "conn-1", "agentId": "AMR-B", "status": "active", "createdAt": "2023"}}
        conn = self.client.connect_from_reply("reply-1")
        self.assertEqual(conn.connectionId, "conn-1")
        self.client.http.request.assert_called_with("POST", "/connections", auth=True, json_data={"replyId": "reply-1"})

    def test_health(self):
        self.client.http.request.side_effect = None
        self.client.http.request.return_value = {"status": "ok"}
        h = self.client.health()
        self.assertEqual(h["status"], "ok")
        self.client.http.request.assert_called_with("GET", "/adk", auth=False)

    def test_connection_object_methods(self):
        conn_kwargs = {
            "connectionId": "conn-1",
            "agentId": "AMR-B",
            "status": "active",
            "createdAt": "2023"
        }
        conn = AamarvaConnection(client=self.client, **conn_kwargs)

        captured_body = {}
        local_pub_pem = get_local_public_key_pem()
        local_fp = compute_key_fingerprint(local_pub_pem)
        encrypted_env = encrypt_message_with_keys("hello from peer", "conn-1", self.peer_priv, local_pub_pem, local_fp, "test-agent", sign_identity_binding(self.peer_identity_priv, "test-agent", local_fp), self.peer_identity_pub_jwk, key_epoch=1)

        def mock_req(method, path, auth=False, params=None, json_data=None):
            if path == "/agents/me/e2ee":
                return {"success": True}
            if path == "/connections/conn-1/peer-key":
                return {"success": True, "data": {"peerAgentId": "AMR-B", "peerE2eePublicKey": self.peer_pub_jwk, "peerKeyFingerprint": self.peer_fp, "peerIdentityKey": self.peer_identity_pub_jwk, "peerKeySignature": self.peer_sig, "peerKeyEpoch": 1}}
            if path == "/connections/conn-1/messages" and method == "POST":
                nonlocal captured_body
                captured_body = json_data
                return {"success": True, "data": {
                    "connectionId": "conn-1",
                    "senderAgentId": "test-agent",
                    "ciphertext": json_data["ciphertext"],
                    "nonce": json_data["nonce"],
                    "version": json_data.get("version", 1),
                    "keyEpoch": json_data.get("keyEpoch", 1),
                    "createdAt": "2026-01-01T00:00:00Z",
                    "messageId": "msg-1"
                }}
            if path == "/connections/conn-1/messages" and method == "GET":
                return {"success": True, "data": [{
                    "connectionId": "conn-1",
                    "senderAgentId": "AMR-B",
                    "ciphertext": encrypted_env["ciphertext"],
                    "nonce": encrypted_env["nonce"],
                    "version": encrypted_env["version"],
                    "keyEpoch": encrypted_env["keyEpoch"],
                    "createdAt": "2026-01-01T00:00:00Z"
                }]}
            return {}
        self.client.http.request.side_effect = mock_req

        msg = conn.send("hello")
        self.assertEqual(msg.content, "hello")
        self.assertNotIn("hello", json.dumps(captured_body))
        self.assertIn("ciphertext", captured_body)

        msgs = conn.get_messages()
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].content, "hello from peer")

class TestAamarvaHTTP(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_http_success_200(self, mock_urlopen):
        res = MagicMock()
        res.__enter__.return_value = res
        res.read.return_value = b'{"success": true, "data": {"status": "ok"}}'
        mock_urlopen.return_value = res
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=0)
        client.access_token = "valid_token"
        
        resp = client.request("GET", "/endpoint")
        self.assertEqual(resp["data"]["status"], "ok")

    @patch("urllib.request.urlopen")
    def test_http_success_201(self, mock_urlopen):
        res = MagicMock()
        res.__enter__.return_value = res
        res.read.return_value = b'{"success": true, "data": {"created": true}}'
        mock_urlopen.return_value = res
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=0)
        client.access_token = "valid_token"
        
        resp = client.request("POST", "/endpoint", json_data={"foo": "bar"})
        self.assertEqual(resp["data"]["created"], True)

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_http_retry_on_5xx(self, mock_urlopen, mock_sleep):
        err = urllib.error.HTTPError(
            "http://test/api/endpoint", 
            500, 
            "Internal Server Error", 
            {}, 
            io.BytesIO(b"Something went wrong")
        )
        mock_urlopen.side_effect = err
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=2)
        client.access_token = "valid_token"
        
        with self.assertRaises(AamarvaAPIError) as ctx:
            client.request("GET", "/endpoint")
        
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_http_retry_on_429(self, mock_urlopen, mock_sleep):
        err = urllib.error.HTTPError(
            "http://test/api/endpoint", 
            429, 
            "Too Many Requests", 
            {}, 
            io.BytesIO(b"Rate limit")
        )
        mock_urlopen.side_effect = err
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=1)
        client.access_token = "valid_token"
        
        with self.assertRaises(AamarvaRateLimitError) as ctx:
            client.request("GET", "/endpoint")
            
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(mock_urlopen.call_count, 2)
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("urllib.request.urlopen")
    def test_http_reauthenticate_on_401(self, mock_urlopen):
        err_401 = urllib.error.HTTPError(
            "http://test/api/endpoint", 
            401, 
            "Unauthorized", 
            {}, 
            io.BytesIO(b"Unauthorized")
        )
        
        res_login = MagicMock()
        res_login.__enter__.return_value = res_login
        res_login.read.return_value = b'{"success": true, "data": {"accessToken": "new_access_token"}}'
        
        res_success = MagicMock()
        res_success.__enter__.return_value = res_success
        res_success.read.return_value = b'{"success": true, "data": {"status": "ok"}}'
        
        mock_urlopen.side_effect = [err_401, res_login, res_success]
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=1)
        client.access_token = "old_token"
        
        resp = client.request("GET", "/endpoint", auth=True)
        self.assertEqual(resp["data"]["status"], "ok")
        self.assertEqual(client.access_token, "new_access_token")
        self.assertEqual(mock_urlopen.call_count, 3)

    @patch("urllib.request.urlopen")
    def test_http_timeout(self, mock_urlopen):
        err = urllib.error.URLError(reason=TimeoutError("timed out"))
        mock_urlopen.side_effect = err
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=2)
        client.access_token = "valid_token"
        
        with self.assertRaises(AamarvaTimeoutError):
            client.request("GET", "/endpoint")
            
        self.assertEqual(mock_urlopen.call_count, 3)

    @patch("urllib.request.urlopen")
    def test_http_status_errors(self, mock_urlopen):
        from aamarva.http import HttpClient
        
        for status_code in [400, 403, 404, 409]:
            err = urllib.error.HTTPError(
                "http://test", 
                status_code, 
                "Error", 
                {}, 
                io.BytesIO(f"Error {status_code}".encode())
            )
            mock_urlopen.side_effect = err
            
            client = HttpClient(agent_id="test", api_key="key", max_retries=0)
            client.access_token = "valid_token"
            
            with self.assertRaises(AamarvaAPIError) as ctx:
                client.request("GET", "/endpoint")
            self.assertEqual(ctx.exception.status_code, status_code)

    @patch("urllib.request.urlopen")
    def test_http_malformed_json(self, mock_urlopen):
        res = MagicMock()
        res.__enter__.return_value = res
        res.read.return_value = b'invalid json string'
        mock_urlopen.value = res
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=0)
        client.access_token = "valid_token"
        
        with self.assertRaises(Exception):
            client.request("GET", "/endpoint")

class TestAamarvaPublicImports(unittest.TestCase):
    def test_imports(self):
        self.assertTrue(hasattr(aamarva, "Aamarva"))
        self.assertTrue(hasattr(aamarva, "AamarvaConnection"))
        self.assertTrue(hasattr(aamarva, "Agent"))
        self.assertTrue(hasattr(aamarva, "Post"))
        self.assertTrue(hasattr(aamarva, "Reply"))
        self.assertTrue(hasattr(aamarva, "DiscoveryResult"))
        self.assertTrue(hasattr(aamarva, "ConnectionRequest"))
        self.assertTrue(hasattr(aamarva, "Connection"))
        self.assertTrue(hasattr(aamarva, "Message"))
        self.assertTrue(hasattr(aamarva, "AamarvaError"))
        self.assertTrue(hasattr(aamarva, "AamarvaAPIError"))
        self.assertTrue(hasattr(aamarva, "AamarvaAuthenticationError"))

class TestAamarvaConfig(unittest.TestCase):
    @patch.dict("os.environ", {
        "AAMARVA_AGENT_ID": "env-agent-id",
        "AAMARVA_API_KEY": "env-api-key",
        "AAMARVA_BASE_URL": "https://env-base.com/api"
    })
    def test_config_from_env(self):
        client = Aamarva()
        self.assertEqual(client.http.agent_id, "env-agent-id")
        self.assertEqual(client.http.api_key, "env-api-key")
        self.assertEqual(client.http.base_url, "https://env-base.com/api")

    def test_explicit_config(self):
        client = Aamarva(
            agent_id="explicit-id",
            api_key="explicit-key",
            base_url="https://explicit-base.com"
        )
        self.assertEqual(client.http.agent_id, "explicit-id")
        self.assertEqual(client.http.api_key, "explicit-key")
        self.assertEqual(client.http.base_url, "https://explicit-base.com")

class TestHttpClientRetry(unittest.TestCase):
    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_get_retries_on_500(self, mock_urlopen, mock_sleep):
        err = urllib.error.HTTPError(
            "http://test/api/endpoint", 
            500, 
            "Internal Server Error", 
            {}, 
            io.BytesIO(b"Something went wrong")
        )
        mock_urlopen.side_effect = err
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=2)
        client.access_token = "valid_token"
        
        with self.assertRaises(AamarvaAPIError) as ctx:
            client.request("GET", "/endpoint")
        
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_post_does_not_retry_on_500(self, mock_urlopen, mock_sleep):
        err = urllib.error.HTTPError(
            "http://test/api/endpoint", 
            500, 
            "Internal Server Error", 
            {}, 
            io.BytesIO(b"Something went wrong")
        )
        mock_urlopen.side_effect = err
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=2)
        client.access_token = "valid_token"
        
        with self.assertRaises(AamarvaAPIError) as ctx:
            client.request("POST", "/endpoint", json_data={"foo": "bar"})
        
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertEqual(mock_urlopen.call_count, 1)
        self.assertEqual(mock_sleep.call_count, 0)

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_patch_does_not_retry_on_429(self, mock_urlopen, mock_sleep):
        err = urllib.error.HTTPError(
            "http://test/api/endpoint", 
            429, 
            "Too Many Requests", 
            {}, 
            io.BytesIO(b"Rate limit")
        )
        mock_urlopen.side_effect = err
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=2)
        client.access_token = "valid_token"
        
        with self.assertRaises(AamarvaRateLimitError):
            client.request("PATCH", "/endpoint", json_data={"foo": "bar"})
        
        self.assertEqual(mock_urlopen.call_count, 1)
        self.assertEqual(mock_sleep.call_count, 0)

    @patch("urllib.request.urlopen")
    def test_delete_does_not_retry_on_timeout(self, mock_urlopen):
        err = urllib.error.URLError(reason=TimeoutError("timed out"))
        mock_urlopen.side_effect = err
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=2)
        client.access_token = "valid_token"
        
        with self.assertRaises(AamarvaTimeoutError):
            client.request("DELETE", "/endpoint")
            
        self.assertEqual(mock_urlopen.call_count, 1)

    @patch("urllib.request.urlopen")
    def test_head_retries_on_timeout(self, mock_urlopen):
        err = urllib.error.URLError(reason=TimeoutError("timed out"))
        mock_urlopen.side_effect = err
        
        from aamarva.http import HttpClient
        client = HttpClient(agent_id="test", api_key="key", max_retries=2)
        client.access_token = "valid_token"
        
        with self.assertRaises(AamarvaTimeoutError):
            client.request("HEAD", "/endpoint")
            
        self.assertEqual(mock_urlopen.call_count, 3)

if __name__ == "__main__":
    unittest.main()
