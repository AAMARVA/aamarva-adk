import base64
import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from aamarva.client import Aamarva
from aamarva.crypto import (
    GATEWAY_ENVELOPE_ALGORITHM,
    GATEWAY_ENVELOPE_PLAINTEXT_VERSION,
    GATEWAY_ENVELOPE_VERSION,
    GATEWAY_HKDF_INFO_PREFIX,
    build_gateway_token_envelope_hkdf_info,
    create_gateway_token_envelope_aad,
    decrypt_gateway_token_envelope,
    derive_gateway_envelope_key,
    get_key_store,
    reset_local_identity_key,
)
from aamarva.errors import AamarvaError
from aamarva.mcp_executor import execute_gateway_mcp_tool, normalize_gateway_mcp_url


FIXTURE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../tests/fixtures/gateway-token-envelope.v1.json")
)
with open(FIXTURE_PATH, "r", encoding="utf-8") as fh:
    GATEWAY_FIXTURE = json.load(fh)


class TestGatewayTokenEnvelope(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(GATEWAY_ENVELOPE_VERSION, "AAMARVA-GW-ENV-V1")
        self.assertEqual(GATEWAY_ENVELOPE_PLAINTEXT_VERSION, 1)
        self.assertEqual(GATEWAY_ENVELOPE_ALGORITHM, "P256-HKDF-SHA256-AES-256-GCM")
        self.assertEqual(GATEWAY_HKDF_INFO_PREFIX, "aamarva-mcp-gateway:token-envelope:v1")

    def test_decrypt_gateway_fixture_hkdf_and_aad_cases_2_14_15(self):
        active_env = copy.deepcopy(GATEWAY_FIXTURE["active"]["envelope"])
        hkdf_info = build_gateway_token_envelope_hkdf_info(active_env["agentId"], active_env["tokenId"])
        self.assertEqual(hkdf_info, GATEWAY_FIXTURE["active"]["hkdfInfo"])

        aad_str = create_gateway_token_envelope_aad(active_env)
        self.assertEqual(aad_str, GATEWAY_FIXTURE["active"]["aadString"])
        self.assertFalse(aad_str.startswith("aamarva-mcp-gateway:"))

        derived_key = derive_gateway_envelope_key(
            GATEWAY_FIXTURE["recipientPrivateKeyPem"],
            active_env["ephemeralPublicKeyPem"],
            active_env["saltBase64"],
            active_env["agentId"],
            active_env["tokenId"],
        )
        self.assertEqual(derived_key.hex(), GATEWAY_FIXTURE["active"]["expectedDerivedKeyHex"])

        before_snapshot = json.dumps(active_env, sort_keys=True)
        plaintext = decrypt_gateway_token_envelope(
            active_env,
            GATEWAY_FIXTURE["recipientPrivateKeyPem"],
            expected_agent_id=active_env["agentId"],
            expected_account_id=active_env["accountId"],
            expected_token_id=active_env["tokenId"],
            expected_gateway_id=active_env["gatewayId"],
            expected_mcp_server_id=active_env["mcpServerId"],
            tool_name="sec_edgar_search",
        )
        # Input envelope must not be mutated
        self.assertEqual(json.dumps(active_env, sort_keys=True), before_snapshot)
        self.assertEqual(plaintext, GATEWAY_FIXTURE["active"]["expectedPlaintext"])

    def test_reject_version_mismatch_case_3(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        for bad_version in (1, "1", "AAMARVA-GW-ENV-V2", ""):
            tampered = {**active_env, "version": bad_version}
            with self.assertRaises(AamarvaError) as ctx:
                decrypt_gateway_token_envelope(
                    tampered,
                    GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                    expected_agent_id=active_env["agentId"],
                    expected_account_id=active_env["accountId"],
                )
            self.assertEqual(ctx.exception.code, "GATEWAY_ENVELOPE_INVALID")

    def test_reject_algorithm_mismatch_case_4(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        for bad_alg in ("ECDH-P256-HKDF-SHA256-AES-256-GCM", "AES-256-GCM", ""):
            tampered = {**active_env, "algorithm": bad_alg}
            with self.assertRaises(AamarvaError) as ctx:
                decrypt_gateway_token_envelope(
                    tampered,
                    GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                    expected_agent_id=active_env["agentId"],
                    expected_account_id=active_env["accountId"],
                )
            self.assertEqual(ctx.exception.code, "GATEWAY_ENVELOPE_INVALID")

    def test_reject_wrong_private_key_case_5(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_gateway_token_envelope(
                active_env,
                GATEWAY_FIXTURE["wrongPrivateKeyPem"],
                expected_agent_id=active_env["agentId"],
                expected_account_id=active_env["accountId"],
            )
        self.assertEqual(ctx.exception.code, "GATEWAY_ENVELOPE_DECRYPTION_FAILED")

    def test_reject_wrong_agent_id_case_6(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_gateway_token_envelope(
                active_env,
                GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                expected_agent_id="AMR-OTHER-AGENT",
                expected_account_id=active_env["accountId"],
            )
        self.assertEqual(ctx.exception.code, "GATEWAY_AGENT_MISMATCH")

    def test_reject_wrong_account_id_case_7(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_gateway_token_envelope(
                active_env,
                GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                expected_agent_id=active_env["agentId"],
                expected_account_id="acc_wrong_owner",
            )
        self.assertEqual(ctx.exception.code, "GATEWAY_ACCOUNT_MISMATCH")

    def test_reject_wrong_token_id_case_8(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_gateway_token_envelope(
                active_env,
                GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                expected_agent_id=active_env["agentId"],
                expected_account_id=active_env["accountId"],
                expected_token_id="gw_tok_wrong_999",
            )
        self.assertEqual(ctx.exception.code, "GATEWAY_TOKEN_ID_MISMATCH")

    def test_reject_modified_aad_metadata_case_9(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        for field, bad_val in [
            ("gatewayId", "gw_tampered_02"),
            ("mcpServerId", "srv_tampered_02"),
            ("expiresAt", "2036-01-01T00:00:00.000Z"),
            ("tokenId", "gw_tok_tampered_999"),
        ]:
            tampered = {**active_env, field: bad_val}
            with self.assertRaises(AamarvaError) as ctx:
                decrypt_gateway_token_envelope(
                    tampered,
                    GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                    expected_agent_id=active_env["agentId"],
                    expected_account_id=active_env["accountId"],
                )
            self.assertEqual(ctx.exception.code, "GATEWAY_ENVELOPE_DECRYPTION_FAILED")

    def test_reject_modified_ciphertext_and_tag_cases_10_11(self):
        active_env = copy.deepcopy(GATEWAY_FIXTURE["active"]["envelope"])
        ct = bytearray(base64.b64decode(active_env["ciphertextBase64"]))
        ct[0] ^= 0xFF
        tampered_ct = {**active_env, "ciphertextBase64": base64.b64encode(bytes(ct)).decode("ascii")}
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_gateway_token_envelope(
                tampered_ct,
                GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                expected_agent_id=active_env["agentId"],
                expected_account_id=active_env["accountId"],
            )
        self.assertEqual(ctx.exception.code, "GATEWAY_ENVELOPE_DECRYPTION_FAILED")

        tag = bytearray(base64.b64decode(active_env["authTagBase64"]))
        tag[0] ^= 0xFF
        tampered_tag = {**active_env, "authTagBase64": base64.b64encode(bytes(tag)).decode("ascii")}
        with self.assertRaises(AamarvaError) as ctx2:
            decrypt_gateway_token_envelope(
                tampered_tag,
                GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                expected_agent_id=active_env["agentId"],
                expected_account_id=active_env["accountId"],
            )
        self.assertEqual(ctx2.exception.code, "GATEWAY_ENVELOPE_DECRYPTION_FAILED")

    def test_reject_expired_tokens_case_12(self):
        expired_env = GATEWAY_FIXTURE["expired"]["envelope"]
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_gateway_token_envelope(
                expired_env,
                GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                expected_agent_id=expired_env["agentId"],
                expected_account_id=expired_env["accountId"],
            )
        self.assertEqual(ctx.exception.code, "GATEWAY_TOKEN_EXPIRED")

    def test_reject_unauthorized_tool_case_13(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_gateway_token_envelope(
                active_env,
                GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                expected_agent_id=active_env["agentId"],
                expected_account_id=active_env["accountId"],
                tool_name="exec_shell_command",
            )
        self.assertEqual(ctx.exception.code, "GATEWAY_TOOL_UNAUTHORIZED")

    def test_reject_missing_outer_fields_before_decryption(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        for field, bad_val in [
            ("ephemeralPublicKeyPem", ""),
            ("saltBase64", "AAAA"),
            ("ivBase64", "AAAA"),
            ("authTagBase64", "AAAA"),
            ("ciphertextBase64", ""),
        ]:
            tampered = {**active_env, field: bad_val}
            with self.assertRaises(AamarvaError) as ctx:
                decrypt_gateway_token_envelope(
                    tampered,
                    GATEWAY_FIXTURE["recipientPrivateKeyPem"],
                    expected_agent_id=active_env["agentId"],
                    expected_account_id=active_env["accountId"],
                )
            self.assertEqual(ctx.exception.code, "GATEWAY_ENVELOPE_INVALID")

    def test_normalize_gateway_url(self):
        self.assertEqual(normalize_gateway_mcp_url("https://gw.aamarva.com/v1"), "https://gw.aamarva.com/v1/mcp")
        self.assertEqual(normalize_gateway_mcp_url("https://gw.aamarva.com/mcp/"), "https://gw.aamarva.com/mcp")
        self.assertEqual(normalize_gateway_mcp_url("http://127.0.0.1:8787"), "http://127.0.0.1:8787/mcp")
        with self.assertRaises(AamarvaError):
            normalize_gateway_mcp_url("http://remote.example.com/mcp")

    def test_execute_gateway_mcp_tool_and_client_relay(self):
        active_env = GATEWAY_FIXTURE["active"]["envelope"]
        reset_local_identity_key()
        get_key_store().save_private_key(GATEWAY_FIXTURE["recipientPrivateKeyPem"], "AMR-GW-ALPHA-01")

        gateway_calls = []

        def fake_transport(url, headers, body_bytes, timeout_sec):
            body = json.loads(body_bytes.decode("utf-8"))
            gateway_calls.append({"url": url, "headers": headers, "body": body})
            return {
                "status": 200,
                "content_type": "text/event-stream",
                "body": f'event: message\ndata: {json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {"filings": ["10-K"]}})}\n\n',
            }

        with self.assertRaises(AamarvaError) as ctx:
            execute_gateway_mcp_tool(
                gateway_url="https://gw.aamarva.com",
                token_envelope=active_env,
                tool_name="unauthorized_tool",
                arguments={"ticker": "AAPL"},
                expected_agent_id="AMR-GW-ALPHA-01",
                expected_account_id="acc_fleet_owner_9001",
                transport_fn=fake_transport,
            )
        self.assertEqual(ctx.exception.code, "GATEWAY_TOOL_UNAUTHORIZED")
        self.assertEqual(len(gateway_calls), 0)

        res = execute_gateway_mcp_tool(
            gateway_url="https://gw.aamarva.com",
            token_envelope=active_env,
            tool_name="sec_edgar_search",
            arguments={"ticker": "AAPL"},
            expected_agent_id="AMR-GW-ALPHA-01",
            expected_account_id="acc_fleet_owner_9001",
            transport_fn=fake_transport,
        )
        self.assertEqual(len(gateway_calls), 1)
        self.assertEqual(gateway_calls[0]["url"], "https://gw.aamarva.com/mcp")
        self.assertEqual(
            gateway_calls[0]["headers"]["Authorization"],
            f'Bearer {GATEWAY_FIXTURE["active"]["expectedPlaintext"]["token"]}',
        )
        self.assertEqual(gateway_calls[0]["body"]["method"], "tools/call")
        self.assertEqual(res["result"], {"filings": ["10-K"]})

        client = Aamarva(
            agent_id="AMR-GW-ALPHA-01",
            account_id="acc_fleet_owner_9001",
            api_key="sk_test",
        )
        plain = client.decrypt_gateway_token_envelope(active_env, tool_name="sec_edgar_filing")
        self.assertEqual(plain["token"], GATEWAY_FIXTURE["active"]["expectedPlaintext"]["token"])

        def fake_core_request(method, path, auth=False, json_data=None, params=None, headers=None):
            if method == "GET" and path == "/floor/agent/tools":
                return {
                    "success": True,
                    "data": [{"id": "tool_sec_edgar", "name": "sec_edgar_search", "accessStatus": "authorized"}],
                }
            if method == "POST" and path == "/floor/tools/tool_sec_edgar/invoke":
                return {
                    "success": True,
                    "status": "approved",
                    "data": {
                        "invocationId": "inv_py_gw_1",
                        "toolId": "tool_sec_edgar",
                        "status": "approved",
                    },
                }
            if method == "POST" and path == "/floor/invocations/inv_py_gw_1/execute":
                return {
                    "success": True,
                    "data": {
                        "status": "approved",
                        "invocationId": "inv_py_gw_1",
                        "toolId": "tool_sec_edgar",
                        "tool": {"id": "tool_sec_edgar", "name": "sec_edgar_search"},
                        "agentId": "AMR-GW-ALPHA-01",
                        "accountId": "acc_fleet_owner_9001",
                        "approvedArguments": {"ticker": "MSFT"},
                        "grant": {
                            "grantId": "grant_py_1",
                            "status": "active",
                            "toolId": "tool_sec_edgar",
                            "agentId": "AMR-GW-ALPHA-01",
                            "scope": "read:sec_edgar",
                            "expiresAt": "2035-01-01T00:00:00.000Z",
                        },
                        "gatewayUrl": "https://gw.aamarva.com",
                        "gatewayId": "gw_prod_us_east_01",
                        "mcpServerId": "srv_sec_edgar_01",
                        "tokenEnvelope": active_env,
                    },
                }
            raise AssertionError(f"Unexpected Core HTTP call: {method} {path}")

        client.http.request = fake_core_request  # type: ignore
        orig_exec = client.execute_gateway_mcp_tool
        gateway_calls.clear()
        client.execute_gateway_mcp_tool = lambda **kw: orig_exec(**{**kw, "transport_fn": fake_transport})  # type: ignore
        floor_res = client.execute_floor_tool("tool_sec_edgar", {"ticker": "MSFT"})
        self.assertEqual(floor_res.status, "executed")
        self.assertEqual(floor_res.invocationId, "inv_py_gw_1")
        self.assertEqual(floor_res.result, {"filings": ["10-K"]})
        self.assertEqual(len(gateway_calls), 1)
        self.assertEqual(
            gateway_calls[0]["headers"]["Authorization"],
            f'Bearer {GATEWAY_FIXTURE["active"]["expectedPlaintext"]["token"]}',
        )
        self.assertEqual(gateway_calls[0]["body"]["params"]["arguments"], {"ticker": "MSFT"})


if __name__ == "__main__":
    unittest.main()
