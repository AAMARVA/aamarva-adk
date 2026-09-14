import os
import json
import base64
import tempfile
import unittest
from unittest.mock import MagicMock
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization

from aamarva import Aamarva, AamarvaConnection
from aamarva.crypto import (
    export_public_key_jwk,
    sign_identity_binding,
    KeyStore,
    InMemoryKeyStore,
    FileSystemKeyStore,
    set_key_store,
    get_key_store,
    reset_local_identity_key,
    get_local_identity_key,
    get_local_public_key_pem,
    compute_key_fingerprint,
    verify_peer_key,
    encrypt_message_with_keys,
    decrypt_message_with_keys,
    export_public_key_jwk,
    sign_identity_binding,
    create_identity_binding_string,
    verify_identity_binding,
)
from aamarva.normalize import normalize_message
from aamarva.errors import AamarvaError


class TestCryptoSecurityHardening(unittest.TestCase):
    def setUp(self):
        reset_local_identity_key()
        self.alice_priv = ec.generate_private_key(ec.SECP256R1())
        self.alice_pub_pem = self.alice_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.alice_fp = compute_key_fingerprint(self.alice_priv.public_key())
        self.alice_identity_pub_jwk = export_public_key_jwk(self.alice_priv.public_key())
        self.alice_identity_priv = ec.generate_private_key(ec.SECP256R1())
        self.alice_identity_pub_jwk = export_public_key_jwk(self.alice_identity_priv.public_key())
        self.alice_sig = sign_identity_binding(self.alice_identity_priv, "AMR-ALICE", self.alice_fp)

        self.bob_priv = ec.generate_private_key(ec.SECP256R1())
        self.bob_pub_pem = self.bob_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.bob_fp = compute_key_fingerprint(self.bob_priv.public_key())
        self.bob_identity_pub_jwk = export_public_key_jwk(self.bob_priv.public_key())
        self.bob_identity_priv = ec.generate_private_key(ec.SECP256R1())
        self.bob_identity_pub_jwk = export_public_key_jwk(self.bob_identity_priv.public_key())
        self.bob_sig = sign_identity_binding(self.bob_identity_priv, "AMR-BOB", self.bob_fp)



    def test_deterministic_fingerprint_vector(self):
        deterministic_jwk = {
            "crv": "P-256",
            "kty": "EC",
            "x": "jLYmaATt9D2gC2__7gx69gTccElDh3sT3WoKxzeeQN4",
            "y": "L4iSoXO7btNvGCd0dPDKOXIWO6JgiVTUWTz7YCppkdI"
        }
        expected_fp = "SHA256:D6:7D:AF:63:1E:5F:B3:6A:1A:56:FA:A2:54:1D:CA:83:4A:8E:BA:A9:7B:14:3C:2D:45:FD:CF:99:38:E6:E6:7A"
        actual_fp = compute_key_fingerprint(deterministic_jwk)
        
        self.assertEqual(actual_fp, expected_fp, "Deterministic canonical JWK fingerprint did not match expected hardcoded vector.")
        self.assertTrue(actual_fp.startswith("SHA256:"), "Fingerprint must start with SHA256:")
        self.assertEqual(len(actual_fp.split(":")), 33, "Fingerprint must have exactly 32 hex bytes separated by colons plus the SHA256 prefix")
        import string
        hex_part = actual_fp[7:].replace(":", "")
        self.assertTrue(all(c in string.hexdigits.upper() for c in hex_part), "Fingerprint must use uppercase hex")

    def test_agent_id_canonicalization(self):
        fp = "SHA256:D6:7D:AF:63:1E:5F:B3:6A:1A:56:FA:A2:54:1D:CA:83:4A:8E:BA:A9:7B:14:3C:2D:45:FD:CF:99:38:E6:E6:7A"
        binding_upper = create_identity_binding_string("AMR-BETA-77", fp)
        binding_lower = create_identity_binding_string("  amr-beta-77  ", fp)
        binding_mixed = create_identity_binding_string("AmR-bEtA-77", fp)
        expected = f"AAMARVA-KEY-BINDING:v1:AMR-BETA-77:{fp}"
        self.assertEqual(binding_upper, expected)
        self.assertEqual(binding_lower, expected)
        self.assertEqual(binding_mixed, expected)

    def test_roundtrip_encryption_decryption(self):
        conn_id = "conn-py-01"
        plaintext = "Hello from Python E2EE test!"
        envelope = encrypt_message_with_keys("Hello from Python E2EE test!", "conn_44", self.alice_priv, self.bob_pub_pem, self.bob_fp, "AMR-BOB", self.bob_sig, self.bob_identity_pub_jwk, key_epoch=2)
        self.assertEqual(envelope["version"], 1)
        self.assertEqual(envelope["keyEpoch"], 2)
        self.assertTrue(isinstance(envelope["ciphertext"], str))
        self.assertTrue(isinstance(envelope["nonce"], str))

        decrypted = decrypt_message_with_keys(envelope, "conn_44", self.bob_priv, self.alice_pub_pem, self.alice_fp, "AMR-ALICE", self.alice_sig, self.alice_identity_pub_jwk)
        self.assertEqual(decrypted, plaintext)

    def test_tampered_ciphertext_fails(self):
        conn_id = "conn-py-01"
        envelope = encrypt_message_with_keys("Hello from Python E2EE test!", "conn_44", self.alice_priv, self.bob_pub_pem, self.bob_fp, "AMR-BOB", self.bob_sig, self.bob_identity_pub_jwk, key_epoch=2)
        raw_ct = bytearray(base64.b64decode(envelope["ciphertext"]))
        raw_ct[0] ^= 0xff
        tampered_env = dict(envelope)
        tampered_env["ciphertext"] = base64.b64encode(raw_ct).decode('utf-8')

        with self.assertRaises(AamarvaError) as ctx:
            decrypt_message_with_keys(tampered_env, "conn_44", self.bob_priv, self.alice_pub_pem, self.alice_fp, "AMR-ALICE", self.alice_sig, self.alice_identity_pub_jwk)
        self.assertEqual(ctx.exception.code, "MESSAGE_DECRYPTION_FAILED")

    def test_tampered_nonce_fails(self):
        conn_id = "conn-py-01"
        envelope = encrypt_message_with_keys("Hello from Python E2EE test!", "conn_44", self.alice_priv, self.bob_pub_pem, self.bob_fp, "AMR-BOB", self.bob_sig, self.bob_identity_pub_jwk, key_epoch=2)
        raw_nonce = bytearray(base64.b64decode(envelope["nonce"]))
        raw_nonce[0] ^= 0xff
        tampered_env = dict(envelope)
        tampered_env["nonce"] = base64.b64encode(raw_nonce).decode('utf-8')

        with self.assertRaises(AamarvaError) as ctx:
            decrypt_message_with_keys(tampered_env, "conn_44", self.bob_priv, self.alice_pub_pem, self.alice_fp, "AMR-ALICE", self.alice_sig, self.alice_identity_pub_jwk)
        self.assertEqual(ctx.exception.code, "MESSAGE_DECRYPTION_FAILED")

    def test_wrong_private_key_fails(self):
        conn_id = "conn-py-01"
        envelope = encrypt_message_with_keys("Hello from Python E2EE test!", "conn_44", self.alice_priv, self.bob_pub_pem, self.bob_fp, "AMR-BOB", self.bob_sig, self.bob_identity_pub_jwk, key_epoch=2)
        eve_priv = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_message_with_keys(envelope, "conn_44", eve_priv, self.alice_pub_pem, self.alice_fp, "AMR-ALICE", self.alice_sig, self.alice_identity_pub_jwk)
        self.assertEqual(ctx.exception.code, "MESSAGE_DECRYPTION_FAILED")

    def test_wrong_peer_key_fails(self):
        conn_id = "conn-py-01"
        envelope = encrypt_message_with_keys("Hello from Python E2EE test!", "conn_44", self.alice_priv, self.bob_pub_pem, self.bob_fp, "AMR-BOB", self.bob_sig, self.bob_identity_pub_jwk, key_epoch=2)
        charlie_priv = ec.generate_private_key(ec.SECP256R1())
        charlie_pub_pem = charlie_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        charlie_fp = compute_key_fingerprint(charlie_pub_pem)

        with self.assertRaises(AamarvaError) as ctx:
            decrypt_message_with_keys(envelope, "conn_44", self.bob_priv, charlie_pub_pem, charlie_fp, "AMR-CHARLIE", sign_identity_binding(charlie_priv, "AMR-CHARLIE", charlie_fp), export_public_key_jwk(charlie_priv.public_key()))
        self.assertEqual(ctx.exception.code, "MESSAGE_DECRYPTION_FAILED")

    def test_wrong_connection_id_aad_fails(self):
        conn_id = "conn-py-01"
        envelope = encrypt_message_with_keys("Hello from Python E2EE test!", "conn_44", self.alice_priv, self.bob_pub_pem, self.bob_fp, "AMR-BOB", self.bob_sig, self.bob_identity_pub_jwk, key_epoch=2)
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_message_with_keys(envelope, "wrong_conn", self.bob_priv, self.alice_pub_pem, self.alice_fp, "AMR-ALICE", self.alice_sig, self.alice_identity_pub_jwk)
        self.assertEqual(ctx.exception.code, "MESSAGE_DECRYPTION_FAILED")

    def test_malformed_envelope_fails(self):
        conn_id = "conn-py-01"
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_message_with_keys({"ciphertext": ""}, conn_id, self.bob_priv, self.alice_pub_pem, self.alice_fp, "AMR-ALICE", self.alice_sig, self.alice_identity_pub_jwk)
        self.assertEqual(ctx.exception.code, "MESSAGE_INVALID_ENVELOPE")

        short_ct = base64.b64encode(b"short").decode('utf-8')
        valid_nonce = base64.b64encode(os.urandom(12)).decode('utf-8')
        with self.assertRaises(AamarvaError) as ctx:
            decrypt_message_with_keys({"ciphertext": short_ct, "nonce": valid_nonce}, conn_id, self.bob_priv, self.alice_pub_pem, self.alice_fp, "AMR-ALICE", self.alice_sig, self.alice_identity_pub_jwk)
        self.assertEqual(ctx.exception.code, "MESSAGE_INVALID_ENVELOPE")

    def test_invalid_peer_fingerprint_fails(self):
        with self.assertRaises(AamarvaError) as ctx:
            verify_peer_key(self.bob_pub_pem, "0000000000000000000000000000000000000000000000000000000000000000", "AMR-BOB", self.bob_sig, self.bob_identity_pub_jwk)
        self.assertEqual(ctx.exception.code, "PEER_KEY_VERIFICATION_FAILED")

        with self.assertRaises(AamarvaError) as ctx:
            verify_peer_key("", "", "", "", "")
        self.assertEqual(ctx.exception.code, "PEER_KEY_UNAVAILABLE")

    def test_non_p256_curve_rejected(self):
        ed_key = ed25519.Ed25519PrivateKey.generate()
        ed_pub_pem = ed_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        with self.assertRaises(AamarvaError) as ctx:
            verify_peer_key(ed_pub_pem, self.bob_fp, "AMR-BOB", self.bob_sig, self.bob_identity_pub_jwk)
        self.assertEqual(ctx.exception.code, "PEER_KEY_VERIFICATION_FAILED")

    def test_keystore_implementations(self):
        mem_store = InMemoryKeyStore()
        self.assertIsNone(mem_store.load_private_key("k1"))
        mem_store.save_private_key("PEM_1", "k1")
        self.assertEqual(mem_store.load_private_key("k1"), "PEM_1")

        with tempfile.TemporaryDirectory() as tmp_dir:
            fs_store = FileSystemKeyStore(tmp_dir)
            self.assertIsNone(fs_store.load_private_key("k2"))
            fs_store.save_private_key("PEM_2", "k2")
            self.assertEqual(fs_store.load_private_key("k2"), "PEM_2")
            key_file = os.path.join(tmp_dir, "k2.pem")
            self.assertTrue(os.path.exists(key_file))
            if os.name == 'posix':
                mode = os.stat(key_file).st_mode & 0o777
                self.assertEqual(mode, 0o600)

    def test_strict_message_normalization(self):
        with self.assertRaises(AamarvaError) as ctx:
            normalize_message("Plaintext transcript string", "conn-1")
        self.assertEqual(ctx.exception.code, "PLAINTEXT_MESSAGE_RECEIVED")

        with self.assertRaises(AamarvaError) as ctx:
            normalize_message({"connectionId": "conn-1", "content": "unencrypted content"}, "conn-1")
        self.assertEqual(ctx.exception.code, "PLAINTEXT_MESSAGE_RECEIVED")

        with self.assertRaises(AamarvaError) as ctx:
            normalize_message({"connectionId": "conn-1", "ciphertext": "abc"}, "conn-1")
        self.assertEqual(ctx.exception.code, "MESSAGE_INVALID_ENVELOPE")

    def test_plaintext_leak_prevention(self):
        client = Aamarva(agent_id="test-agent", api_key="test-key")
        captured_body = {}

        def mock_req(method, path, auth=False, params=None, json_data=None):
            if path == "/agents/me/e2ee":
                return {"success": True}
            if path == "/connections/conn-leak/peer-key":
                return {"success": True, "data": {"peerAgentId": "AMR-BOB", "peerE2eePublicKey": export_public_key_jwk(self.bob_priv.public_key()), "peerKeyFingerprint": self.bob_fp, "peerIdentityKey": self.bob_identity_pub_jwk, "peerKeySignature": self.bob_sig, "peerKeyEpoch": 1}}
            if path == "/connections/conn-leak/messages" and method == "POST":
                nonlocal captured_body
                captured_body = json_data
                return {"success": True, "data": {
                    "connectionId": "conn-leak",
                    "senderAgentId": "test-agent",
                    "ciphertext": json_data["ciphertext"],
                    "nonce": json_data["nonce"],
                    "version": json_data.get("version", 1),
                    "keyEpoch": json_data.get("keyEpoch", 1),
                    "createdAt": "2026-01-01T00:00:00Z",
                    "messageId": "msg-leak-1"
                }}
            return {}
        client.http.request = MagicMock(side_effect=mock_req)

        sensitive_text = "ULTRA_SENSITIVE_PYTHON_PAYLOAD_998877"
        msg = client.send_message("conn-leak", sensitive_text, "AMR-BOB")
        self.assertEqual(msg.content, sensitive_text)

        # Assert no plaintext in captured POST body
        body_str = json.dumps(captured_body)
        self.assertNotIn(sensitive_text, body_str)
        self.assertIn("ciphertext", captured_body)
        self.assertIn("nonce", captured_body)
        self.assertEqual(captured_body["version"], 1)
        self.assertEqual(captured_body["keyEpoch"], 1)
        self.assertNotIn("content", captured_body)
        self.assertNotIn("message", captured_body)

        # Connection.send() leak test
        captured_body = {}
        conn = AamarvaConnection(client=client, connectionId="conn-leak", agentId="AMR-BOB", status="active", createdAt="2026-01-01T00:00:00Z")
        conn_secret = "SECOND_SECRET_VIA_CONN_SEND_332211"
        conn.send(conn_secret)
        self.assertNotIn(conn_secret, json.dumps(captured_body))
        self.assertIn("ciphertext", captured_body)


if __name__ == "__main__":
    unittest.main()
