import os
import json
import base64
import tempfile
import unittest
from unittest.mock import MagicMock

try:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    try:
        from aamarva._openssl_backend import ec, serialization
        ed25519 = None
        HAS_CRYPTOGRAPHY = True
    except ImportError:
        ec = None
        ed25519 = None
        serialization = None
        HAS_CRYPTOGRAPHY = False

from aamarva import Aamarva, AamarvaConnection
from aamarva.crypto import (
    WORKFLOW_HKDF_SALT,
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
    normalize_agent_id,
    canonical_member_set,
    compute_key_fingerprint,
    compute_group_key_fingerprint,
    compute_roster_hash,
    compute_audience_hash,
    verify_peer_key,
    create_direct_message_aad_v1,
    encrypt_message_with_keys,
    decrypt_message_with_keys,
    create_identity_binding_string,
    verify_identity_binding,
    generate_cluster_key,
    create_cluster_wrap_aad_v2,
    create_cluster_message_aad_v2,
    create_cluster_signing_payload_v2,
    sign_cluster_message_v2,
    verify_cluster_message_signature_v2,
    wrap_cluster_key_for_recipient,
    unwrap_cluster_key,
    encrypt_cluster_message,
    decrypt_cluster_message,
    GATEWAY_PROTOCOL_VERSION,
    GATEWAY_HPKE_SUITE,
    canonical_json_stringify,
    sha256_hex,
    compute_args_digest,
    generate_x25519_key_pair,
    export_x25519_public_key_jwk,
    import_x25519_public_key,
    compute_x25519_key_fingerprint,
    compute_agent_encryption_key_id,
    get_local_agent_encryption_key_pair,
    rotate_local_agent_encryption_key_pair,
    revoke_local_agent_encryption_key_pair,
    is_agent_encryption_key_revoked,
    reset_local_agent_encryption_keys,
    sign_agent_encryption_key_binding,
    verify_agent_encryption_key_binding,
    build_agent_encryption_key_registration_payload,
    sign_gateway_instruction,
    verify_gateway_instruction_signature,
    hpke_seal_base,
    hpke_open_base,
    seal_gateway_token_envelope,
    open_gateway_token_envelope,
    sign_gateway_pop,
    verify_gateway_pop,
)
from aamarva.normalize import normalize_message, normalize_cluster
from aamarva.errors import AamarvaError


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library not installed in environment")
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
        if ed25519 is not None:
            ed_key = ed25519.Ed25519PrivateKey.generate()
            ed_pub_pem = ed_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            with self.assertRaises(AamarvaError) as ctx:
                verify_peer_key(ed_pub_pem, self.bob_fp, "AMR-BOB", self.bob_sig, self.bob_identity_pub_jwk)
            self.assertEqual(ctx.exception.code, "PEER_KEY_VERIFICATION_FAILED")
        # Also test non-P256 JWK rejection (works identically with OpenSSL fallback)
        with self.assertRaises(AamarvaError) as ctx2:
            verify_peer_key(
                {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
                self.bob_fp,
                "AMR-BOB",
                self.bob_sig,
                self.bob_identity_pub_jwk,
            )
        self.assertEqual(ctx2.exception.code, "PEER_KEY_VERIFICATION_FAILED")

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

    def test_persistent_keystore_process_restart(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            set_key_store(FileSystemKeyStore(tmp_dir))

            # 1. Generate identity key for Alice before restart
            alice_key_1 = get_local_identity_key("AMR-ALICE-PERSISTENT")
            alice_pub_pem_1 = get_local_public_key_pem("AMR-ALICE-PERSISTENT")
            alice_pub_jwk_1 = export_public_key_jwk(alice_key_1.public_key())
            alice_fp_1 = compute_key_fingerprint(alice_pub_jwk_1)
            alice_sig_1 = sign_identity_binding(alice_key_1, "AMR-ALICE-PERSISTENT", alice_fp_1)

            # Bob generates key
            bob_key = ec.generate_private_key(ec.SECP256R1())
            bob_pub_pem = bob_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            bob_fp = compute_key_fingerprint(bob_key.public_key())
            bob_jwk = export_public_key_jwk(bob_key.public_key())
            bob_sig = sign_identity_binding(bob_key, "AMR-BOB", bob_fp)

            # Encrypt message before restart
            secret = "Python persistent secret surviving restart"
            envelope = encrypt_message_with_keys(
                secret, "conn-persist-py", alice_key_1, bob_pub_pem, bob_fp, "AMR-BOB", bob_sig, bob_jwk
            )

            # 2. Simulate Process Restart: Clear cached identity keys & re-assign FileSystemKeyStore
            reset_local_identity_key()
            set_key_store(FileSystemKeyStore(tmp_dir))

            # 3. Reload Alice's key after restart
            alice_key_2 = get_local_identity_key("AMR-ALICE-PERSISTENT")
            alice_pub_pem_2 = get_local_public_key_pem("AMR-ALICE-PERSISTENT")
            alice_pub_jwk_2 = export_public_key_jwk(alice_key_2.public_key())
            alice_fp_2 = compute_key_fingerprint(alice_pub_jwk_2)

            self.assertEqual(alice_fp_1, alice_fp_2, "Key fingerprint must survive process restart")
            self.assertEqual(alice_pub_pem_1, alice_pub_pem_2, "Public key PEM must survive process restart")

            # Verify message decrypted after restart
            decrypted = decrypt_message_with_keys(
                envelope, "conn-persist-py", bob_key, alice_pub_pem_2, alice_fp_2, "AMR-ALICE-PERSISTENT", alice_sig_1, alice_pub_jwk_2
            )
            self.assertEqual(decrypted, secret)
            reset_local_identity_key()

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

        def mock_req(method, path, auth=False, params=None, json_data=None, skip_auto_auth=False, **kwargs):
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

    def test_workflow1_hkdf_and_sender_aad(self):
        self.assertEqual(WORKFLOW_HKDF_SALT, "aamarva-e2ee-channel-v1")
        env = encrypt_message_with_keys(
            "Workflow 1 sender-bound message",
            "conn_wf1",
            self.alice_priv,
            self.bob_pub_pem,
            self.bob_fp,
            "AMR-BOB",
            self.bob_sig,
            self.bob_identity_pub_jwk,
            key_epoch=1,
            sender_agent_id="amr-alice",
        )
        plain = decrypt_message_with_keys(
            env,
            "conn_wf1",
            self.bob_priv,
            self.alice_pub_pem,
            self.alice_fp,
            "AMR-ALICE",
            self.alice_sig,
            self.alice_identity_pub_jwk,
            sender_agent_id="AMR-ALICE",
        )
        self.assertEqual(plain, "Workflow 1 sender-bound message")

        with self.assertRaises(AamarvaError) as ctx:
            decrypt_message_with_keys(
                env,
                "conn_wf1",
                self.bob_priv,
                self.alice_pub_pem,
                self.alice_fp,
                "AMR-ALICE",
                self.alice_sig,
                self.alice_identity_pub_jwk,
                sender_agent_id="AMR-EVE",
            )
        self.assertEqual(ctx.exception.code, "MESSAGE_DECRYPTION_FAILED")

    def test_workflow2_cluster_crypto_and_ieee_p1363_signing(self):
        cluster_id = "clu_py_wf2"
        roster = ["AMR-MASTER", "AMR-ALICE", "AMR-BOB"]
        rst = compute_roster_hash(roster)
        aud = compute_audience_hash(["AMR-ALICE", "AMR-BOB"], roster)
        self.assertTrue(rst.startswith("RST:"))
        self.assertTrue(aud.startswith("AUD:"))

        group_key = generate_cluster_key()
        group_fp = compute_group_key_fingerprint(group_key)
        wrapped = wrap_cluster_key_for_recipient(
            cluster_key=group_key,
            recipient_public_key=self.bob_pub_pem,
            sender_private_key=self.alice_priv,
            cluster_id=cluster_id,
            epoch=2,
            audience_hash=aud,
            roster_hash=rst,
            key_fingerprint=group_fp,
            sender_agent_id="AMR-ALICE",
            recipient_agent_id="AMR-BOB",
        )
        unwrapped = unwrap_cluster_key(
            wrapped["encryptedKeyPackage"],
            wrapped["nonce"],
            self.bob_priv,
            self.alice_pub_pem,
            cluster_id=cluster_id,
            epoch=2,
            audience_hash=aud,
            expected_key_fingerprint=group_fp,
        )
        self.assertEqual(unwrapped, group_key)

        with self.assertRaises(AamarvaError) as fp_ctx:
            unwrap_cluster_key(
                wrapped["encryptedKeyPackage"],
                wrapped["nonce"],
                self.bob_priv,
                self.alice_pub_pem,
                cluster_id=cluster_id,
                epoch=2,
                audience_hash=aud,
                expected_key_fingerprint="SHA256:" + ":".join(["00"] * 32),
            )
        self.assertEqual(fp_ctx.exception.code, "CLUSTER_KEY_FINGERPRINT_MISMATCH")

        enc = encrypt_cluster_message("Subgroup message", group_key, cluster_id, epoch=2, audience_hash=aud, sender_agent_id="AMR-ALICE")
        dec = decrypt_cluster_message(enc["ciphertext"], enc["nonce"], group_key, cluster_id, epoch=2, audience_hash=aud, sender_agent_id="AMR-ALICE")
        self.assertEqual(dec, "Subgroup message")

        with self.assertRaises(AamarvaError) as aud_ctx:
            decrypt_cluster_message(enc["ciphertext"], enc["nonce"], group_key, cluster_id, epoch=2, audience_hash="ALL", sender_agent_id="AMR-ALICE")
        self.assertEqual(aud_ctx.exception.code, "CLUSTER_MESSAGE_DECRYPTION_FAILED")

        sig = sign_cluster_message_v2(
            self.alice_priv,
            cluster_id,
            2,
            "AMR-ALICE",
            aud,
            rst,
            5,
            group_fp,
            enc["nonce"],
            enc["ciphertext"],
        )
        self.assertEqual(len(base64.b64decode(sig)), 64)
        self.assertTrue(
            verify_cluster_message_signature_v2(
                self.alice_pub_pem,
                cluster_id,
                2,
                "AMR-ALICE",
                aud,
                rst,
                5,
                group_fp,
                enc["nonce"],
                enc["ciphertext"],
                sig,
            )
        )
        self.assertFalse(
            verify_cluster_message_signature_v2(
                self.alice_pub_pem,
                cluster_id,
                2,
                "AMR-ALICE",
                aud,
                rst,
                6,
                group_fp,
                enc["nonce"],
                enc["ciphertext"],
                sig,
            )
        )

    def test_epoch_and_unwrap_fail_closed(self):
        get_local_identity_key("AMR-EPOCH-TEST-PY")
        with self.assertRaises(AamarvaError) as ctx:
            get_local_identity_key("AMR-EPOCH-TEST-PY", epoch=99)
        self.assertEqual(ctx.exception.code, "IDENTITY_KEY_UNAVAILABLE")

        for bad_ep in (0, -1, True):
            with self.assertRaises(AamarvaError) as bad_ctx:
                get_local_identity_key("AMR-EPOCH-TEST-PY", epoch=bad_ep)
            self.assertEqual(bad_ctx.exception.code, "IDENTITY_KEY_INVALID")

        group_key = generate_cluster_key()
        group_fp = compute_group_key_fingerprint(group_key)
        wrapped = wrap_cluster_key_for_recipient(
            cluster_key=group_key,
            recipient_public_key=self.bob_pub_pem,
            sender_private_key=self.alice_priv,
            cluster_id="clu_unwrap_py",
            epoch=2,
            audience_hash="ALL",
            key_fingerprint=group_fp,
            sender_agent_id="AMR-ALICE",
            recipient_agent_id="AMR-BOB",
        )

        with self.assertRaises(AamarvaError) as c1:
            unwrap_cluster_key(wrapped["encryptedKeyPackage"], wrapped["nonce"], self.bob_priv, self.alice_pub_pem, cluster_id="", epoch=2, audience_hash="ALL", expected_key_fingerprint=group_fp)
        self.assertEqual(c1.exception.code, "CLUSTER_KEY_UNWRAP_FAILED")

        with self.assertRaises(AamarvaError) as c2:
            unwrap_cluster_key(wrapped["encryptedKeyPackage"], wrapped["nonce"], self.bob_priv, self.alice_pub_pem, cluster_id="clu_unwrap_py", epoch=0, audience_hash="ALL", expected_key_fingerprint=group_fp)
        self.assertEqual(c2.exception.code, "CLUSTER_KEY_UNWRAP_FAILED")

        with self.assertRaises(AamarvaError) as c3:
            unwrap_cluster_key(wrapped["encryptedKeyPackage"], wrapped["nonce"], self.bob_priv, self.alice_pub_pem, cluster_id="clu_unwrap_py", epoch=3, audience_hash="ALL", expected_key_fingerprint=group_fp)
        self.assertEqual(c3.exception.code, "CLUSTER_KEY_UNWRAP_FAILED")

        with self.assertRaises(AamarvaError) as c4:
            unwrap_cluster_key(
                wrapped["encryptedKeyPackage"],
                wrapped["nonce"],
                self.bob_priv,
                self.alice_pub_pem,
                cluster_id="clu_unwrap_py",
                epoch=2,
                audience_hash="ALL",
                expected_key_fingerprint=group_fp,
                recipient_agent_id="AMR-CHARLIE",
            )
        self.assertEqual(c4.exception.code, "RECIPIENT_KEY_MISMATCH")

        with self.assertRaises(AamarvaError) as c5:
            unwrap_cluster_key(
                wrapped["encryptedKeyPackage"],
                wrapped["nonce"],
                self.bob_priv,
                self.alice_pub_pem,
                cluster_id="clu_unwrap_py",
                epoch=2,
                audience_hash="ALL",
                expected_key_fingerprint=group_fp,
                wrapping_params={"algorithm": "RSA-OAEP", "curve": "P-256", "hkdfHash": "SHA-256"},
            )
        self.assertEqual(c5.exception.code, "CLUSTER_KEY_UNWRAP_FAILED")


class TestNormalizationSecurityHardening(unittest.TestCase):
    def test_normalize_message_rejects_invalid_version_and_epoch(self):
        base = {
            "messageId": "m1",
            "connectionId": "conn-1",
            "senderAgentId": "AMR-A",
            "ciphertext": "Y2lwaGVy",
            "nonce": "MTIzNDU2Nzg5MDEy",
            "version": 1,
            "keyEpoch": 1,
        }
        ok = normalize_message(base, "conn-1")
        self.assertEqual(ok.version, 1)
        self.assertEqual(ok.keyEpoch, 1)

        for bad_ver in (None, 0, -1, True, 1.5, "abc"):
            bad = {**base, "version": bad_ver}
            with self.assertRaises(AamarvaError) as ctx:
                normalize_message(bad, "conn-1")
            self.assertEqual(ctx.exception.code, "MESSAGE_INVALID_ENVELOPE")

        for bad_ep in (None, 0, -1, True, 1.5, "abc"):
            bad = {**base, "keyEpoch": bad_ep}
            with self.assertRaises(AamarvaError) as ctx:
                normalize_message(bad, "conn-1")
            self.assertEqual(ctx.exception.code, "MESSAGE_INVALID_ENVELOPE")

    def test_normalize_cluster_rejects_invalid_epoch(self):
        for bad_ep in (None, 0, -2, True, 2.5, "abc"):
            cluster = normalize_cluster({"clusterId": "c1", "name": "C", "epoch": bad_ep})
            self.assertIsNone(cluster.epoch)
            self.assertIsNone(cluster.keyEpoch)


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography/OpenSSL backend not available")
class TestGatewayCrypto(unittest.TestCase):
    def setUp(self):
        reset_local_identity_key()
        reset_local_agent_encryption_keys()
        self.addCleanup(reset_local_identity_key)
        self.addCleanup(reset_local_agent_encryption_keys)

    def test_canonical_json_and_args_digest(self):
        a = {"b": 2, "a": [True, {"y": 9, "x": 8}]}
        b = {"a": [True, {"x": 8, "y": 9}], "b": 2}
        self.assertEqual(canonical_json_stringify(a), canonical_json_stringify(b))
        self.assertEqual(compute_args_digest(a), compute_args_digest(b))
        self.assertTrue(compute_args_digest(a).startswith("sha256:"))

    def test_x25519_key_lifecycle_rotation_revocation_and_binding(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            set_key_store(FileSystemKeyStore(tmp_dir))
            k1 = get_local_agent_encryption_key_pair("AMR-GW-PY", require_persistent=True)
            self.assertEqual(k1["key_version"], 1)
            self.assertTrue(k1["key_id"].startswith("amv_ak_"))
            self.assertEqual(k1["public_key_jwk"]["kty"], "OKP")
            self.assertEqual(k1["public_key_jwk"]["crv"], "X25519")

            payload = build_agent_encryption_key_registration_payload("AMR-GW-PY", require_persistent=True, key_info=k1)
            self.assertEqual(payload["version"], GATEWAY_PROTOCOL_VERSION)
            self.assertEqual(payload["algorithm"], "X25519")
            self.assertEqual(payload["hpkeSuite"], GATEWAY_HPKE_SUITE)
            self.assertTrue(
                verify_agent_encryption_key_binding(
                    payload["identityPublicKey"],
                    "AMR-GW-PY",
                    payload["keyId"],
                    payload["keyVersion"],
                    payload["fingerprint"],
                    payload["publicKey"],
                    payload["signature"],
                )
            )

            # Tampered keyId or signature must fail verification
            self.assertFalse(
                verify_agent_encryption_key_binding(
                    payload["identityPublicKey"],
                    "AMR-OTHER",
                    payload["keyId"],
                    payload["keyVersion"],
                    payload["fingerprint"],
                    payload["publicKey"],
                    payload["signature"],
                )
            )

            # Rotate with revoke_previous=True
            k2 = rotate_local_agent_encryption_key_pair("AMR-GW-PY", require_persistent=True, revoke_previous=True)
            self.assertEqual(k2["key_version"], 2)
            self.assertEqual(k2["previous_key_id"], k1["key_id"])
            self.assertTrue(is_agent_encryption_key_revoked("AMR-GW-PY", k1["key_id"], 1))
            with self.assertRaises(AamarvaError) as rev_ctx:
                get_local_agent_encryption_key_pair("AMR-GW-PY", key_id=k1["key_id"])
            self.assertEqual(rev_ctx.exception.code, "AGENT_ENCRYPTION_KEY_REVOKED")

            # Persistent enforcement on InMemoryKeyStore must fail closed
            set_key_store(InMemoryKeyStore())
            with self.assertRaises(AamarvaError) as mem_ctx:
                get_local_agent_encryption_key_pair("AMR-GW-MEM", require_persistent=True)
            self.assertEqual(mem_ctx.exception.code, "KEYSTORE_NOT_PERSISTENT")

    def test_hpke_base_seal_open_and_tamper_resistance(self):
        kp = generate_x25519_key_pair()
        wrong_kp = generate_x25519_key_pair()
        jwk = export_x25519_public_key_jwk(kp["public_key"])
        aad = b"aad-context"
        info = b"info-context"
        pt = b'{"token":"gw_tok_123"}'

        enc, ct = hpke_seal_base(jwk, pt, aad=aad, info=info)
        self.assertEqual(len(enc), 32)
        opened = hpke_open_base(kp["private_key"], enc, ct, aad=aad, info=info)
        self.assertEqual(opened, pt)

        with self.assertRaises(Exception):
            hpke_open_base(wrong_kp["private_key"], enc, ct, aad=aad, info=info)
        with self.assertRaises(Exception):
            hpke_open_base(kp["private_key"], enc, ct, aad=b"wrong-aad", info=info)
        with self.assertRaises(Exception):
            hpke_open_base(kp["private_key"], enc, ct, aad=aad, info=b"wrong-info")

    def test_gateway_instruction_envelope_and_pop_roundtrip(self):
        import datetime
        agent_enc = get_local_agent_encryption_key_pair("AMR-PY-AGENT")
        agent_id_priv = get_local_identity_key("AMR-PY-AGENT")
        agent_id_jwk = export_public_key_jwk(agent_id_priv.public_key())

        issuer_priv = ec.generate_private_key(ec.SECP256R1())
        issuer_jwk = export_public_key_jwk(issuer_priv.public_key())
        gw_priv = ec.generate_private_key(ec.SECP256R1())
        gw_jwk = export_public_key_jwk(gw_priv.public_key())

        now = datetime.datetime.now(datetime.timezone.utc)
        iat = now.isoformat().replace("+00:00", "Z")
        exp = (now + datetime.timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        args = {"ticker": "AAPL"}
        digest = compute_args_digest(args)

        inst = {
            "version": GATEWAY_PROTOCOL_VERSION,
            "instructionId": "inst_py_1",
            "issuer": "aamarva.platform",
            "audience": "aamarva.gateway",
            "gatewayId": "gw_py",
            "agentId": "AMR-PY-AGENT",
            "agentKeyId": agent_enc["key_id"],
            "agentKeyVersion": agent_enc["key_version"],
            "agentPublicKey": agent_enc["public_key_jwk"],
            "invocationId": "inv_py_1",
            "mcpServerId": "mcp_sec",
            "toolId": "tool_sec",
            "approvedArguments": args,
            "approvedArgsDigest": digest,
            "decision": "approved",
            "scope": "tool:invoke",
            "iat": iat,
            "exp": exp,
            "issuerKeyId": "iss_k1",
        }
        inst["signature"] = sign_gateway_instruction(issuer_priv, inst)
        self.assertTrue(verify_gateway_instruction_signature(issuer_jwk, inst))
        self.assertFalse(verify_gateway_instruction_signature(gw_jwk, inst))

        token_payload = {
            "version": GATEWAY_PROTOCOL_VERSION,
            "token": "gw_single_use_tok_py",
            "gatewayId": "gw_py",
            "gatewayUrl": "https://aamarva.com/api/gateway",
            "agentId": "AMR-PY-AGENT",
            "agentKeyId": agent_enc["key_id"],
            "agentKeyVersion": agent_enc["key_version"],
            "invocationId": "inv_py_1",
            "instructionId": "inst_py_1",
            "mcpServerId": "mcp_sec",
            "toolId": "tool_sec",
            "approvedArgsDigest": digest,
            "scope": "tool:invoke",
            "iat": iat,
            "exp": exp,
        }
        envelope = seal_gateway_token_envelope(
            token_payload=token_payload,
            agent_public_key=agent_enc["public_key_jwk"],
            gateway_signing_private_key=gw_priv,
            gateway_key_id="gw_k1",
            gateway_public_key=gw_jwk,
        )
        opened = open_gateway_token_envelope(
            envelope=envelope,
            agent_encryption_key=agent_enc["private_key"],
            trusted_gateway_public_keys={"gw_k1": gw_jwk},
            expected_context={"agentId": "AMR-PY-AGENT", "toolId": "tool_sec", "approvedArgsDigest": digest},
        )
        self.assertEqual(opened["token"], "gw_single_use_tok_py")

        # Tampered gateway signature or untrusted key must fail closed
        with self.assertRaises(AamarvaError) as untrusted_ctx:
            open_gateway_token_envelope(envelope, agent_enc["private_key"], {"other": gw_jwk})
        self.assertEqual(untrusted_ctx.exception.code, "GATEWAY_UNTRUSTED_KEY")

        bad_sig_env = {**envelope, "ciphertext": base64.b64encode(b"\x00" * 32).decode("ascii")}
        with self.assertRaises(AamarvaError) as sig_ctx:
            open_gateway_token_envelope(bad_sig_env, agent_enc["private_key"], {"gw_k1": gw_jwk})
        self.assertEqual(sig_ctx.exception.code, "GATEWAY_SIGNATURE_INVALID")

        # Proof-of-possession sign + verify
        pop_params = {
            "version": GATEWAY_PROTOCOL_VERSION,
            "tokenSha256": sha256_hex(opened["token"]),
            "gatewayId": "gw_py",
            "agentId": "AMR-PY-AGENT",
            "agentKeyId": agent_enc["key_id"],
            "invocationId": "inv_py_1",
            "instructionId": "inst_py_1",
            "mcpServerId": "mcp_sec",
            "toolId": "tool_sec",
            "approvedArgsDigest": digest,
            "nonce": "nonce_py_1",
            "timestamp": iat,
        }
        pop_sig = sign_gateway_pop(agent_id_priv, pop_params)
        self.assertTrue(verify_gateway_pop(agent_id_jwk, pop_params, pop_sig))
        self.assertFalse(verify_gateway_pop(agent_id_jwk, {**pop_params, "nonce": "replayed"}, pop_sig))


if __name__ == "__main__":
    unittest.main()
