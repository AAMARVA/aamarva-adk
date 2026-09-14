#!/usr/bin/env python3
import sys
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Add python directory to sys.path
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from aamarva.crypto import (
    export_public_key_jwk,
    sign_identity_binding,
    compute_key_fingerprint,
    encrypt_message_with_keys,
    decrypt_message_with_keys,
)
from aamarva.errors import AamarvaError

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Missing command"}))
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "gen-key":
        priv = ec.generate_private_key(ec.SECP256R1())
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        fp = compute_key_fingerprint(pub_pem)
        jwk = export_public_key_jwk(priv.public_key())
        sig = sign_identity_binding(priv, "AMR-PYTHON", fp)
        print(json.dumps({
            "privateKey": priv_pem,
            "publicKey": pub_pem,
            "fingerprint": fp,
            "identityKey": jwk,
            "identitySignature": sig
        }))
        return

    input_data = json.loads(sys.stdin.read())

    if cmd == "decrypt":
        envelope = input_data["envelope"]
        conn_id = input_data["connectionId"]
        priv_pem = input_data.get("localPrivPem", input_data.get("privateKey"))
        peer_pub_pem = input_data["peerPubPem"]
        peer_fp = input_data.get("peerFingerprint")
        peer_agent_id = input_data.get("peerAgentId")
        peer_sig = input_data.get("peerSignature")
        peer_identity_key = input_data.get("peerIdentityKey")

        priv = serialization.load_pem_private_key(priv_pem.encode('utf-8'), password=None)
        try:
            plaintext = decrypt_message_with_keys(envelope, conn_id, priv, peer_pub_pem, peer_fp, peer_agent_id, peer_sig, peer_identity_key)
            print(json.dumps({"success": True, "plaintext": plaintext}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))
        except Exception as err:
            print(json.dumps({"success": False, "error": str(err), "code": "UNKNOWN_ERROR"}))

    elif cmd == "encrypt":
        plaintext = input_data["plaintext"]
        conn_id = input_data["connectionId"]
        priv_pem = input_data.get("localPrivPem", input_data.get("privateKey"))
        peer_pub_pem = input_data["peerPubPem"]
        peer_fp = input_data.get("peerFingerprint")
        peer_agent_id = input_data.get("peerAgentId")
        peer_sig = input_data.get("peerSignature")
        peer_identity_key = input_data.get("peerIdentityKey")
        key_epoch = input_data.get("keyEpoch", 1)

        priv = serialization.load_pem_private_key(priv_pem.encode('utf-8'), password=None)
        try:
            envelope = encrypt_message_with_keys(plaintext, conn_id, priv, peer_pub_pem, peer_fp, peer_agent_id, peer_sig, peer_identity_key, key_epoch=key_epoch)
            print(json.dumps({"success": True, "envelope": envelope}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))
        except Exception as err:
            print(json.dumps({"success": False, "error": str(err), "code": "UNKNOWN_ERROR"}))

    else:
        print(json.dumps({"error": f"Unknown command {cmd}"}))
        sys.exit(1)

if __name__ == "__main__":
    main()
