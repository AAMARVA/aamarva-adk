#!/usr/bin/env python3
import sys
import json
import base64
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

try:
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    from aamarva._openssl_backend import ec, x25519, serialization

from aamarva.crypto import (
    export_public_key_jwk,
    sign_identity_binding,
    compute_key_fingerprint,
    compute_group_key_fingerprint,
    encrypt_message_with_keys,
    decrypt_message_with_keys,
    wrap_cluster_key_for_recipient,
    unwrap_cluster_key,
    encrypt_cluster_message,
    decrypt_cluster_message,
    sign_cluster_message_v2,
    verify_cluster_message_signature_v2,
    generate_x25519_key_pair,
    export_x25519_public_key_jwk,
    compute_x25519_key_fingerprint,
    compute_agent_encryption_key_id,
    sign_agent_encryption_key_binding,
    verify_agent_encryption_key_binding,
    sign_gateway_instruction,
    verify_gateway_instruction_signature,
    seal_gateway_token_envelope,
    open_gateway_token_envelope,
    sign_gateway_pop,
    verify_gateway_pop,
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
        sender_agent_id = input_data.get("senderAgentId")

        priv = serialization.load_pem_private_key(priv_pem.encode('utf-8'), password=None)
        try:
            plaintext = decrypt_message_with_keys(
                envelope,
                conn_id,
                priv,
                peer_pub_pem,
                peer_fp,
                peer_agent_id,
                peer_sig,
                peer_identity_key,
                sender_agent_id=sender_agent_id,
            )
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
        sender_agent_id = input_data.get("senderAgentId")

        priv = serialization.load_pem_private_key(priv_pem.encode('utf-8'), password=None)
        try:
            envelope = encrypt_message_with_keys(
                plaintext,
                conn_id,
                priv,
                peer_pub_pem,
                peer_fp,
                peer_agent_id,
                peer_sig,
                peer_identity_key,
                key_epoch=key_epoch,
                sender_agent_id=sender_agent_id,
            )
            print(json.dumps({"success": True, "envelope": envelope}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))
        except Exception as err:
            print(json.dumps({"success": False, "error": str(err), "code": "UNKNOWN_ERROR"}))

    elif cmd == "cluster-wrap":
        cluster_key = base64.b64decode(input_data["clusterKeyB64"])
        priv = serialization.load_pem_private_key(input_data["senderPrivPem"].encode("utf-8"), password=None)
        try:
            wrapped = wrap_cluster_key_for_recipient(
                cluster_key=cluster_key,
                recipient_public_key=input_data["recipientPubPem"],
                sender_private_key=priv,
                cluster_id=input_data["clusterId"],
                epoch=input_data.get("epoch", 1),
                audience_hash=input_data.get("audienceHash", "ALL"),
                roster_hash=input_data.get("rosterHash"),
                sender_agent_id=input_data.get("senderAgentId"),
                recipient_agent_id=input_data.get("recipientAgentId"),
            )
            print(json.dumps({"success": True, **wrapped}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))

    elif cmd == "cluster-unwrap":
        priv = serialization.load_pem_private_key(input_data["recipientPrivPem"].encode("utf-8"), password=None)
        try:
            unwrapped = unwrap_cluster_key(
                encrypted_key_package=input_data["encryptedKeyPackage"],
                nonce_b64=input_data.get("nonce", ""),
                recipient_private_key=priv,
                sender_public_key=input_data["senderPubPem"],
                cluster_id=input_data["clusterId"],
                epoch=input_data.get("epoch", 1),
                audience_hash=input_data.get("audienceHash", "ALL"),
                expected_key_fingerprint=input_data.get("expectedKeyFingerprint"),
            )
            print(json.dumps({"success": True, "clusterKeyB64": base64.b64encode(unwrapped).decode("utf-8")}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))

    elif cmd == "cluster-sign-encrypt":
        cluster_key = base64.b64decode(input_data["clusterKeyB64"])
        priv = serialization.load_pem_private_key(input_data["senderPrivPem"].encode("utf-8"), password=None)
        cluster_id = input_data["clusterId"]
        epoch = input_data.get("epoch", 1)
        audience_hash = input_data.get("audienceHash", "ALL")
        roster_hash = input_data["rosterHash"]
        sender_agent_id = input_data["senderAgentId"]
        sequence = input_data.get("sequence")
        try:
            enc = encrypt_cluster_message(
                plaintext=input_data["plaintext"],
                cluster_key=cluster_key,
                cluster_id=cluster_id,
                epoch=epoch,
                audience_hash=audience_hash,
                sender_agent_id=sender_agent_id,
            )
            key_fp = compute_group_key_fingerprint(cluster_key)
            sig = sign_cluster_message_v2(
                private_key=priv,
                cluster_id=cluster_id,
                key_epoch=epoch,
                sender_agent_id=sender_agent_id,
                audience_hash=audience_hash,
                roster_hash=roster_hash,
                sequence=sequence,
                key_fingerprint=key_fp,
                nonce=enc["nonce"],
                ciphertext=enc["ciphertext"],
            )
            print(json.dumps({
                "success": True,
                **enc,
                "keyFingerprint": key_fp,
                "rosterHash": roster_hash,
                "signature": sig,
            }))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))

    elif cmd == "cluster-verify-decrypt":
        cluster_key = base64.b64decode(input_data["clusterKeyB64"])
        cluster_id = input_data["clusterId"]
        epoch = input_data.get("epoch", 1)
        audience_hash = input_data.get("audienceHash", "ALL")
        roster_hash = input_data["rosterHash"]
        sender_agent_id = input_data["senderAgentId"]
        sequence = input_data.get("sequence")
        key_fp = input_data["keyFingerprint"]
        try:
            sig_valid = verify_cluster_message_signature_v2(
                sender_public_key=input_data["senderPubPem"],
                cluster_id=cluster_id,
                key_epoch=epoch,
                sender_agent_id=sender_agent_id,
                audience_hash=audience_hash,
                roster_hash=roster_hash,
                sequence=sequence,
                key_fingerprint=key_fp,
                nonce=input_data["nonce"],
                ciphertext=input_data["ciphertext"],
                signature_b64=input_data["signature"],
            )
            plaintext = decrypt_cluster_message(
                ciphertext_b64=input_data["ciphertext"],
                nonce_b64=input_data["nonce"],
                cluster_key=cluster_key,
                cluster_id=cluster_id,
                epoch=epoch,
                audience_hash=audience_hash,
                sender_agent_id=sender_agent_id,
            )
            print(json.dumps({"success": True, "signatureValid": sig_valid, "plaintext": plaintext}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))

    elif cmd == "gw-gen-keys":
        id_priv = ec.generate_private_key(ec.SECP256R1())
        id_priv_pem = id_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        id_pub_jwk = export_public_key_jwk(id_priv.public_key())

        x_kp = generate_x25519_key_pair()
        x_priv_pem = x_kp["private_key"].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        x_pub_jwk = export_x25519_public_key_jwk(x_kp["public_key"])
        x_fp = compute_x25519_key_fingerprint(x_pub_jwk)
        key_id = compute_agent_encryption_key_id(input_data.get("agentId", "AMR-PYTHON"), x_pub_jwk, 1)
        enc_sig = sign_agent_encryption_key_binding(
            id_priv,
            agent_id=input_data.get("agentId", "AMR-PYTHON"),
            key_id=key_id,
            key_version=1,
            fingerprint=x_fp,
            public_key=x_pub_jwk,
        )
        print(json.dumps({
            "success": True,
            "identityPrivateKeyPem": id_priv_pem,
            "identityPublicKeyJwk": id_pub_jwk,
            "x25519PrivateKeyPem": x_priv_pem,
            "x25519PublicKeyJwk": x_pub_jwk,
            "x25519Fingerprint": x_fp,
            "keyId": key_id,
            "keyVersion": 1,
            "encBindingSignature": enc_sig,
        }))

    elif cmd == "gw-seal-envelope":
        try:
            gw_priv = serialization.load_pem_private_key(input_data["gatewaySigningPrivateKeyPem"].encode("utf-8"), password=None)
            envelope = seal_gateway_token_envelope(
                token_payload=input_data["tokenPayload"],
                agent_public_key=input_data["agentPublicKey"],
                gateway_signing_private_key=gw_priv,
                gateway_key_id=input_data["gatewayKeyId"],
                gateway_public_key=input_data.get("gatewayPublicKey"),
            )
            print(json.dumps({"success": True, "envelope": envelope}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))

    elif cmd == "gw-open-envelope":
        try:
            x_priv = serialization.load_pem_private_key(input_data["agentPrivateKeyPem"].encode("utf-8"), password=None)
            payload = open_gateway_token_envelope(
                envelope=input_data["envelope"],
                agent_encryption_key=x_priv,
                trusted_gateway_public_keys=input_data["trustedGatewayPublicKeys"],
                expected_context=input_data.get("expectedContext"),
            )
            print(json.dumps({"success": True, "payload": payload}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))

    elif cmd == "gw-sign-instruction":
        try:
            iss_priv = serialization.load_pem_private_key(input_data["issuerPrivateKeyPem"].encode("utf-8"), password=None)
            sig = sign_gateway_instruction(iss_priv, input_data["instruction"])
            print(json.dumps({"success": True, "signature": sig}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))

    elif cmd == "gw-verify-instruction":
        valid = verify_gateway_instruction_signature(input_data["issuerPublicKey"], input_data["instruction"])
        print(json.dumps({"success": True, "valid": valid}))

    elif cmd == "gw-sign-pop":
        try:
            id_priv = serialization.load_pem_private_key(input_data["identityPrivateKeyPem"].encode("utf-8"), password=None)
            sig = sign_gateway_pop(id_priv, input_data["params"])
            print(json.dumps({"success": True, "signature": sig}))
        except AamarvaError as err:
            print(json.dumps({"success": False, "error": str(err), "code": err.code}))

    elif cmd == "gw-verify-pop":
        valid = verify_gateway_pop(input_data["identityPublicKey"], input_data["params"], input_data["signature"])
        print(json.dumps({"success": True, "valid": valid}))

    else:
        print(json.dumps({"error": f"Unknown command {cmd}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
