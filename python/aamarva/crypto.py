import os
import json
import hashlib
import base64
from abc import ABC, abstractmethod
from typing import Optional, Union, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .errors import AamarvaError


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


def _b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s += '=' * pad
    return base64.urlsafe_b64decode(s)


class KeyStore(ABC):
    """
    KeyStore abstraction for managing local agent private identity keys.
    Private keys must never be logged or transmitted to AAMARVA.
    """
    @abstractmethod
    def load_private_key(self, identity_id: str = "default") -> Optional[str]:
        pass

    @abstractmethod
    def save_private_key(self, private_key_pem: str, identity_id: str = "default") -> None:
        pass


class InMemoryKeyStore(KeyStore):
    """
    Default in-memory KeyStore. Keys are kept purely in process memory
    and discarded upon process exit.
    """
    def __init__(self):
        self._keys = {}

    def load_private_key(self, identity_id: str = "default") -> Optional[str]:
        return self._keys.get(identity_id)

    def save_private_key(self, private_key_pem: str, identity_id: str = "default") -> None:
        self._keys[identity_id] = private_key_pem


class FileSystemKeyStore(KeyStore):
    """
    FileSystemKeyStore persists private keys to disk with POSIX permissions (0600).
    Configurable via base_dir or AAMARVA_KEY_STORE_PATH env variable.
    """
    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.environ.get("AAMARVA_KEY_STORE_PATH", "")

    def load_private_key(self, identity_id: str = "default") -> Optional[str]:
        if not self.base_dir:
            return None
        key_path = os.path.join(self.base_dir, f"{identity_id}.pem")
        if os.path.exists(key_path):
            with open(key_path, "r", encoding="utf-8") as f:
                return f.read()
        return None

    def save_private_key(self, private_key_pem: str, identity_id: str = "default") -> None:
        if not self.base_dir:
            return
        os.makedirs(self.base_dir, mode=0o700, exist_ok=True)
        key_path = os.path.join(self.base_dir, f"{identity_id}.pem")
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(private_key_pem)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass


_active_key_store: KeyStore = InMemoryKeyStore()
_cached_identity_keys = {}


def set_key_store(store: KeyStore) -> None:
    global _active_key_store
    _active_key_store = store


def get_key_store() -> KeyStore:
    return _active_key_store


def reset_local_identity_key() -> None:
    global _active_key_store, _cached_identity_keys
    _cached_identity_keys.clear()
    _active_key_store = InMemoryKeyStore()


def get_local_identity_key(identity_id: str = "default") -> ec.EllipticCurvePrivateKey:
    global _cached_identity_keys, _active_key_store
    if identity_id in _cached_identity_keys:
        return _cached_identity_keys[identity_id]

    stored_pem = _active_key_store.load_private_key(identity_id)
    if stored_pem and isinstance(stored_pem, str) and stored_pem.strip():
        try:
            priv = serialization.load_pem_private_key(stored_pem.encode('utf-8'), password=None)
            if isinstance(priv, ec.EllipticCurvePrivateKey):
                _cached_identity_keys[identity_id] = priv
                return priv
            raise AamarvaError("Stored key is not an EC private key.", code="IDENTITY_KEY_INVALID")
        except Exception as err:
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(
                f"Failed to load stored identity key: key is corrupt or invalid format: {str(err)}",
                code="IDENTITY_KEY_INVALID"
            )

    priv = ec.generate_private_key(ec.SECP256R1())
    _cached_identity_keys[identity_id] = priv
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    _active_key_store.save_private_key(priv_pem, identity_id)
    return priv


def get_local_public_key_pem(identity_id: str = "default") -> str:
    priv = get_local_identity_key(identity_id)
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


def export_public_key_jwk(key: Optional[Any] = None) -> Dict[str, str]:
    """
    Export a P-256 EC public key in standard JWK representation.
    """
    if key is None:
        pub = get_local_identity_key().public_key()
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        pub = key.public_key()
    elif isinstance(key, ec.EllipticCurvePublicKey):
        pub = key
    elif isinstance(key, (str, dict)):
        pub = import_public_key(key)
    else:
        raise AamarvaError("Invalid key object provided for JWK export.", code="INVALID_PEER_KEY")

    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise AamarvaError("Exported key must be an EC P-256 public key.", code="INVALID_PEER_KEY")

    pn = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(pn.x.to_bytes(32, byteorder='big')),
        "y": _b64url_encode(pn.y.to_bytes(32, byteorder='big')),
    }


def import_public_key(key: Any) -> ec.EllipticCurvePublicKey:
    """
    Import a P-256 EC public key from JWK dict, JSON string, PEM string, or key object.
    """
    if key is None:
        raise AamarvaError("Missing public key.", code="PEER_KEY_UNAVAILABLE")

    if isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise AamarvaError(f"Unsupported curve: {key.curve.name}. Only P-256 is supported.", code="INVALID_PEER_KEY")
        return key

    if isinstance(key, str):
        trimmed = key.strip()
        if not trimmed:
            raise AamarvaError("Empty public key provided.", code="PEER_KEY_UNAVAILABLE")
        if trimmed.startswith('{'):
            try:
                parsed = json.loads(trimmed)
                return import_public_key(parsed)
            except Exception as err:
                raise AamarvaError(f"Failed to parse JWK string: {str(err)}", code="INVALID_PEER_KEY")
        try:
            pub = serialization.load_pem_public_key(trimmed.encode('utf-8'))
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                raise AamarvaError("Public key must be an elliptic curve (EC) key.", code="INVALID_PEER_KEY")
            if not isinstance(pub.curve, ec.SECP256R1):
                raise AamarvaError(f"Unsupported curve: {pub.curve.name}. Only P-256 is supported.", code="INVALID_PEER_KEY")
            return pub
        except Exception as err:
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(f"Invalid peer public key: {str(err)}", code="INVALID_PEER_KEY")

    if isinstance(key, dict):
        kty = key.get("kty")
        crv = key.get("crv")
        if not kty or not crv:
            raise AamarvaError("Invalid key object: missing kty or crv properties.", code="INVALID_PEER_KEY")
        if kty != "EC":
            raise AamarvaError(f"Invalid key type: {kty}. Expected 'EC'.", code="INVALID_PEER_KEY")
        if crv != "P-256":
            raise AamarvaError(f"Unsupported curve: {crv}. Only P-256 is supported.", code="INVALID_PEER_KEY")
        x_raw = key.get("x")
        y_raw = key.get("y")
        if not x_raw or not y_raw or not isinstance(x_raw, str) or not isinstance(y_raw, str):
            raise AamarvaError("Malformed JWK: missing or invalid x/y coordinate parameters.", code="INVALID_PEER_KEY")
        try:
            x_int = int.from_bytes(_b64url_decode(x_raw), byteorder='big')
            y_int = int.from_bytes(_b64url_decode(y_raw), byteorder='big')
            pub_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1())
            return pub_numbers.public_key()
        except Exception as err:
            raise AamarvaError(f"Failed to import EC JWK: {str(err)}", code="INVALID_PEER_KEY")

    raise AamarvaError("Invalid public key format provided.", code="INVALID_PEER_KEY")


def compute_key_fingerprint(key: Any) -> str:
    """
    Exact fingerprint calculation: SHA-256 hash of canonical P-256 JWK.
    """
    try:
        pub = import_public_key(key)
        
        # Build canonical dict
        jwk_dict = export_public_key_jwk(pub)
        
        import json
        import hashlib
        
        canonical_dict = {
            "crv": "P-256",
            "kty": "EC",
            "x": jwk_dict["x"],
            "y": jwk_dict["y"]
        }
        canonical_json = json.dumps(canonical_dict, separators=(',', ':'))
        hash_hex = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest().upper()
        formatted = ':'.join(hash_hex[i:i+2] for i in range(0, len(hash_hex), 2))
        return f"SHA256:{formatted}"
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to compute key fingerprint: {str(err)}", code="PEER_KEY_VERIFICATION_FAILED")


def create_identity_binding_string(agent_id: str, fingerprint: str) -> str:
    """
    Construct the canonical identity binding string expected by AAMARVA:
    AAMARVA-KEY-BINDING:v1:<AGENT_ID>:<FINGERPRINT>
    """
    if not agent_id or not isinstance(agent_id, str) or not agent_id.strip():
        raise AamarvaError("agent_id is required for identity key binding.", code="IDENTITY_KEY_INVALID")
    if not fingerprint or not isinstance(fingerprint, str) or not fingerprint.strip():
        raise AamarvaError("fingerprint is required for identity key binding.", code="IDENTITY_KEY_INVALID")
    return f"AAMARVA-KEY-BINDING:v1:{agent_id.strip().upper()}:{fingerprint.strip()}"


def sign_identity_binding(private_key: Any, agent_id: str, fingerprint: str) -> str:
    """
    Sign the identity binding string using ECDSA SHA-256 with the agent's private identity key.
    """
    binding_string = create_identity_binding_string(agent_id, fingerprint)
    try:
        priv = private_key
        if isinstance(private_key, str):
            priv = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)
        sig = priv.sign(binding_string.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(sig).decode('utf-8')
    except Exception as err:
        raise AamarvaError(f"Failed to sign identity binding: {str(err)}", code="IDENTITY_KEY_INVALID")


def verify_identity_binding(
    identity_key: Any,
    agent_id: str,
    fingerprint: str,
    signature_b64: str
) -> bool:
    """
    Verify an identity binding signature against the binding string with the identity public key.
    """
    if not signature_b64 or not isinstance(signature_b64, str):
        return False
    binding_string = create_identity_binding_string(agent_id, fingerprint)
    try:
        pub = import_public_key(identity_key)
        sig_bytes = base64.b64decode(signature_b64)
        pub.verify(sig_bytes, binding_string.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def verify_peer_key(
    peer_key: Any,
    expected_fingerprint: str,
    peer_agent_id: str,
    signature: str,
    identity_key: Any
) -> None:
    """
    Strict verification of peer public key, fingerprint, and identity signature binding.
    """
    if peer_key is None:
        raise AamarvaError("Invalid or missing peer public key.", code="PEER_KEY_UNAVAILABLE")
    if isinstance(peer_key, str) and not peer_key.strip():
        raise AamarvaError("Invalid or missing peer public key.", code="PEER_KEY_UNAVAILABLE")
    
    if not expected_fingerprint:
        raise AamarvaError("Missing expected peer fingerprint.", code="PEER_KEY_VERIFICATION_FAILED")
    
    if not peer_agent_id:
        raise AamarvaError("Missing peer agent ID.", code="PEER_KEY_VERIFICATION_FAILED")
    
    if not signature:
        raise AamarvaError("Missing peer key signature.", code="PEER_KEY_VERIFICATION_FAILED")
    
    if not identity_key:
        raise AamarvaError("Missing peer identity key.", code="PEER_KEY_VERIFICATION_FAILED")

    try:
        pub = import_public_key(peer_key)
    except Exception as err:
        if isinstance(err, AamarvaError) and err.code == "PEER_KEY_UNAVAILABLE":
            raise err
        raise AamarvaError(f"Peer key verification failed: {str(err)}", code="PEER_KEY_VERIFICATION_FAILED")

    computed_fp = compute_key_fingerprint(pub)
    if computed_fp != expected_fingerprint:
        raise AamarvaError("Peer key fingerprint verification failed (mismatch).", code="PEER_KEY_VERIFICATION_FAILED")

    try:
        import_public_key(identity_key)
    except Exception as err:
        raise AamarvaError(f"Peer identity key verification failed: {str(err)}", code="PEER_KEY_VERIFICATION_FAILED")

    is_valid = verify_identity_binding(identity_key, peer_agent_id, computed_fp, signature)
    if not is_valid:
        raise AamarvaError("Peer key identity signature verification failed.", code="PEER_KEY_VERIFICATION_FAILED")


def derive_shared_secret(local_priv, peer_key: Any) -> bytes:
    try:
        peer_pub = import_public_key(peer_key)
        priv = local_priv if isinstance(local_priv, ec.EllipticCurvePrivateKey) else get_local_identity_key()
        return priv.exchange(ec.ECDH(), peer_pub)
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to perform ECDH shared secret derivation: {str(err)}", code="MESSAGE_ENCRYPTION_FAILED")


def derive_connection_aes_key(shared_secret: bytes, connection_id: str) -> bytes:
    if not connection_id:
        raise AamarvaError("Connection ID is required for key derivation.", code="MESSAGE_ENCRYPTION_FAILED")
    try:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=connection_id.encode('utf-8'),
            info=b"aamarva-e2ee-v1",
        ).derive(shared_secret)
    except Exception as err:
        raise AamarvaError(f"Failed to derive AES key via HKDF: {str(err)}", code="MESSAGE_ENCRYPTION_FAILED")


def encrypt_message_with_keys(
    plaintext: str,
    connection_id: str,
    local_priv,
    peer_key: Any,
    expected_fingerprint: str,
    peer_agent_id: str,
    peer_signature: str,
    peer_identity_key: Any,
    key_epoch: int = 1
) -> dict:
    if not isinstance(plaintext, str):
        raise AamarvaError("Message payload must be a string.", code="MESSAGE_ENCRYPTION_FAILED")
    verify_peer_key(peer_key, expected_fingerprint, peer_agent_id, peer_signature, peer_identity_key)
    shared_secret = derive_shared_secret(local_priv, peer_key)
    aes_key = derive_connection_aes_key(shared_secret, connection_id)

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), connection_id.encode('utf-8'))

    return {
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "version": 1,
        "keyEpoch": int(key_epoch) or 1,
    }


def decrypt_message_with_keys(
    envelope: dict,
    connection_id: str,
    local_priv,
    peer_key: Any,
    expected_fingerprint: str,
    peer_agent_id: str,
    peer_signature: str,
    peer_identity_key: Any
) -> str:
    if not isinstance(envelope, dict) or not envelope.get("ciphertext") or not envelope.get("nonce"):
        raise AamarvaError("Invalid encrypted message envelope: missing ciphertext or nonce.", code="MESSAGE_INVALID_ENVELOPE")
    verify_peer_key(peer_key, expected_fingerprint, peer_agent_id, peer_signature, peer_identity_key)

    try:
        shared_secret = derive_shared_secret(local_priv, peer_key)
        aes_key = derive_connection_aes_key(shared_secret, connection_id)

        nonce = base64.b64decode(envelope["nonce"])
        combined = base64.b64decode(envelope["ciphertext"])

        if len(combined) < 16:
            raise AamarvaError("Ciphertext is too short or malformed (missing auth tag).", code="MESSAGE_INVALID_ENVELOPE")

        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, combined, connection_id.encode('utf-8'))
        return plaintext_bytes.decode('utf-8')
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to decrypt message locally: {str(err)}", code="MESSAGE_DECRYPTION_FAILED")


def encrypt_message(plaintext: str, connection_id: str, agent_id_a: str = "", agent_id_b: str = "") -> dict:
    raise AamarvaError("Use connection.send() or client.send_message() with E2EE key exchange.", code="MESSAGE_ENCRYPTION_FAILED")


def decrypt_message(envelope: dict, connection_id: str, agent_id_a: str = "", agent_id_b: str = "") -> str:
    raise AamarvaError("Use connection.get_messages() with E2EE key exchange.", code="MESSAGE_DECRYPTION_FAILED")

