import os
import re
import hmac
import math
import json
import hashlib
import base64
import datetime
from abc import ABC, abstractmethod
from typing import Optional, Union, Dict, Any, Iterable, List, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    try:
        from ._openssl_backend import (
            ec,
            x25519,
            decode_dss_signature,
            encode_dss_signature,
            serialization,
            hashes,
            HKDF,
            AESGCM,
        )
        HAS_CRYPTOGRAPHY = True
    except ImportError:
        ec = None
        x25519 = None
        decode_dss_signature = None
        encode_dss_signature = None
        serialization = None
        hashes = None
        HKDF = None
        AESGCM = None
        HAS_CRYPTOGRAPHY = False

from .errors import AamarvaError


def _require_cryptography():
    if not HAS_CRYPTOGRAPHY:
        raise AamarvaError(
            "The 'cryptography' Python package is required for E2EE cryptographic operations. "
            "Please install it using 'pip install cryptography'.",
            code="CRYPTO_DEPENDENCY_MISSING"
        )



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
        if identity_id in self._keys:
            return
        self._keys[identity_id] = private_key_pem


class FileSystemKeyStore(KeyStore):
    """
    FileSystemKeyStore persists private keys to disk with POSIX permissions (0600).
    Configurable via base_dir or AAMARVA_KEY_STORE_PATH env variable (defaults to ~/.aamarva/keys).
    """
    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.environ.get("AAMARVA_KEY_STORE_PATH") or os.path.expanduser("~/.aamarva/keys")

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
        if os.path.exists(key_path):
            return
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


def get_local_identity_key(identity_id: str = "default", epoch: Optional[int] = None) -> Any:
    _require_cryptography()
    global _cached_identity_keys, _active_key_store
    has_explicit_epoch = epoch is not None
    if has_explicit_epoch:
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            raise AamarvaError("Invalid identity key epoch: must be a positive integer >= 1.", code="IDENTITY_KEY_INVALID")

    effective_id = f"{identity_id}_epoch_{epoch}" if has_explicit_epoch else identity_id
    if effective_id in _cached_identity_keys:
        return _cached_identity_keys[effective_id]

    stored_pem = _active_key_store.load_private_key(effective_id)
    if stored_pem and isinstance(stored_pem, str) and stored_pem.strip():
        try:
            priv = serialization.load_pem_private_key(stored_pem.encode('utf-8'), password=None)
            if isinstance(priv, ec.EllipticCurvePrivateKey):
                _cached_identity_keys[effective_id] = priv
                return priv
            raise AamarvaError("Stored key is not an EC private key.", code="IDENTITY_KEY_INVALID")
        except Exception as err:
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(
                f"Failed to load stored identity key: key is corrupt or invalid format: {str(err)}",
                code="IDENTITY_KEY_INVALID"
            )

    if has_explicit_epoch:
        if epoch == 1:
            has_higher_epoch = (
                f"{identity_id}_epoch_2" in _cached_identity_keys
                or bool(_active_key_store.load_private_key(f"{identity_id}_epoch_2"))
            )
            if not has_higher_epoch:
                if identity_id in _cached_identity_keys:
                    return _cached_identity_keys[identity_id]
                active_stored = _active_key_store.load_private_key(identity_id)
                if active_stored and isinstance(active_stored, str) and active_stored.strip():
                    return get_local_identity_key(identity_id)
        raise AamarvaError(
            f'Identity key for "{identity_id}" at requested epoch {epoch} is unavailable.',
            code="IDENTITY_KEY_UNAVAILABLE",
        )

    priv = ec.generate_private_key(ec.SECP256R1())
    _cached_identity_keys[identity_id] = priv
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    _active_key_store.save_private_key(priv_pem, identity_id)
    if not _active_key_store.load_private_key(f"{identity_id}_epoch_1"):
        _active_key_store.save_private_key(priv_pem, f"{identity_id}_epoch_1")
        _cached_identity_keys[f"{identity_id}_epoch_1"] = priv
    return priv


def get_local_public_key_pem(identity_id: str = "default", epoch: Optional[int] = None) -> str:
    priv = get_local_identity_key(identity_id, epoch=epoch)
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


def import_public_key(key: Any) -> Any:
    """
    Import a P-256 EC public key from JWK dict, JSON string, PEM string, or key object.
    """
    _require_cryptography()
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


def normalize_agent_id(agent_id: Optional[str]) -> str:
    return str(agent_id or "").strip().lstrip("@").strip().upper()


def canonical_member_set(agent_ids: Iterable[str]) -> List[str]:
    cleaned = {normalize_agent_id(aid) for aid in agent_ids}
    return sorted(aid for aid in cleaned if aid)


def compute_key_fingerprint(key: Any) -> str:
    """
    Exact fingerprint calculation: SHA-256 hash of canonical P-256 JWK.
    """
    try:
        pub = import_public_key(key)
        
        # Build canonical dict
        jwk_dict = export_public_key_jwk(pub)
        
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


def compute_group_key_fingerprint(raw_key: bytes) -> str:
    """
    Compute full SHA-256 fingerprint of raw 32-byte AES cluster group key.
    Format: SHA256:AA:BB:CC:...
    """
    hash_hex = hashlib.sha256(raw_key).hexdigest().upper()
    formatted = ':'.join(hash_hex[i:i+2] for i in range(0, len(hash_hex), 2))
    return f"SHA256:{formatted}"


def compute_roster_hash(active_ids: Iterable[str]) -> str:
    canonical = canonical_member_set(active_ids)
    hash_hex = hashlib.sha256(','.join(canonical).encode('utf-8')).hexdigest().upper()
    return f"RST:{hash_hex[:32]}"


def compute_audience_hash(recipient_ids: Iterable[str], all_active_ids: Iterable[str]) -> str:
    canon_rec = canonical_member_set(recipient_ids)
    canon_all = canonical_member_set(all_active_ids)
    if not canon_rec:
        return "ALL"
    if canon_all:
        rec_set = set(canon_rec)
        if all(aid in rec_set for aid in canon_all):
            return "ALL"
    hash_hex = hashlib.sha256(','.join(canon_rec).encode('utf-8')).hexdigest().upper()
    return f"AUD:{hash_hex[:32]}"


def create_identity_binding_string(agent_id: str, fingerprint: str) -> str:
    """
    Construct the canonical identity binding string expected by AAMARVA:
    AAMARVA-KEY-BINDING:v1:<AGENT_ID>:<FINGERPRINT>
    """
    if not agent_id or not isinstance(agent_id, str) or not agent_id.strip():
        raise AamarvaError("agent_id is required for identity key binding.", code="IDENTITY_KEY_INVALID")
    if not fingerprint or not isinstance(fingerprint, str) or not fingerprint.strip():
        raise AamarvaError("fingerprint is required for identity key binding.", code="IDENTITY_KEY_INVALID")
    return f"AAMARVA-KEY-BINDING:v1:{normalize_agent_id(agent_id)}:{fingerprint.strip()}"


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


def _coerce_ec_private_key(local_priv: Any, error_code: str = "IDENTITY_KEY_INVALID") -> Any:
    if isinstance(local_priv, ec.EllipticCurvePrivateKey):
        return local_priv
    if isinstance(local_priv, str) and local_priv.strip():
        try:
            priv = serialization.load_pem_private_key(local_priv.encode("utf-8"), password=None)
            if isinstance(priv, ec.EllipticCurvePrivateKey):
                return priv
        except Exception as err:
            raise AamarvaError(f"Invalid EC private key: {str(err)}", code=error_code)
    raise AamarvaError("Valid local EC private key is required.", code=error_code)


def derive_shared_secret(local_priv, peer_key: Any) -> bytes:
    try:
        peer_pub = import_public_key(peer_key)
        priv = _coerce_ec_private_key(local_priv, error_code="IDENTITY_KEY_INVALID")
        return priv.exchange(ec.ECDH(), peer_pub)
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to perform ECDH shared secret derivation: {str(err)}", code="MESSAGE_ENCRYPTION_FAILED")


WORKFLOW_HKDF_SALT = "aamarva-e2ee-channel-v1"


def derive_connection_aes_key(shared_secret: bytes, connection_id: str) -> bytes:
    if not connection_id:
        raise AamarvaError("Connection ID is required for key derivation.", code="MESSAGE_ENCRYPTION_FAILED")
    try:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=WORKFLOW_HKDF_SALT.encode('utf-8'),
            info=f"aamarva-channel:{connection_id}".encode('utf-8'),
        ).derive(shared_secret)
    except Exception as err:
        raise AamarvaError(f"Failed to derive AES key via HKDF: {str(err)}", code="MESSAGE_ENCRYPTION_FAILED")


def create_direct_message_aad_v1(connection_id: str, sender_agent_id: Optional[str] = None) -> str:
    norm_sender = normalize_agent_id(sender_agent_id) or "AGENT"
    return f"AAMARVA:E2EE:v1:{connection_id}:{norm_sender}"


def encrypt_message_with_keys(
    plaintext: str,
    connection_id: str,
    local_priv,
    peer_key: Any,
    expected_fingerprint: str,
    peer_agent_id: str,
    peer_signature: str,
    peer_identity_key: Any,
    key_epoch: int = 1,
    sender_agent_id: Optional[str] = None,
) -> dict:
    if not isinstance(plaintext, str):
        raise AamarvaError("Message payload must be a string.", code="MESSAGE_ENCRYPTION_FAILED")
    verify_peer_key(peer_key, expected_fingerprint, peer_agent_id, peer_signature, peer_identity_key)
    shared_secret = derive_shared_secret(local_priv, peer_key)
    aes_key = derive_connection_aes_key(shared_secret, connection_id)

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    aad = create_direct_message_aad_v1(connection_id, sender_agent_id).encode('utf-8')
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad)

    if isinstance(key_epoch, bool) or not isinstance(key_epoch, int) or key_epoch < 1:
        raise AamarvaError("Direct message keyEpoch must be a positive integer >= 1.", code="MESSAGE_ENCRYPTION_FAILED")

    return {
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "version": 1,
        "keyEpoch": key_epoch,
    }


def decrypt_message_with_keys(
    envelope: dict,
    connection_id: str,
    local_priv,
    peer_key: Any,
    expected_fingerprint: str,
    peer_agent_id: str,
    peer_signature: str,
    peer_identity_key: Any,
    sender_agent_id: Optional[str] = None,
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

        resolved_sender = sender_agent_id if sender_agent_id is not None else envelope.get("senderAgentId")
        aad = create_direct_message_aad_v1(connection_id, resolved_sender).encode('utf-8')
        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, combined, aad)
        return plaintext_bytes.decode('utf-8')
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to decrypt message locally: {str(err)}", code="MESSAGE_DECRYPTION_FAILED")


def encrypt_message(plaintext: str, connection_id: str, agent_id_a: str = "", agent_id_b: str = "") -> dict:
    raise AamarvaError("Use connection.send() or client.send_message() with E2EE key exchange.", code="MESSAGE_ENCRYPTION_FAILED")


def decrypt_message(envelope: dict, connection_id: str, agent_id_a: str = "", agent_id_b: str = "") -> str:
    raise AamarvaError("Use connection.get_messages() with E2EE key exchange.", code="MESSAGE_DECRYPTION_FAILED")


# Workflow 2: Cluster Group Key Distribution, Wrapping, AAD & ECDSA Signing
def generate_cluster_key() -> bytes:
    """
    Generate a 256-bit symmetric key for cluster encryption.
    """
    _require_cryptography()
    return os.urandom(32)


def create_cluster_wrap_aad_v2(cluster_id: str, epoch: int = 1, audience_hash: str = "ALL") -> str:
    scope = f":{audience_hash}" if audience_hash and audience_hash != "ALL" else ""
    return f"aamarva-cluster-group-key:{cluster_id}:{epoch}{scope}"


def create_cluster_message_aad_v2(
    cluster_id: str,
    sender_agent_id: Optional[str] = None,
    epoch: int = 1,
    audience_hash: str = "ALL",
) -> str:
    norm_sender = normalize_agent_id(sender_agent_id) or "AGENT"
    scope = f":{audience_hash}" if audience_hash and audience_hash != "ALL" else ""
    return f"AAMARVA:E2EE:v2:{cluster_id}:{norm_sender}:{epoch}{scope}"


def create_cluster_signing_payload_v2(
    cluster_id: str,
    key_epoch: int,
    sender_agent_id: str,
    audience_hash: Optional[str],
    roster_hash: str,
    sequence: Optional[Union[str, int]],
    key_fingerprint: str,
    nonce: str,
    ciphertext: str,
) -> str:
    seq_str = "" if sequence is None else str(sequence)
    return "|".join([
        "AAMARVA:CLUSTER_MSG:v2",
        cluster_id.strip(),
        str(key_epoch),
        normalize_agent_id(sender_agent_id),
        audience_hash or "ALL",
        roster_hash,
        seq_str,
        key_fingerprint,
        nonce,
        ciphertext,
    ])


def sign_cluster_message_v2(
    private_key: Any,
    cluster_id: str,
    key_epoch: int,
    sender_agent_id: str,
    audience_hash: Optional[str],
    roster_hash: str,
    sequence: Optional[Union[str, int]],
    key_fingerprint: str,
    nonce: str,
    ciphertext: str,
) -> str:
    """
    Sign a Workflow 2 cluster message using ECDSA P-256 SHA-256 returning IEEE P1363 64-byte (r || s) Base64.
    """
    _require_cryptography()
    payload = create_cluster_signing_payload_v2(
        cluster_id=cluster_id,
        key_epoch=key_epoch,
        sender_agent_id=sender_agent_id,
        audience_hash=audience_hash,
        roster_hash=roster_hash,
        sequence=sequence,
        key_fingerprint=key_fingerprint,
        nonce=nonce,
        ciphertext=ciphertext,
    )
    try:
        priv = private_key
        if isinstance(private_key, str):
            priv = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)
        der_sig = priv.sign(payload.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        return base64.b64encode(raw_sig).decode('utf-8')
    except Exception as err:
        raise AamarvaError(f"Failed to sign cluster message: {str(err)}", code="CLUSTER_MESSAGE_SIGN_FAILED")


def verify_cluster_message_signature_v2(
    sender_public_key: Any,
    cluster_id: str,
    key_epoch: int,
    sender_agent_id: str,
    audience_hash: Optional[str],
    roster_hash: str,
    sequence: Optional[Union[str, int]],
    key_fingerprint: str,
    nonce: str,
    ciphertext: str,
    signature_b64: str,
) -> bool:
    _require_cryptography()
    if not signature_b64 or not isinstance(signature_b64, str):
        return False
    payload = create_cluster_signing_payload_v2(
        cluster_id=cluster_id,
        key_epoch=key_epoch,
        sender_agent_id=sender_agent_id,
        audience_hash=audience_hash,
        roster_hash=roster_hash,
        sequence=sequence,
        key_fingerprint=key_fingerprint,
        nonce=nonce,
        ciphertext=ciphertext,
    )
    try:
        pub = import_public_key(sender_public_key)
        sig_bytes = base64.b64decode(signature_b64)
        if len(sig_bytes) == 64:
            r = int.from_bytes(sig_bytes[:32], byteorder='big')
            s = int.from_bytes(sig_bytes[32:], byteorder='big')
            der_sig = encode_dss_signature(r, s)
            pub.verify(der_sig, payload.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(sig_bytes, payload.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def wrap_cluster_key_for_recipient(
    cluster_key: bytes,
    recipient_public_key: Any,
    sender_private_key: Any,
    cluster_id: str = "default",
    epoch: int = 1,
    audience_hash: str = "ALL",
    roster_hash: Optional[str] = None,
    key_fingerprint: Optional[str] = None,
    sender_agent_id: Optional[str] = None,
    sender_public_key: Optional[Any] = None,
    recipient_agent_id: Optional[str] = None,
    recipient_key_fingerprint: Optional[str] = None,
    recipient_key_epoch: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Wrap cluster symmetric key for a recipient using Workflow 2 HKDF-SHA256 and AES-256-GCM AAD.
    """
    _require_cryptography()
    recipient_pub = import_public_key(recipient_public_key)
    sender_priv = _coerce_ec_private_key(sender_private_key, error_code="IDENTITY_KEY_INVALID")

    hkdf_salt = WORKFLOW_HKDF_SALT
    hkdf_info = f"aamarva-channel:{cluster_id}"
    wrap_aad = create_cluster_wrap_aad_v2(cluster_id, epoch, audience_hash or "ALL")
    resolved_fp = key_fingerprint or compute_group_key_fingerprint(cluster_key)

    shared_secret = sender_priv.exchange(ec.ECDH(), recipient_pub)
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt.encode('utf-8'),
        info=hkdf_info.encode('utf-8'),
    ).derive(shared_secret)

    iv = os.urandom(12)
    aesgcm = AESGCM(wrap_key)
    ciphertext_with_tag = aesgcm.encrypt(iv, cluster_key, wrap_aad.encode('utf-8'))
    ct_b64 = base64.b64encode(ciphertext_with_tag).decode("utf-8")
    iv_b64 = base64.b64encode(iv).decode("utf-8")

    sender_pub_jwk = sender_public_key or export_public_key_jwk(sender_priv.public_key())
    package_obj: Dict[str, Any] = {
        "iv": iv_b64,
        "key": ct_b64,
        "epoch": epoch,
        "clusterId": cluster_id,
        "audienceHash": audience_hash or "ALL",
        "keyFingerprint": resolved_fp,
        "aad": wrap_aad,
        "hkdfSalt": hkdf_salt,
        "hkdfInfo": hkdf_info,
    }
    if roster_hash:
        package_obj["rosterHash"] = roster_hash
    if sender_agent_id:
        package_obj["senderAgentId"] = sender_agent_id
    if sender_pub_jwk:
        package_obj["senderPublicKey"] = sender_pub_jwk
    if recipient_agent_id:
        package_obj["recipientAgentId"] = recipient_agent_id
    if recipient_key_fingerprint:
        package_obj["recipientKeyFingerprint"] = recipient_key_fingerprint
    if recipient_key_epoch is not None:
        package_obj["recipientKeyEpoch"] = recipient_key_epoch

    return {
        "encryptedKeyPackage": package_obj,
        "nonce": iv_b64,
        "ciphertext": ct_b64,
        "keyFingerprint": resolved_fp,
        "aad": wrap_aad,
        "wrappingParams": {
            "algorithm": "ECDH-ES+HKDF-256+A256GCM",
            "alg": "ECDH-ES+A256GCM",
            "curve": "P-256",
            "hkdfHash": "SHA-256",
            "hkdfSalt": hkdf_salt,
            "hkdfInfo": hkdf_info,
            "aad": wrap_aad,
        },
    }


def unwrap_cluster_key(
    encrypted_key_package: Union[str, Dict[str, Any]],
    nonce_b64: str,
    recipient_private_key: Any,
    sender_public_key: Any,
    cluster_id: Optional[str] = None,
    epoch: Optional[int] = None,
    audience_hash: Optional[str] = None,
    expected_key_fingerprint: Optional[str] = None,
    aad: Optional[str] = None,
    hkdf_salt: Optional[str] = None,
    hkdf_info: Optional[str] = None,
    recipient_agent_id: Optional[str] = None,
    wrapping_params: Optional[Dict[str, Any]] = None,
) -> bytes:
    """
    Unwrap cluster symmetric key using Workflow 2 HKDF-SHA256, AAD, and fingerprint verification.
    """
    _require_cryptography()
    if not cluster_id or not isinstance(cluster_id, str) or not cluster_id.strip():
        raise AamarvaError("Cluster ID is required to unwrap cluster key.", code="CLUSTER_KEY_UNWRAP_FAILED")
    clean_cluster_id = cluster_id.strip()

    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise AamarvaError("Valid positive integer epoch is required to unwrap cluster key.", code="CLUSTER_KEY_UNWRAP_FAILED")

    clean_audience = audience_hash.strip() if isinstance(audience_hash, str) else ""
    if not clean_audience or (clean_audience != "ALL" and not re.match(r"^AUD:[0-9A-F]{32}$", clean_audience)):
        raise AamarvaError("Valid audienceHash (ALL or AUD:<32-HEX>) is required to unwrap cluster key.", code="CLUSTER_KEY_UNWRAP_FAILED")

    pkg_obj: Optional[Dict[str, Any]] = None
    if isinstance(encrypted_key_package, dict):
        pkg_obj = encrypted_key_package
    elif isinstance(encrypted_key_package, str) and encrypted_key_package.strip().startswith('{'):
        try:
            parsed_pkg = json.loads(encrypted_key_package)
            if not isinstance(parsed_pkg, dict):
                raise ValueError("package JSON must be an object")
            pkg_obj = parsed_pkg
        except Exception as err:
            raise AamarvaError("Malformed JSON in encryptedKeyPackage.", code="CLUSTER_KEY_UNWRAP_FAILED") from err

    ct_b64 = str((pkg_obj or {}).get("key") or (pkg_obj or {}).get("ciphertext") or (encrypted_key_package if isinstance(encrypted_key_package, str) else ""))
    iv_b64 = str((pkg_obj or {}).get("iv") or nonce_b64 or "")
    if not ct_b64 or not iv_b64:
        raise AamarvaError("Cluster key package is missing ciphertext or iv/nonce.", code="CLUSTER_KEY_UNWRAP_FAILED")

    resolved_salt = hkdf_salt or WORKFLOW_HKDF_SALT
    resolved_info = hkdf_info or f"aamarva-channel:{clean_cluster_id}"
    resolved_aad = aad or create_cluster_wrap_aad_v2(clean_cluster_id, epoch, clean_audience)

    # Fail closed if untrusted package metadata contradicts expected context
    if pkg_obj is not None:
        if pkg_obj.get("clusterId") is not None and str(pkg_obj.get("clusterId")).strip() != clean_cluster_id:
            raise AamarvaError("Wrapped cluster key package clusterId mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if pkg_obj.get("epoch") is not None:
            pkg_epoch = pkg_obj.get("epoch")
            if isinstance(pkg_epoch, bool) or not isinstance(pkg_epoch, int) or pkg_epoch != epoch:
                raise AamarvaError("Wrapped cluster key package epoch mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if pkg_obj.get("audienceHash") is not None and str(pkg_obj.get("audienceHash")) != clean_audience:
            raise AamarvaError("Wrapped cluster key package audienceHash mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if pkg_obj.get("hkdfSalt") is not None and str(pkg_obj.get("hkdfSalt")) != resolved_salt:
            raise AamarvaError("Wrapped cluster key package hkdfSalt mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if pkg_obj.get("hkdfInfo") is not None and str(pkg_obj.get("hkdfInfo")) != resolved_info:
            raise AamarvaError("Wrapped cluster key package hkdfInfo mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if pkg_obj.get("aad") is not None and str(pkg_obj.get("aad")) != resolved_aad:
            raise AamarvaError("Wrapped cluster key package AAD metadata mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if recipient_agent_id and pkg_obj.get("recipientAgentId") is not None:
            if normalize_agent_id(str(pkg_obj.get("recipientAgentId"))) != normalize_agent_id(recipient_agent_id):
                raise AamarvaError("Wrapped cluster key package recipientAgentId mismatch.", code="RECIPIENT_KEY_MISMATCH")

    if wrapping_params is not None:
        if not isinstance(wrapping_params, dict):
            raise AamarvaError("Malformed wrappingParams object.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if wrapping_params.get("algorithm") is not None and wrapping_params.get("algorithm") != "ECDH-ES+HKDF-256+A256GCM":
            raise AamarvaError(f"Unsupported wrapping algorithm: {wrapping_params.get('algorithm')}", code="CLUSTER_KEY_UNWRAP_FAILED")
        if wrapping_params.get("curve") is not None and wrapping_params.get("curve") != "P-256":
            raise AamarvaError(f"Unsupported wrapping curve: {wrapping_params.get('curve')}", code="CLUSTER_KEY_UNWRAP_FAILED")
        if wrapping_params.get("hkdfHash") is not None and wrapping_params.get("hkdfHash") != "SHA-256":
            raise AamarvaError(f"Unsupported HKDF hash: {wrapping_params.get('hkdfHash')}", code="CLUSTER_KEY_UNWRAP_FAILED")
        if wrapping_params.get("hkdfSalt") is not None and str(wrapping_params.get("hkdfSalt")) != resolved_salt:
            raise AamarvaError("Wrapping params hkdfSalt mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if wrapping_params.get("hkdfInfo") is not None and str(wrapping_params.get("hkdfInfo")) != resolved_info:
            raise AamarvaError("Wrapping params hkdfInfo mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
        if wrapping_params.get("aad") is not None and str(wrapping_params.get("aad")) != resolved_aad:
            raise AamarvaError("Wrapping params AAD mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")

    if recipient_private_key is None:
        raise AamarvaError("Recipient private key is required to unwrap cluster key.", code="CLUSTER_KEY_UNWRAP_FAILED")

    sender_pub = import_public_key(sender_public_key)
    recipient_priv = _coerce_ec_private_key(recipient_private_key, error_code="CLUSTER_KEY_UNWRAP_FAILED")

    shared_secret = recipient_priv.exchange(ec.ECDH(), sender_pub)
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=resolved_salt.encode('utf-8'),
        info=resolved_info.encode('utf-8'),
    ).derive(shared_secret)

    try:
        iv = base64.b64decode(iv_b64)
        combined = base64.b64decode(ct_b64)
        if len(iv) != 12 or len(combined) < 16:
            raise AamarvaError("Cluster key package nonce or ciphertext is malformed.", code="CLUSTER_KEY_UNWRAP_FAILED")
        aesgcm = AESGCM(wrap_key)
        raw_key = aesgcm.decrypt(iv, combined, resolved_aad.encode('utf-8') if resolved_aad else None)
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to unwrap cluster key: {str(err)}", code="CLUSTER_KEY_UNWRAP_FAILED")

    if len(raw_key) != 32:
        raise AamarvaError("Unwrapped cluster key has invalid length (expected 32 bytes).", code="CLUSTER_KEY_UNWRAP_FAILED")

    pkg_fp = (pkg_obj or {}).get("keyFingerprint") if isinstance((pkg_obj or {}).get("keyFingerprint"), str) else None
    if expected_key_fingerprint and pkg_fp and expected_key_fingerprint != pkg_fp:
        raise AamarvaError("Cluster key fingerprint mismatch between expected value and package metadata.", code="CLUSTER_KEY_FINGERPRINT_MISMATCH")

    fp_check = expected_key_fingerprint or pkg_fp
    if fp_check is not None:
        if not isinstance(fp_check, str) or not re.match(r"^SHA256:([0-9A-F]{2}:){31}[0-9A-F]{2}$", fp_check):
            raise AamarvaError(f"Malformed cluster key fingerprint format: {fp_check}", code="CLUSTER_KEY_FINGERPRINT_MISMATCH")
        actual_fp = compute_group_key_fingerprint(raw_key)
        if actual_fp != fp_check:
            raise AamarvaError(
                f"Cluster group key fingerprint mismatch: expected {fp_check}, got {actual_fp}.",
                code="CLUSTER_KEY_FINGERPRINT_MISMATCH",
            )

    return raw_key


def encrypt_cluster_message(
    plaintext: str,
    cluster_key: bytes,
    cluster_id: str,
    epoch: int = 1,
    audience_hash: str = "ALL",
    sender_agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Encrypt cluster message using symmetric cluster key and AES-256-GCM with Workflow 2 AAD.
    """
    _require_cryptography()
    if not isinstance(plaintext, str):
        raise AamarvaError("Cluster message plaintext must be a string.", code="MESSAGE_ENCRYPTION_FAILED")

    iv = os.urandom(12)
    aesgcm = AESGCM(cluster_key)
    aad = create_cluster_message_aad_v2(cluster_id, sender_agent_id, epoch, audience_hash or "ALL").encode("utf-8")
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), aad)

    return {
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode("utf-8"),
        "nonce": base64.b64encode(iv).decode("utf-8"),
        "version": 2,
        "keyEpoch": epoch,
        "audienceHash": audience_hash or "ALL",
    }


def decrypt_cluster_message(
    ciphertext_b64: str,
    nonce_b64: str,
    cluster_key: bytes,
    cluster_id: str,
    epoch: int = 1,
    version: int = 2,
    audience_hash: str = "ALL",
    sender_agent_id: Optional[str] = None,
) -> str:
    """
    Decrypt cluster message using symmetric cluster key and AES-256-GCM with Workflow 2 AAD.
    """
    _require_cryptography()
    try:
        iv = base64.b64decode(nonce_b64)
        combined = base64.b64decode(ciphertext_b64)
        if len(combined) < 16:
            raise AamarvaError("Cluster ciphertext is too short or malformed.", code="CLUSTER_MESSAGE_DECRYPTION_FAILED")

        aesgcm = AESGCM(cluster_key)
        aad = create_cluster_message_aad_v2(cluster_id, sender_agent_id, epoch, audience_hash or "ALL").encode("utf-8")
        decrypted_bytes = aesgcm.decrypt(iv, combined, aad)
        return decrypted_bytes.decode("utf-8")
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to decrypt cluster message: {str(err)}", code="CLUSTER_MESSAGE_DECRYPTION_FAILED")


# =============================================================================
# Mandatory MCP Adapter Gateway Cryptography (P-256 + RFC 9180 HPKE + ECDSA)
# =============================================================================

GATEWAY_PROTOCOL_VERSION = "aamarva.gateway.v1"
GATEWAY_HPKE_KEM = "DHKEM(P-256, HKDF-SHA256)"
GATEWAY_HPKE_KDF = "HKDF-SHA256"
GATEWAY_HPKE_AEAD = "AES-256-GCM"
GATEWAY_HPKE_SUITE = {
    "kem": GATEWAY_HPKE_KEM,
    "kdf": GATEWAY_HPKE_KDF,
    "aead": GATEWAY_HPKE_AEAD,
}

_HPKE_KEM_SUITE_ID = b"KEM\x00\x10"
_HPKE_SUITE_ID = b"HPKE\x00\x10\x00\x01\x00\x02"


def canonical_json_stringify(obj: Any) -> str:
    if obj is None or isinstance(obj, (bool, int, str)):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, float):
        if obj == 0.0 and math.copysign(1.0, obj) < 0:
            return "0"
        if obj.is_integer():
            return str(int(obj))
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical_json_stringify(item) for item in obj) + "]"
    if isinstance(obj, dict):
        items = []
        for k in sorted(obj.keys(), key=lambda key: str(key)):
            items.append(f"{json.dumps(str(k), ensure_ascii=False)}:{canonical_json_stringify(obj[k])}")
        return "{" + ",".join(items) + "}"
    return json.dumps(obj, ensure_ascii=False)


def sha256_hex(data: Union[str, bytes, bytearray]) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return hashlib.sha256(raw).hexdigest().lower()


def compute_args_digest(args: Optional[Dict[str, Any]] = None) -> str:
    return f"sha256:{sha256_hex(canonical_json_stringify(args or {}))}"


def _p256_sign_p1363(private_key: Any, payload: bytes, error_code: str = "IDENTITY_KEY_INVALID") -> str:
    _require_cryptography()
    try:
        priv = _coerce_ec_private_key(private_key, error_code=error_code)
        der_sig = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
        return base64.b64encode(raw_sig).decode("ascii")
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"ECDSA P-256 signing failed: {str(err)}", code=error_code)


def _p256_verify_sig(public_key: Any, payload: bytes, signature_b64: str) -> bool:
    if not signature_b64 or not isinstance(signature_b64, str):
        return False
    _require_cryptography()
    try:
        pub = import_public_key(public_key)
        sig_bytes = base64.b64decode(signature_b64)
        if len(sig_bytes) == 64:
            r = int.from_bytes(sig_bytes[:32], byteorder="big")
            s = int.from_bytes(sig_bytes[32:], byteorder="big")
            der_sig = encode_dss_signature(r, s)
            pub.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(sig_bytes, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _export_p256_uncompressed_point(key: Any) -> bytes:
    pub = import_public_key(key)
    pn = pub.public_numbers()
    x = pn.x.to_bytes(32, byteorder="big")
    y = pn.y.to_bytes(32, byteorder="big")
    return b"\x04" + x + y


def _coerce_p256_private_key(key: Any, error_code: str = "TOKEN_DECRYPTION_FAILED") -> Any:
    _require_cryptography()
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise AamarvaError("Private key must be P-256.", code=error_code)
        return key
    if isinstance(key, dict) and "private_key" in key and isinstance(key["private_key"], ec.EllipticCurvePrivateKey):
        return key["private_key"]
    if isinstance(key, str) and key.strip():
        try:
            priv = serialization.load_pem_private_key(key.strip().encode("utf-8"), password=None)
            if isinstance(priv, ec.EllipticCurvePrivateKey):
                return priv
        except Exception:
            pass
    raise AamarvaError("Valid local P-256 private key is required.", code=error_code)


def create_aamarva_identity_assertion_payload(assertion: Dict[str, Any]) -> str:
    norm_agent_id = normalize_agent_id(assertion.get("agentId"))
    agent_name = str(assertion.get("agentName", "")).strip()
    pub_key = assertion.get("agentPublicKey")
    if not norm_agent_id or not agent_name or not pub_key:
        raise AamarvaError("AAMARVA identity assertion requires agentPublicKey, agentId, and agentName.", code="AAMARVA_ASSERTION_INVALID")
    pub_jwk = export_public_key_jwk(pub_key)
    if pub_jwk.get("kty") != "EC" or pub_jwk.get("crv") != "P-256":
        raise AamarvaError("AAMARVA identity assertion requires a valid P-256 agentPublicKey.", code="AAMARVA_ASSERTION_INVALID")
    return canonical_json_stringify({
        "agentPublicKey": pub_jwk,
        "agentId": norm_agent_id,
        "agentName": agent_name,
    })


def sign_aamarva_identity_assertion(aamarva_private_key: Any, assertion: Dict[str, Any]) -> str:
    payload = create_aamarva_identity_assertion_payload(assertion)
    return _p256_sign_p1363(aamarva_private_key, payload.encode("utf-8"), error_code="AAMARVA_ASSERTION_INVALID")


def verify_aamarva_identity_assertion(trusted_aamarva_public_key: Any, assertion: Dict[str, Any]) -> bool:
    if not isinstance(assertion, dict) or not isinstance(assertion.get("signature"), str) or not assertion["signature"].strip():
        return False
    try:
        payload = create_aamarva_identity_assertion_payload(assertion)
        return _p256_verify_sig(trusted_aamarva_public_key, payload.encode("utf-8"), assertion["signature"])
    except Exception:
        return False


def create_gateway_token_aad(params: Dict[str, Any]) -> str:
    return "|".join([
        "AAMARVA:GW_TOKEN:v1",
        str(params.get("version", "")),
        str(params.get("gatewayId", "")),
        normalize_agent_id(params.get("agentId")),
        str(params.get("agentName", "")).strip(),
        str(params.get("agentPublicKeyFingerprint", "")),
        str(params.get("mcpServerId", "")),
        str(params.get("toolId", "")),
        str(params.get("approvedArgsDigest", "")),
        str(params.get("iat", "")),
        str(params.get("exp", "")),
    ])


def create_gateway_token_info(gateway_id: str, agent_id: str) -> str:
    return f"AAMARVA-GATEWAY-HPKE-v1:{gateway_id}:{normalize_agent_id(agent_id)}"


def create_gateway_envelope_signing_payload(envelope: Dict[str, Any]) -> str:
    payload: Dict[str, Any] = {
        "version": envelope.get("version"),
        "suite": envelope.get("suite"),
        "gatewayId": envelope.get("gatewayId"),
        "gatewayKeyId": envelope.get("gatewayKeyId"),
        "gatewayUrl": envelope.get("gatewayUrl"),
        "agentId": normalize_agent_id(envelope.get("agentId")),
        "agentName": str(envelope.get("agentName", "")).strip(),
        "agentPublicKeyFingerprint": envelope.get("agentPublicKeyFingerprint"),
        "mcpServerId": envelope.get("mcpServerId"),
        "toolId": envelope.get("toolId"),
        "approvedArgsDigest": envelope.get("approvedArgsDigest"),
        "iat": envelope.get("iat"),
        "exp": envelope.get("exp"),
        "enc": envelope.get("enc"),
        "ciphertext": envelope.get("ciphertext"),
        "aad": envelope.get("aad"),
        "info": envelope.get("info"),
    }
    if envelope.get("scope") is not None:
        payload["scope"] = envelope["scope"]
    return canonical_json_stringify(payload)


def verify_gateway_envelope_signature(trusted_gateway_public_key: Any, envelope: Dict[str, Any]) -> bool:
    if not isinstance(envelope, dict) or not isinstance(envelope.get("gatewaySignature"), str) or not envelope["gatewaySignature"]:
        return False
    try:
        payload = create_gateway_envelope_signing_payload(envelope)
        return _p256_verify_sig(trusted_gateway_public_key, payload.encode("utf-8"), envelope["gatewaySignature"])
    except Exception:
        return False


def _hpke_labeled_extract(salt: bytes, suite_id: bytes, label: bytes, ikm: bytes) -> bytes:
    actual_salt = salt if salt else b"\x00" * 32
    labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
    return hmac.new(actual_salt, labeled_ikm, hashlib.sha256).digest()


def _hpke_labeled_expand(prk: bytes, suite_id: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info
    okm = bytearray()
    t = b""
    n = (length + 31) // 32
    for i in range(1, n + 1):
        t = hmac.new(prk, t + labeled_info + bytes([i]), hashlib.sha256).digest()
        okm.extend(t)
    return bytes(okm[:length])


def _dhkem_p256_extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _hpke_labeled_extract(b"", _HPKE_KEM_SUITE_ID, b"eae_prk", dh)
    return _hpke_labeled_expand(eae_prk, _HPKE_KEM_SUITE_ID, b"shared_secret", kem_context, 32)


def _hpke_key_schedule_base(shared_secret: bytes, info: bytes) -> Tuple[bytes, bytes]:
    psk_id_hash = _hpke_labeled_extract(b"", _HPKE_SUITE_ID, b"psk_id_hash", b"")
    info_hash = _hpke_labeled_extract(b"", _HPKE_SUITE_ID, b"info_hash", info)
    ks_context = b"\x00" + psk_id_hash + info_hash
    secret = _hpke_labeled_extract(shared_secret, _HPKE_SUITE_ID, b"secret", b"")
    key = _hpke_labeled_expand(secret, _HPKE_SUITE_ID, b"key", ks_context, 32)
    base_nonce = _hpke_labeled_expand(secret, _HPKE_SUITE_ID, b"base_nonce", ks_context, 12)
    return key, base_nonce


def hpke_seal_base(
    recipient_public_key: Any,
    plaintext: bytes,
    aad: bytes = b"",
    info: bytes = b"",
) -> Tuple[bytes, bytes]:
    _require_cryptography()
    pk_r = import_public_key(recipient_public_key)
    pk_rm = _export_p256_uncompressed_point(pk_r)

    sk_e = ec.generate_private_key(ec.SECP256R1())
    enc = _export_p256_uncompressed_point(sk_e.public_key())
    dh = sk_e.exchange(ec.ECDH(), pk_r)
    if not dh or dh == b"\x00" * len(dh):
        raise AamarvaError("HPKE P-256 derived invalid all-zero shared secret.", code="TOKEN_ENCRYPTION_FAILED")

    shared_secret = _dhkem_p256_extract_and_expand(dh, enc + pk_rm)
    key, nonce = _hpke_key_schedule_base(shared_secret, info)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return enc, ciphertext


def hpke_open_base(
    recipient_private_key: Any,
    enc: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
    info: bytes = b"",
) -> bytes:
    _require_cryptography()
    if not isinstance(enc, (bytes, bytearray)) or len(enc) != 65 or enc[0] != 0x04 or bytes(enc) == b"\x00" * 65:
        raise AamarvaError("Invalid HPKE encapsulated secret length or value.", code="TOKEN_DECRYPTION_FAILED")
    sk_r = _coerce_p256_private_key(recipient_private_key, error_code="TOKEN_DECRYPTION_FAILED")
    pk_rm = _export_p256_uncompressed_point(sk_r.public_key())
    pk_e = import_public_key(bytes(enc))
    dh = sk_r.exchange(ec.ECDH(), pk_e)
    if not dh or dh == b"\x00" * len(dh):
        raise AamarvaError("HPKE P-256 derived invalid all-zero shared secret.", code="TOKEN_DECRYPTION_FAILED")

    shared_secret = _dhkem_p256_extract_and_expand(dh, bytes(enc) + pk_rm)
    key, nonce = _hpke_key_schedule_base(shared_secret, info)
    return AESGCM(key).decrypt(nonce, ciphertext, aad or None)


def seal_gateway_token_envelope(
    token_payload: Dict[str, Any],
    agent_public_key: Any,
    gateway_signing_private_key: Any,
    gateway_key_id: str,
    gateway_public_key: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    computed_fp = compute_key_fingerprint(agent_public_key)
    if token_payload.get("agentPublicKeyFingerprint") and token_payload["agentPublicKeyFingerprint"] != computed_fp:
        raise AamarvaError("Token payload agentPublicKeyFingerprint does not match target P-256 agentPublicKey.", code="GATEWAY_ENVELOPE_INVALID")
    normalized_payload = dict(token_payload)
    normalized_payload["agentPublicKeyFingerprint"] = computed_fp

    aad_str = create_gateway_token_aad(normalized_payload)
    info_str = create_gateway_token_info(normalized_payload["gatewayId"], normalized_payload["agentId"])
    pt_bytes = canonical_json_stringify(normalized_payload).encode("utf-8")

    enc, ciphertext = hpke_seal_base(
        agent_public_key,
        pt_bytes,
        aad=aad_str.encode("utf-8"),
        info=info_str.encode("utf-8"),
    )

    unsigned_envelope: Dict[str, Any] = {
        "version": normalized_payload["version"],
        "suite": dict(GATEWAY_HPKE_SUITE),
        "gatewayId": normalized_payload["gatewayId"],
        "gatewayKeyId": gateway_key_id,
        "gatewayUrl": normalized_payload["gatewayUrl"],
        "agentId": normalized_payload["agentId"],
        "agentName": str(normalized_payload.get("agentName", "")).strip(),
        "agentPublicKeyFingerprint": computed_fp,
        "mcpServerId": normalized_payload["mcpServerId"],
        "toolId": normalized_payload["toolId"],
        "approvedArgsDigest": normalized_payload["approvedArgsDigest"],
        "iat": normalized_payload["iat"],
        "exp": normalized_payload["exp"],
        "enc": base64.b64encode(enc).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": aad_str,
        "info": info_str,
    }
    if gateway_public_key is not None:
        unsigned_envelope["gatewayPublicKey"] = gateway_public_key
    if normalized_payload.get("scope") is not None:
        unsigned_envelope["scope"] = normalized_payload["scope"]

    signing_payload = create_gateway_envelope_signing_payload(unsigned_envelope)
    sig = _p256_sign_p1363(
        gateway_signing_private_key,
        signing_payload.encode("utf-8"),
        error_code="TOKEN_ENCRYPTION_FAILED",
    )
    unsigned_envelope["gatewaySignature"] = sig
    return unsigned_envelope


def _resolve_trusted_gateway_key(trusted_keys: Any, envelope: Dict[str, Any]) -> Any:
    if not trusted_keys:
        return None
    if isinstance(trusted_keys, str) or (isinstance(trusted_keys, dict) and trusted_keys.get("kty") == "EC"):
        return trusted_keys
    if isinstance(trusted_keys, dict):
        gk_id = envelope.get("gatewayKeyId")
        if gk_id and gk_id in trusted_keys:
            return trusted_keys[gk_id]
        g_id = envelope.get("gatewayId")
        if g_id and g_id in trusted_keys:
            return trusted_keys[g_id]
    return None


def _parse_iso_dt(raw: Any) -> Optional[datetime.datetime]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        s = raw.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None


def open_gateway_token_envelope(
    envelope: Dict[str, Any],
    agent_encryption_key: Any,
    trusted_gateway_public_keys: Any,
    expected_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if not isinstance(envelope, dict):
        raise AamarvaError("Malformed gateway token envelope.", code="GATEWAY_ENVELOPE_INVALID")
    if envelope.get("version") != GATEWAY_PROTOCOL_VERSION:
        raise AamarvaError(f"Unsupported gateway protocol version: {envelope.get('version')}.", code="GATEWAY_ENVELOPE_INVALID")

    suite = envelope.get("suite")
    if (
        not isinstance(suite, dict)
        or suite.get("kem") != GATEWAY_HPKE_KEM
        or suite.get("kdf") != GATEWAY_HPKE_KDF
        or suite.get("aead") != GATEWAY_HPKE_AEAD
    ):
        raise AamarvaError("Unsupported or missing HPKE suite in gateway token envelope.", code="GATEWAY_ENVELOPE_INVALID")

    trusted_key = _resolve_trusted_gateway_key(trusted_gateway_public_keys, envelope)
    if not trusted_key:
        raise AamarvaError(
            f'No trusted gateway public key found for gatewayKeyId="{envelope.get("gatewayKeyId", "")}" / gatewayId="{envelope.get("gatewayId", "")}".',
            code="GATEWAY_UNTRUSTED_KEY",
        )
    if not verify_gateway_envelope_signature(trusted_key, envelope):
        raise AamarvaError("Gateway token envelope signature verification failed.", code="GATEWAY_SIGNATURE_INVALID")

    expected_aad = create_gateway_token_aad(envelope)
    expected_info = create_gateway_token_info(str(envelope.get("gatewayId", "")), str(envelope.get("agentId", "")))
    if envelope.get("aad") != expected_aad or envelope.get("info") != expected_info:
        raise AamarvaError("Gateway token envelope AAD or HPKE info metadata mismatch.", code="GATEWAY_ENVELOPE_INVALID")

    exp_dt = _parse_iso_dt(envelope.get("exp"))
    if not exp_dt or exp_dt <= datetime.datetime.now(datetime.timezone.utc):
        raise AamarvaError("Gateway token envelope has expired.", code="GATEWAY_TOKEN_EXPIRED")

    ctx = expected_context or {}
    if ctx.get("gatewayId") and envelope.get("gatewayId") != ctx["gatewayId"]:
        raise AamarvaError("Gateway token envelope gatewayId mismatch.", code="GATEWAY_ENVELOPE_INVALID")
    if ctx.get("gatewayUrl") and envelope.get("gatewayUrl") != ctx["gatewayUrl"]:
        raise AamarvaError("Gateway token envelope gatewayUrl mismatch.", code="GATEWAY_ENVELOPE_INVALID")
    if ctx.get("agentId") and normalize_agent_id(envelope.get("agentId")) != normalize_agent_id(ctx["agentId"]):
        raise AamarvaError("Gateway token envelope agentId mismatch.", code="AGENT_IDENTITY_MISMATCH")
    if ctx.get("agentName") and str(envelope.get("agentName", "")).strip() != str(ctx["agentName"]).strip():
        raise AamarvaError("Gateway token envelope agentName mismatch.", code="AGENT_IDENTITY_MISMATCH")
    if ctx.get("agentPublicKeyFingerprint") and envelope.get("agentPublicKeyFingerprint") != ctx["agentPublicKeyFingerprint"]:
        raise AamarvaError("Gateway token envelope agentPublicKeyFingerprint mismatch.", code="AGENT_IDENTITY_MISMATCH")
    if ctx.get("mcpServerId") and envelope.get("mcpServerId") != ctx["mcpServerId"]:
        raise AamarvaError("Gateway token envelope mcpServerId mismatch.", code="GATEWAY_ENVELOPE_INVALID")
    if ctx.get("toolId") and envelope.get("toolId") != ctx["toolId"]:
        raise AamarvaError("Gateway token envelope toolId mismatch.", code="GATEWAY_ENVELOPE_INVALID")
    if ctx.get("approvedArgsDigest") and envelope.get("approvedArgsDigest") != ctx["approvedArgsDigest"]:
        raise AamarvaError("Gateway token envelope approvedArgsDigest mismatch.", code="GATEWAY_ENVELOPE_INVALID")

    local_priv = _coerce_p256_private_key(agent_encryption_key, error_code="TOKEN_DECRYPTION_FAILED")
    local_fp = compute_key_fingerprint(local_priv.public_key())
    if envelope.get("agentPublicKeyFingerprint") and envelope["agentPublicKeyFingerprint"] != local_fp:
        raise AamarvaError("Gateway token envelope is sealed to a different agent P-256 public key.", code="TOKEN_DECRYPTION_FAILED")

    try:
        enc_bytes = base64.b64decode(envelope["enc"])
        ct_bytes = base64.b64decode(envelope["ciphertext"])
        plaintext_bytes = hpke_open_base(
            local_priv,
            enc_bytes,
            ct_bytes,
            aad=expected_aad.encode("utf-8"),
            info=expected_info.encode("utf-8"),
        )
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"RFC 9180 HPKE token decryption failed: {str(err)}", code="TOKEN_DECRYPTION_FAILED")

    try:
        payload = json.loads(plaintext_bytes.decode("utf-8"))
    except Exception as err:
        raise AamarvaError("Decrypted gateway token payload is not valid JSON.", code="TOKEN_DECRYPTION_FAILED") from err

    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("token"), str)
        or not payload["token"].strip()
        or payload.get("version") != envelope.get("version")
        or payload.get("gatewayId") != envelope.get("gatewayId")
        or payload.get("gatewayUrl") != envelope.get("gatewayUrl")
        or normalize_agent_id(payload.get("agentId")) != normalize_agent_id(envelope.get("agentId"))
        or str(payload.get("agentName", "")).strip() != str(envelope.get("agentName", "")).strip()
        or payload.get("agentPublicKeyFingerprint") != envelope.get("agentPublicKeyFingerprint")
        or payload.get("mcpServerId") != envelope.get("mcpServerId")
        or payload.get("toolId") != envelope.get("toolId")
        or payload.get("approvedArgsDigest") != envelope.get("approvedArgsDigest")
    ):
        raise AamarvaError("Decrypted gateway token claims do not match envelope metadata.", code="TOKEN_CLAIM_MISMATCH")

    payload_exp = _parse_iso_dt(payload.get("exp"))
    if not payload_exp or payload_exp <= datetime.datetime.now(datetime.timezone.utc):
        raise AamarvaError("Decrypted gateway token has expired.", code="GATEWAY_TOKEN_EXPIRED")

    return payload


def create_gateway_pop_signing_payload(params: Dict[str, Any]) -> str:
    return "|".join([
        "AAMARVA:GW_POP:v1",
        str(params.get("version", "")),
        str(params.get("tokenSha256", "")),
        str(params.get("gatewayId", "")),
        normalize_agent_id(params.get("agentId")),
        str(params.get("mcpServerId", "")),
        str(params.get("toolId", "")),
        str(params.get("approvedArgsDigest", "")),
        str(params.get("nonce", "")),
        str(params.get("timestamp", "")),
    ])


def sign_gateway_pop(identity_private_key: Any, params: Dict[str, Any]) -> str:
    payload = create_gateway_pop_signing_payload(params)
    return _p256_sign_p1363(identity_private_key, payload.encode("utf-8"), error_code="GATEWAY_POP_SIGN_FAILED")


def verify_gateway_pop(identity_public_key: Any, params: Dict[str, Any], signature_b64: str) -> bool:
    if not signature_b64 or not isinstance(signature_b64, str):
        return False
    try:
        payload = create_gateway_pop_signing_payload(params)
        return _p256_verify_sig(identity_public_key, payload.encode("utf-8"), signature_b64)
    except Exception:
        return False


def create_gateway_instruction_signing_payload(inst: Dict[str, Any]) -> str:
    return canonical_json_stringify({
        "version": inst.get("version"),
        "instructionId": inst.get("instructionId"),
        "issuer": inst.get("issuer"),
        "audience": inst.get("audience"),
        "gatewayId": inst.get("gatewayId"),
        "agentId": normalize_agent_id(inst.get("agentId")),
        "agentKeyId": inst.get("agentKeyId"),
        "agentKeyVersion": inst.get("agentKeyVersion"),
        "invocationId": inst.get("invocationId"),
        "mcpServerId": inst.get("mcpServerId"),
        "toolId": inst.get("toolId"),
        "approvedArgsDigest": inst.get("approvedArgsDigest"),
        "decision": inst.get("decision"),
        "iat": inst.get("iat"),
        "exp": inst.get("exp"),
    })


def sign_gateway_instruction(private_key: Any, inst: Dict[str, Any]) -> str:
    payload = create_gateway_instruction_signing_payload(inst)
    return _p256_sign_p1363(private_key, payload.encode("utf-8"), error_code="GATEWAY_INSTRUCTION_SIGN_FAILED")


def verify_gateway_instruction_signature(public_key: Any, inst: Dict[str, Any]) -> bool:
    sig = inst.get("signature")
    if not sig or not isinstance(sig, str):
        return False
    try:
        payload = create_gateway_instruction_signing_payload(inst)
        return _p256_verify_sig(public_key, payload.encode("utf-8"), sig)
    except Exception:
        return False



