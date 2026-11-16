import os
import re
import json
import hashlib
import base64
import tempfile
from abc import ABC, abstractmethod
from typing import Optional, Union, Dict, Any, List

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    ec = None
    serialization = None
    hashes = None
    HKDF = None
    AESGCM = None
    HAS_CRYPTOGRAPHY = False

from .errors import AamarvaError

CHANNEL_HKDF_SALT = "aamarva-e2ee-channel-v1"
CHANNEL_HKDF_INFO_PREFIX = "aamarva-channel:"
CLUSTER_KEY_WRAP_VERSION = "AAMARVA_CLUSTER_KEY_WRAP_V1"
CLUSTER_KEY_WRAP_ALGORITHM = "ECDH-ES+HKDF-256+A256GCM"
CLUSTER_KEY_AAD_PREFIX = "aamarva-cluster-group-key:"


def _require_cryptography():
    if not HAS_CRYPTOGRAPHY:
        raise AamarvaError(
            "The 'cryptography' Python package is required for E2EE cryptographic operations. "
            "Please install it using 'pip install cryptography'.",
            code="CRYPTO_DEPENDENCY_MISSING"
        )


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _sanitize_key_slot_id(raw_id: str) -> str:
    if not raw_id or not isinstance(raw_id, str):
        raise AamarvaError("Key identifier must be a non-empty string.", code="IDENTITY_KEY_INVALID")
    trimmed = raw_id.strip()
    if (
        not trimmed
        or trimmed in (".", "..")
        or "/" in trimmed
        or "\\" in trimmed
        or "\x00" in trimmed
        or ".." in trimmed
    ):
        raise AamarvaError(f'Unsafe key identifier rejected: "{raw_id}".', code="IDENTITY_KEY_INVALID")
    safe = re.sub(r"[^A-Za-z0-9._:-]", "_", trimmed)
    if not safe or safe in (".", ".."):
        raise AamarvaError(f'Invalid key identifier: "{raw_id}".', code="IDENTITY_KEY_INVALID")
    return safe


def _validate_positive_epoch(epoch: Any, code: str = "MESSAGE_INVALID_ENVELOPE") -> int:
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise AamarvaError(f'Invalid keyEpoch "{epoch}": must be a positive integer >= 1.', code=code)
    return epoch


def _decode_strict_base64(value: Any, field_name: str, error_code: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise AamarvaError(f'Missing or empty base64 field "{field_name}".', code=error_code)
    trimmed = value.strip()
    if len(trimmed) % 4 == 1 or not re.match(r"^[A-Za-z0-9+/]+={0,2}$", trimmed):
        raise AamarvaError(f'Malformed base64 encoding for "{field_name}".', code=error_code)
    try:
        buf = base64.b64decode(trimmed, validate=True)
    except Exception as err:
        raise AamarvaError(f'Malformed base64 encoding for "{field_name}": {str(err)}', code=error_code)
    if len(buf) == 0:
        raise AamarvaError(f'Empty decoded buffer for "{field_name}".', code=error_code)
    return buf


class KeyStore(ABC):
    """
    KeyStore abstraction for managing local agent private keys.
    Private keys must never be logged or transmitted to AAMARVA.
    """
    @abstractmethod
    def load_private_key(self, identity_id: str = "default") -> Optional[str]:
        pass

    @abstractmethod
    def save_private_key(self, private_key_pem: str, identity_id: str = "default", overwrite: bool = False) -> None:
        pass


class InMemoryKeyStore(KeyStore):
    """
    In-memory KeyStore for ephemeral testing or explicit opt-in.
    """
    def __init__(self):
        self._keys: Dict[str, str] = {}

    def load_private_key(self, identity_id: str = "default") -> Optional[str]:
        safe_id = _sanitize_key_slot_id(identity_id)
        return self._keys.get(safe_id)

    def save_private_key(self, private_key_pem: str, identity_id: str = "default", overwrite: bool = False) -> None:
        safe_id = _sanitize_key_slot_id(identity_id)
        if safe_id in self._keys and not overwrite:
            return
        self._keys[safe_id] = private_key_pem

    def list_key_ids(self) -> List[str]:
        return list(self._keys.keys())


class FileSystemKeyStore(KeyStore):
    """
    FileSystemKeyStore persists private keys atomically to disk with POSIX permissions (0600 files, 0700 dir).
    Configurable via base_dir or AAMARVA_KEY_STORE_PATH env variable (defaults to ~/.aamarva/keys).
    """
    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.environ.get("AAMARVA_KEY_STORE_PATH") or os.path.expanduser("~/.aamarva/keys")

    def _resolve_key_path(self, identity_id: str) -> str:
        safe_id = _sanitize_key_slot_id(identity_id)
        resolved_base = os.path.realpath(self.base_dir)
        resolved_target = os.path.realpath(os.path.join(resolved_base, f"{safe_id}.pem"))
        if not resolved_target.startswith(resolved_base + os.sep):
            raise AamarvaError("Resolved key path escapes keystore base directory.", code="IDENTITY_KEY_INVALID")
        return resolved_target

    def load_private_key(self, identity_id: str = "default") -> Optional[str]:
        if not self.base_dir:
            return None
        key_path = self._resolve_key_path(identity_id)
        if not os.path.exists(key_path):
            return None
        if os.path.islink(key_path) or not os.path.isfile(key_path):
            raise AamarvaError("Refusing to load private key from non-regular file or symlink.", code="IDENTITY_KEY_INVALID")
        with open(key_path, "r", encoding="utf-8") as f:
            content = f.read()
        if not content.strip():
            raise AamarvaError("Stored private key file is empty or corrupt.", code="IDENTITY_KEY_INVALID")
        return content

    def save_private_key(self, private_key_pem: str, identity_id: str = "default", overwrite: bool = False) -> None:
        if not private_key_pem or not isinstance(private_key_pem, str) or not private_key_pem.strip():
            raise AamarvaError("Cannot persist empty private key.", code="IDENTITY_KEY_INVALID")
        if not self.base_dir:
            return
        resolved_base = os.path.realpath(self.base_dir)
        os.makedirs(resolved_base, mode=0o700, exist_ok=True)
        try:
            os.chmod(resolved_base, 0o700)
        except OSError:
            pass
        key_path = self._resolve_key_path(identity_id)
        if os.path.exists(key_path) and not overwrite:
            return

        fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".pem", dir=resolved_base)
        try:
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(private_key_pem)
            os.replace(tmp_path, key_path)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

    def list_key_ids(self) -> List[str]:
        if not self.base_dir or not os.path.exists(self.base_dir):
            return []
        ids: List[str] = []
        for entry in os.listdir(self.base_dir):
            if entry.endswith(".pem") and not entry.startswith(".tmp-"):
                ids.append(entry[:-4])
        return ids


_active_key_store: KeyStore = FileSystemKeyStore()
_cached_identity_keys: Dict[str, Any] = {}


def set_key_store(store: KeyStore) -> None:
    global _active_key_store, _cached_identity_keys
    _active_key_store = store
    _cached_identity_keys.clear()


def get_key_store() -> KeyStore:
    return _active_key_store


def reset_local_identity_key() -> None:
    global _active_key_store, _cached_identity_keys
    _cached_identity_keys.clear()
    _active_key_store = FileSystemKeyStore()


def _validate_private_ec_p256(priv: Any) -> Any:
    _require_cryptography()
    if not isinstance(priv, ec.EllipticCurvePrivateKey):
        raise AamarvaError("Stored key is not an EC private key.", code="IDENTITY_KEY_INVALID")
    if not isinstance(priv.curve, ec.SECP256R1):
        raise AamarvaError(
            f"Unsupported curve for stored key: {priv.curve.name}. Only P-256 is supported.",
            code="IDENTITY_KEY_INVALID"
        )
    return priv


def _load_or_create_key_slot(slot_id: str, allow_generate: bool = True) -> Any:
    _require_cryptography()
    global _cached_identity_keys, _active_key_store
    if slot_id in _cached_identity_keys:
        return _cached_identity_keys[slot_id]

    stored_pem = _active_key_store.load_private_key(slot_id)
    if stored_pem and isinstance(stored_pem, str) and stored_pem.strip():
        try:
            priv = serialization.load_pem_private_key(stored_pem.encode("utf-8"), password=None)
            _validate_private_ec_p256(priv)
            _cached_identity_keys[slot_id] = priv
            return priv
        except Exception as err:
            if isinstance(err, AamarvaError):
                raise err
            raise AamarvaError(
                f"Failed to load stored key: key is corrupt or invalid format: {str(err)}",
                code="IDENTITY_KEY_INVALID"
            )

    if not allow_generate:
        raise AamarvaError(f'Missing stored key for slot "{slot_id}".', code="IDENTITY_KEY_MISSING")

    priv = ec.generate_private_key(ec.SECP256R1())
    _cached_identity_keys[slot_id] = priv
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    _active_key_store.save_private_key(priv_pem, slot_id)
    return priv


def _load_key_slot_if_exists(slot_id: str) -> Optional[Any]:
    if slot_id in _cached_identity_keys:
        return _cached_identity_keys[slot_id]
    stored_pem = _active_key_store.load_private_key(slot_id)
    if stored_pem and isinstance(stored_pem, str) and stored_pem.strip():
        return _load_or_create_key_slot(slot_id, allow_generate=False)
    return None


def get_local_identity_signing_key(agent_id: str) -> Any:
    """
    Retrieve or generate the persistent ECDSA P-256 identity signing keypair for an agent.
    Separate from the epoch-scoped ECDH key-agreement keypair.
    """
    if not agent_id or not isinstance(agent_id, str) or not agent_id.strip():
        raise AamarvaError("agent_id is required for identity signing key.", code="IDENTITY_KEY_INVALID")
    slot_id = f"{agent_id.strip()}__identity"
    return _load_or_create_key_slot(slot_id, allow_generate=True)


def get_local_ecdh_key(agent_id: str, key_epoch: int = 1) -> Any:
    """
    Retrieve or generate an epoch-scoped ECDH P-256 keypair for an agent.
    """
    if not agent_id or not isinstance(agent_id, str) or not agent_id.strip():
        raise AamarvaError("agent_id is required for ECDH keypair.", code="IDENTITY_KEY_INVALID")
    epoch = _validate_positive_epoch(key_epoch, code="IDENTITY_KEY_INVALID")
    normalized_id = agent_id.strip()
    slot_id = f"{normalized_id}__ecdh_e{epoch}"

    existing = _load_key_slot_if_exists(slot_id)
    if existing is not None:
        return existing
    if epoch == 1:
        legacy = _load_key_slot_if_exists(normalized_id)
        if legacy is not None:
            return legacy
    return _load_or_create_key_slot(slot_id, allow_generate=True)


def find_local_ecdh_key(agent_id: str, key_epoch: int) -> Optional[Any]:
    """
    Look up a stored local ECDH private key for a specific historical epoch without creating one.
    """
    if not agent_id or not isinstance(agent_id, str) or not agent_id.strip():
        return None
    epoch = _validate_positive_epoch(key_epoch, code="IDENTITY_KEY_INVALID")
    normalized_id = agent_id.strip()
    slot_id = f"{normalized_id}__ecdh_e{epoch}"
    existing = _load_key_slot_if_exists(slot_id)
    if existing is not None:
        return existing
    if epoch == 1:
        return _load_key_slot_if_exists(normalized_id)
    return None


def get_latest_local_ecdh_epoch(agent_id: str) -> int:
    if not agent_id or not isinstance(agent_id, str) or not agent_id.strip():
        return 1
    safe_prefix = f"{_sanitize_key_slot_id(agent_id.strip())}__ecdh_e"
    max_epoch = 0
    if hasattr(_active_key_store, "list_key_ids"):
        for slot in _active_key_store.list_key_ids():
            if slot.startswith(safe_prefix):
                try:
                    val = int(slot[len(safe_prefix):])
                    if val >= 1 and val > max_epoch:
                        max_epoch = val
                except ValueError:
                    pass
    for slot in _cached_identity_keys.keys():
        if slot.startswith(safe_prefix):
            try:
                val = int(slot[len(safe_prefix):])
                if val >= 1 and val > max_epoch:
                    max_epoch = val
            except ValueError:
                pass
    return max_epoch if max_epoch >= 1 else 1


def rotate_local_ecdh_key(agent_id: str, next_epoch: Optional[int] = None) -> tuple:
    """
    Generate and persist a fresh ECDH keypair at next_epoch. Returns (private_key, epoch).
    """
    _require_cryptography()
    if not agent_id or not isinstance(agent_id, str) or not agent_id.strip():
        raise AamarvaError("agent_id is required for ECDH key rotation.", code="IDENTITY_KEY_INVALID")
    current_latest = get_latest_local_ecdh_epoch(agent_id)
    target_epoch = _validate_positive_epoch(next_epoch, code="IDENTITY_KEY_INVALID") if next_epoch is not None else current_latest + 1
    normalized_id = agent_id.strip()
    slot_id = f"{normalized_id}__ecdh_e{target_epoch}"

    if _load_key_slot_if_exists(slot_id) is not None:
        raise AamarvaError(
            f"ECDH key for epoch {target_epoch} already exists; refusing to overwrite existing epoch key.",
            code="IDENTITY_KEY_INVALID"
        )

    priv = ec.generate_private_key(ec.SECP256R1())
    _cached_identity_keys[slot_id] = priv
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    _active_key_store.save_private_key(priv_pem, slot_id)
    return priv, target_epoch


def get_local_identity_key(identity_id: str = "default") -> Any:
    """
    Backwards-compatible accessor returning the active local ECDH key for an identity.
    """
    _require_cryptography()
    safe_id = _sanitize_key_slot_id(identity_id)
    legacy = _load_key_slot_if_exists(safe_id)
    if legacy is not None:
        return legacy
    latest_epoch = get_latest_local_ecdh_epoch(identity_id)
    if latest_epoch > 1 or _load_key_slot_if_exists(f"{safe_id}__ecdh_e1") is not None:
        return get_local_ecdh_key(identity_id, latest_epoch)
    return _load_or_create_key_slot(safe_id, allow_generate=True)


def get_local_public_key_pem(identity_id: str = "default") -> str:
    priv = get_local_identity_key(identity_id)
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def export_public_key_jwk(key: Optional[Any] = None) -> Dict[str, str]:
    """
    Export a P-256 EC public key in standard JWK representation.
    """
    _require_cryptography()
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
        "x": _b64url_encode(pn.x.to_bytes(32, byteorder="big")),
        "y": _b64url_encode(pn.y.to_bytes(32, byteorder="big")),
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
        if trimmed.startswith("{"):
            try:
                parsed = json.loads(trimmed)
                return import_public_key(parsed)
            except Exception as err:
                if isinstance(err, AamarvaError):
                    raise err
                raise AamarvaError(f"Failed to parse JWK string: {str(err)}", code="INVALID_PEER_KEY")
        try:
            pub = serialization.load_pem_public_key(trimmed.encode("utf-8"))
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
            x_int = int.from_bytes(_b64url_decode(x_raw), byteorder="big")
            y_int = int.from_bytes(_b64url_decode(y_raw), byteorder="big")
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
        jwk_dict = export_public_key_jwk(pub)
        canonical_dict = {
            "crv": "P-256",
            "kty": "EC",
            "x": jwk_dict["x"],
            "y": jwk_dict["y"],
        }
        canonical_json = json.dumps(canonical_dict, separators=(",", ":"))
        hash_hex = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest().upper()
        formatted = ":".join(hash_hex[i:i + 2] for i in range(0, len(hash_hex), 2))
        return f"SHA256:{formatted}"
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to compute key fingerprint: {str(err)}", code="PEER_KEY_VERIFICATION_FAILED")


def compute_cluster_key_fingerprint(cluster_key: bytes) -> str:
    if not isinstance(cluster_key, (bytes, bytearray)) or len(cluster_key) != 32:
        raise AamarvaError("Cluster key must be 32 bytes.", code="CLUSTER_KEY_INVALID")
    hash_hex = hashlib.sha256(bytes(cluster_key)).hexdigest().upper()
    formatted = ":".join(hash_hex[i:i + 2] for i in range(0, len(hash_hex), 2))
    return f"SHA256:{formatted}"


def compute_audience_hash(agent_ids: List[str]) -> str:
    normalized = sorted({a.strip().upper() for a in agent_ids if isinstance(a, str) and a.strip()})
    payload = json.dumps(normalized, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_roster_hash(member_ids: List[str]) -> str:
    return compute_audience_hash(member_ids)


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
    _require_cryptography()
    binding_string = create_identity_binding_string(agent_id, fingerprint)
    try:
        priv = private_key
        if isinstance(private_key, str):
            priv = serialization.load_pem_private_key(private_key.encode("utf-8"), password=None)
        _validate_private_ec_p256(priv)
        sig = priv.sign(binding_string.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(sig).decode("utf-8")
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
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
    _require_cryptography()
    if not signature_b64 or not isinstance(signature_b64, str):
        return False
    binding_string = create_identity_binding_string(agent_id, fingerprint)
    try:
        pub = import_public_key(identity_key)
        sig_bytes = _decode_strict_base64(signature_b64, "signature", "PEER_KEY_VERIFICATION_FAILED")
        pub.verify(sig_bytes, binding_string.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
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
    _require_cryptography()
    try:
        peer_pub = import_public_key(peer_key)
        priv = local_priv
        if isinstance(local_priv, str):
            priv = serialization.load_pem_private_key(local_priv.encode("utf-8"), password=None)
        elif not isinstance(local_priv, ec.EllipticCurvePrivateKey):
            raise AamarvaError("Invalid local private key provided for ECDH.", code="IDENTITY_KEY_INVALID")
        _validate_private_ec_p256(priv)
        return priv.exchange(ec.ECDH(), peer_pub)
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to perform ECDH shared secret derivation: {str(err)}", code="MESSAGE_ENCRYPTION_FAILED")


def derive_connection_aes_key(shared_secret: bytes, connection_id: str) -> bytes:
    """
    Authoritative Platform HKDF-SHA256 channel key derivation:
    - Hash: SHA-256
    - Salt: "aamarva-e2ee-channel-v1"
    - Info: "aamarva-channel:<connectionId>"
    - Length: 32 bytes (AES-256-GCM)
    """
    _require_cryptography()
    if not connection_id or not isinstance(connection_id, str) or not connection_id.strip():
        raise AamarvaError("Connection ID is required for key derivation.", code="MESSAGE_ENCRYPTION_FAILED")
    canonical_id = connection_id.strip()
    try:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=CHANNEL_HKDF_SALT.encode("utf-8"),
            info=f"{CHANNEL_HKDF_INFO_PREFIX}{canonical_id}".encode("utf-8"),
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
    validated_epoch = _validate_positive_epoch(key_epoch, code="MESSAGE_ENCRYPTION_FAILED")
    verify_peer_key(peer_key, expected_fingerprint, peer_agent_id, peer_signature, peer_identity_key)
    shared_secret = derive_shared_secret(local_priv, peer_key)
    aes_key = derive_connection_aes_key(shared_secret, connection_id)

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), connection_id.strip().encode("utf-8"))

    return {
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "version": 1,
        "keyEpoch": validated_epoch,
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
    if "version" in envelope and envelope["version"] is not None and envelope["version"] != 1:
        raise AamarvaError(f'Unsupported direct message envelope version: {envelope.get("version")}.', code="MESSAGE_INVALID_ENVELOPE")
    if "keyEpoch" in envelope and envelope["keyEpoch"] is not None:
        _validate_positive_epoch(envelope["keyEpoch"], code="MESSAGE_INVALID_ENVELOPE")

    nonce = _decode_strict_base64(envelope["nonce"], "nonce", "MESSAGE_INVALID_ENVELOPE")
    if len(nonce) != 12:
        raise AamarvaError(f"Invalid AES-GCM nonce length: expected 12 bytes, got {len(nonce)}.", code="MESSAGE_INVALID_ENVELOPE")
    combined = _decode_strict_base64(envelope["ciphertext"], "ciphertext", "MESSAGE_INVALID_ENVELOPE")
    if len(combined) < 16:
        raise AamarvaError("Ciphertext is too short or malformed (missing auth tag).", code="MESSAGE_INVALID_ENVELOPE")

    verify_peer_key(peer_key, expected_fingerprint, peer_agent_id, peer_signature, peer_identity_key)

    try:
        shared_secret = derive_shared_secret(local_priv, peer_key)
        aes_key = derive_connection_aes_key(shared_secret, connection_id)

        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, combined, connection_id.strip().encode("utf-8"))
        return plaintext_bytes.decode("utf-8")
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to decrypt message locally: {str(err)}", code="MESSAGE_DECRYPTION_FAILED")


def encrypt_message(plaintext: str, connection_id: str, agent_id_a: str = "", agent_id_b: str = "") -> dict:
    raise AamarvaError("Use connection.send() or client.send_message() with E2EE key exchange.", code="MESSAGE_ENCRYPTION_FAILED")


def decrypt_message(envelope: dict, connection_id: str, agent_id_a: str = "", agent_id_b: str = "") -> str:
    raise AamarvaError("Use connection.get_messages() with E2EE key exchange.", code="MESSAGE_DECRYPTION_FAILED")


# Cluster Key Distribution & Group Encryption (AAMARVA_CLUSTER_KEY_WRAP_V1)
def generate_cluster_key() -> bytes:
    """
    Generate a 256-bit symmetric key for cluster encryption.
    """
    _require_cryptography()
    return os.urandom(32)


def build_cluster_wrapping_params(cluster_id: str, epoch: int) -> Dict[str, str]:
    if not cluster_id or not isinstance(cluster_id, str) or not cluster_id.strip():
        raise AamarvaError("cluster_id is required for cluster key wrapping.", code="CLUSTER_KEY_INVALID")
    clean_id = cluster_id.strip()
    valid_epoch = _validate_positive_epoch(epoch, code="CLUSTER_KEY_INVALID")
    return {
        "algorithm": CLUSTER_KEY_WRAP_ALGORITHM,
        "curve": "P-256",
        "hkdfHash": "SHA-256",
        "hkdfSalt": CHANNEL_HKDF_SALT,
        "hkdfInfo": f"{CHANNEL_HKDF_INFO_PREFIX}{clean_id}",
        "aad": f"{CLUSTER_KEY_AAD_PREFIX}{clean_id}:{valid_epoch}",
    }


def wrap_cluster_key_for_recipient(
    cluster_key: bytes,
    recipient_public_key: Any,
    sender_private_key: Any,
    cluster_id: str = "",
    epoch: int = 1,
) -> Dict[str, Any]:
    """
    Wrap cluster symmetric key for a recipient using AAMARVA_CLUSTER_KEY_WRAP_V1 (ECDH-ES+HKDF-256+A256GCM).
    """
    _require_cryptography()
    if not isinstance(cluster_key, (bytes, bytearray)) or len(cluster_key) != 32:
        raise AamarvaError("Cluster key must be a 32-byte value.", code="CLUSTER_KEY_INVALID")
    if not cluster_id or not isinstance(cluster_id, str) or not cluster_id.strip():
        raise AamarvaError("cluster_id is required to wrap cluster key under AAMARVA_CLUSTER_KEY_WRAP_V1.", code="CLUSTER_KEY_INVALID")
    clean_id = cluster_id.strip()
    valid_epoch = _validate_positive_epoch(epoch, code="CLUSTER_KEY_INVALID")

    recipient_pub = import_public_key(recipient_public_key)
    sender_priv = sender_private_key
    if isinstance(sender_private_key, str):
        sender_priv = serialization.load_pem_private_key(sender_private_key.encode("utf-8"), password=None)
    _validate_private_ec_p256(sender_priv)

    sender_pub_jwk = export_public_key_jwk(sender_priv.public_key())
    wrapping_params = build_cluster_wrapping_params(clean_id, valid_epoch)

    shared_secret = sender_priv.exchange(ec.ECDH(), recipient_pub)
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=wrapping_params["hkdfSalt"].encode("utf-8"),
        info=wrapping_params["hkdfInfo"].encode("utf-8"),
    ).derive(shared_secret)

    iv = os.urandom(12)
    aesgcm = AESGCM(wrap_key)
    ciphertext_with_tag = aesgcm.encrypt(iv, bytes(cluster_key), wrapping_params["aad"].encode("utf-8"))

    iv_b64 = base64.b64encode(iv).decode("utf-8")
    ct_b64 = base64.b64encode(ciphertext_with_tag).decode("utf-8")

    pkg = {
        "version": CLUSTER_KEY_WRAP_VERSION,
        "clusterId": clean_id,
        "epoch": valid_epoch,
        "iv": iv_b64,
        "ciphertext": ct_b64,
        "senderPublicKey": sender_pub_jwk,
        "wrappingParams": wrapping_params,
    }

    return {
        "encryptedKeyPackage": json.dumps(pkg, separators=(",", ":")),
        "nonce": iv_b64,
        "wrappingParams": wrapping_params,
    }


def unwrap_cluster_key(
    encrypted_key_package: Union[str, Dict[str, Any]],
    nonce_or_options: Optional[Union[str, Dict[str, Any]]] = None,
    recipient_private_key: Any = None,
    sender_public_key: Any = None,
    expected_cluster_id: Optional[str] = None,
    expected_epoch: Optional[int] = None,
) -> bytes:
    """
    Unwrap cluster symmetric key from AAMARVA_CLUSTER_KEY_WRAP_V1 package.
    """
    _require_cryptography()
    if isinstance(encrypted_key_package, str):
        trimmed = encrypted_key_package.strip()
        if not trimmed.startswith("{"):
            raise AamarvaError("Cluster key package must be a valid AAMARVA_CLUSTER_KEY_WRAP_V1 JSON package.", code="CLUSTER_KEY_UNWRAP_FAILED")
        try:
            pkg = json.loads(trimmed)
        except Exception as err:
            raise AamarvaError(f"Failed to parse wrapped cluster key package: {str(err)}", code="CLUSTER_KEY_UNWRAP_FAILED")
    elif isinstance(encrypted_key_package, dict):
        pkg = encrypted_key_package
    else:
        raise AamarvaError("Missing wrapped cluster key package.", code="CLUSTER_KEY_UNWRAP_FAILED")

    if pkg.get("version") != CLUSTER_KEY_WRAP_VERSION:
        raise AamarvaError(f'Unsupported cluster key wrap version: {pkg.get("version")}.', code="CLUSTER_KEY_UNWRAP_FAILED")

    pkg_cluster_id = pkg.get("clusterId")
    if not pkg_cluster_id or not isinstance(pkg_cluster_id, str) or not pkg_cluster_id.strip():
        raise AamarvaError("Wrapped cluster key package is missing clusterId.", code="CLUSTER_KEY_UNWRAP_FAILED")
    pkg_epoch = _validate_positive_epoch(pkg.get("epoch"), code="CLUSTER_KEY_UNWRAP_FAILED")

    if isinstance(nonce_or_options, dict):
        expected_cluster_id = expected_cluster_id or nonce_or_options.get("expectedClusterId")
        expected_epoch = expected_epoch if expected_epoch is not None else nonce_or_options.get("expectedEpoch")

    if expected_cluster_id and pkg_cluster_id.strip() != expected_cluster_id.strip():
        raise AamarvaError("Wrapped cluster key package clusterId mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")
    if expected_epoch is not None and pkg_epoch != expected_epoch:
        raise AamarvaError("Wrapped cluster key package epoch mismatch.", code="CLUSTER_KEY_UNWRAP_FAILED")

    expected_params = build_cluster_wrapping_params(pkg_cluster_id, pkg_epoch)
    wp = pkg.get("wrappingParams")
    if not isinstance(wp, dict) or any(wp.get(k) != v for k, v in expected_params.items()):
        raise AamarvaError("Wrapped cluster key package wrappingParams failed validation.", code="CLUSTER_KEY_UNWRAP_FAILED")

    resolved_sender_input = sender_public_key or pkg.get("senderPublicKey")
    if not resolved_sender_input:
        raise AamarvaError("Missing sender public key for cluster key unwrap.", code="CLUSTER_KEY_UNWRAP_FAILED")

    sender_pub = import_public_key(resolved_sender_input)
    if sender_public_key and pkg.get("senderPublicKey"):
        if compute_key_fingerprint(sender_pub) != compute_key_fingerprint(pkg.get("senderPublicKey")):
            raise AamarvaError("Sender public key in cluster key package does not match verified sender key.", code="CLUSTER_KEY_UNWRAP_FAILED")

    recipient_priv = recipient_private_key
    if isinstance(recipient_private_key, str):
        recipient_priv = serialization.load_pem_private_key(recipient_private_key.encode("utf-8"), password=None)
    _validate_private_ec_p256(recipient_priv)

    iv = _decode_strict_base64(pkg.get("iv"), "iv", "CLUSTER_KEY_UNWRAP_FAILED")
    if len(iv) != 12:
        raise AamarvaError(f"Invalid cluster key wrap IV length: expected 12 bytes, got {len(iv)}.", code="CLUSTER_KEY_UNWRAP_FAILED")
    combined = _decode_strict_base64(pkg.get("ciphertext"), "ciphertext", "CLUSTER_KEY_UNWRAP_FAILED")
    if len(combined) < 16:
        raise AamarvaError("Cluster key package is too short or malformed.", code="CLUSTER_KEY_UNWRAP_FAILED")

    shared_secret = recipient_priv.exchange(ec.ECDH(), sender_pub)
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=expected_params["hkdfSalt"].encode("utf-8"),
        info=expected_params["hkdfInfo"].encode("utf-8"),
    ).derive(shared_secret)

    try:
        aesgcm = AESGCM(wrap_key)
        unwrapped = aesgcm.decrypt(iv, combined, expected_params["aad"].encode("utf-8"))
        if len(unwrapped) != 32:
            raise AamarvaError("Unwrapped cluster key has invalid length (expected 32 bytes).", code="CLUSTER_KEY_UNWRAP_FAILED")
        return unwrapped
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to unwrap cluster key: {str(err)}", code="CLUSTER_KEY_UNWRAP_FAILED")


def encrypt_cluster_message(
    plaintext: str,
    cluster_key: bytes,
    cluster_id: str,
    epoch: int = 1,
) -> Dict[str, Any]:
    """
    Encrypt cluster message using symmetric cluster key and AES-256-GCM.
    """
    _require_cryptography()
    if not isinstance(plaintext, str):
        raise AamarvaError("Cluster message plaintext must be a string.", code="MESSAGE_ENCRYPTION_FAILED")
    if not isinstance(cluster_key, (bytes, bytearray)) or len(cluster_key) != 32:
        raise AamarvaError("Cluster key must be a 32-byte value.", code="CLUSTER_KEY_INVALID")
    if not cluster_id or not isinstance(cluster_id, str) or not cluster_id.strip():
        raise AamarvaError("cluster_id is required for cluster message encryption.", code="MESSAGE_ENCRYPTION_FAILED")
    valid_epoch = _validate_positive_epoch(epoch, code="MESSAGE_ENCRYPTION_FAILED")

    iv = os.urandom(12)
    aesgcm = AESGCM(bytes(cluster_key))
    aad = f"{cluster_id.strip()}:{valid_epoch}:v2".encode("utf-8")
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), aad)

    return {
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode("utf-8"),
        "nonce": base64.b64encode(iv).decode("utf-8"),
        "version": 2,
        "keyEpoch": valid_epoch,
    }


def decrypt_cluster_message(
    ciphertext_b64: str,
    nonce_b64: str,
    cluster_key: bytes,
    cluster_id: str,
    epoch: int,
    version: int = 2,
) -> str:
    """
    Decrypt cluster message using symmetric cluster key and AES-256-GCM.
    """
    _require_cryptography()
    if not isinstance(cluster_key, (bytes, bytearray)) or len(cluster_key) != 32:
        raise AamarvaError("Cluster key must be a 32-byte value.", code="CLUSTER_MESSAGE_DECRYPTION_FAILED")
    if not cluster_id or not isinstance(cluster_id, str) or not cluster_id.strip():
        raise AamarvaError("cluster_id is required for cluster message decryption.", code="CLUSTER_MESSAGE_DECRYPTION_FAILED")
    valid_epoch = _validate_positive_epoch(epoch, code="CLUSTER_MESSAGE_DECRYPTION_FAILED")
    if version != 2:
        raise AamarvaError(f"Unsupported cluster message version: {version}. Expected v2.", code="CLUSTER_MESSAGE_DECRYPTION_FAILED")

    iv = _decode_strict_base64(nonce_b64, "nonce", "CLUSTER_MESSAGE_DECRYPTION_FAILED")
    if len(iv) != 12:
        raise AamarvaError(f"Invalid AES-GCM nonce length: expected 12 bytes, got {len(iv)}.", code="CLUSTER_MESSAGE_DECRYPTION_FAILED")
    combined = _decode_strict_base64(ciphertext_b64, "ciphertext", "CLUSTER_MESSAGE_DECRYPTION_FAILED")
    if len(combined) < 16:
        raise AamarvaError("Cluster ciphertext is too short or malformed.", code="CLUSTER_MESSAGE_DECRYPTION_FAILED")

    try:
        aesgcm = AESGCM(bytes(cluster_key))
        aad = f"{cluster_id.strip()}:{valid_epoch}:v{version}".encode("utf-8")
        decrypted_bytes = aesgcm.decrypt(iv, combined, aad)
        return decrypted_bytes.decode("utf-8")
    except Exception as err:
        if isinstance(err, AamarvaError):
            raise err
        raise AamarvaError(f"Failed to decrypt cluster message: {str(err)}", code="CLUSTER_MESSAGE_DECRYPTION_FAILED")
