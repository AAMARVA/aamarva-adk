"""
Pure-Python OpenSSL 3.x (libcrypto) cryptographic backend matching the subset of
the `cryptography` library interfaces used by `aamarva.crypto`.

Used automatically as a fallback when the third-party `cryptography` wheel is
not installed in the Python runtime, using the system OpenSSL shared library
(`libcrypto.so.3` / `libcrypto`) via `ctypes` and standard-library `hmac`/`hashlib`.
"""

import ctypes
import ctypes.util
import hashlib
import hmac as _hmac
import os
from typing import Any, Optional, Tuple


class InvalidSignature(Exception):
    pass


class InvalidTag(Exception):
    pass


def _load_libcrypto() -> ctypes.CDLL:
    candidates = [
        "libcrypto.so.3",
        "/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/lib/aarch64-linux-gnu/libcrypto.so.3",
        ctypes.util.find_library("crypto"),
        "libcrypto.so",
        "libcrypto.dylib",
    ]
    for path in candidates:
        if not path:
            continue
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue
    raise ImportError("Unable to locate system OpenSSL libcrypto shared library.")


_lib = _load_libcrypto()

# OpenSSL constants
_EVP_PKEY_EC = 408
_EVP_PKEY_X25519 = 1034
_EVP_CTRL_GCM_SET_IVLEN = 0x9
_EVP_CTRL_GCM_GET_TAG = 0x10
_EVP_CTRL_GCM_SET_TAG = 0x11

# Type aliases
_c_void_p = ctypes.c_void_p
_c_int = ctypes.c_int
_c_uint = ctypes.c_uint
_c_size_t = ctypes.c_size_t
_c_char_p = ctypes.c_char_p
_c_ubyte_p = ctypes.POINTER(ctypes.c_ubyte)
_c_size_p = ctypes.POINTER(ctypes.c_size_t)
_c_int_p = ctypes.POINTER(ctypes.c_int)

# Bindings
_lib.EVP_PKEY_Q_keygen.argtypes = [_c_void_p, _c_char_p, _c_char_p]
_lib.EVP_PKEY_Q_keygen.restype = _c_void_p

# Note: EVP_PKEY_Q_keygen is variadic for "EC", group_name. Define a second handle.
_evp_pkey_q_keygen_ec = _lib.__getattr__("EVP_PKEY_Q_keygen")
_evp_pkey_q_keygen_ec = ctypes.CFUNCTYPE(
    _c_void_p, _c_void_p, _c_char_p, _c_char_p, _c_char_p
)(ctypes.cast(_lib.EVP_PKEY_Q_keygen, _c_void_p).value)

_evp_pkey_q_keygen_raw = ctypes.CFUNCTYPE(
    _c_void_p, _c_void_p, _c_char_p, _c_char_p
)(ctypes.cast(_lib.EVP_PKEY_Q_keygen, _c_void_p).value)

_lib.EVP_PKEY_free.argtypes = [_c_void_p]
_lib.EVP_PKEY_free.restype = None

_lib.EVP_PKEY_get_id.argtypes = [_c_void_p]
_lib.EVP_PKEY_get_id.restype = _c_int

_lib.EVP_PKEY_new_raw_private_key.argtypes = [_c_int, _c_void_p, ctypes.c_char_p, _c_size_t]
_lib.EVP_PKEY_new_raw_private_key.restype = _c_void_p

_lib.EVP_PKEY_new_raw_public_key.argtypes = [_c_int, _c_void_p, ctypes.c_char_p, _c_size_t]
_lib.EVP_PKEY_new_raw_public_key.restype = _c_void_p

_lib.EVP_PKEY_get_raw_private_key.argtypes = [_c_void_p, ctypes.c_char_p, _c_size_p]
_lib.EVP_PKEY_get_raw_private_key.restype = _c_int

_lib.EVP_PKEY_get_raw_public_key.argtypes = [_c_void_p, ctypes.c_char_p, _c_size_p]
_lib.EVP_PKEY_get_raw_public_key.restype = _c_int

_lib.EVP_PKEY_get_octet_string_param.argtypes = [_c_void_p, _c_char_p, ctypes.c_char_p, _c_size_t, _c_size_p]
_lib.EVP_PKEY_get_octet_string_param.restype = _c_int

_lib.EVP_PKEY_get_utf8_string_param.argtypes = [_c_void_p, _c_char_p, ctypes.c_char_p, _c_size_t, _c_size_p]
_lib.EVP_PKEY_get_utf8_string_param.restype = _c_int

_lib.EVP_PKEY_CTX_new.argtypes = [_c_void_p, _c_void_p]
_lib.EVP_PKEY_CTX_new.restype = _c_void_p

_lib.EVP_PKEY_CTX_new_from_pkey.argtypes = [_c_void_p, _c_void_p, _c_char_p]
_lib.EVP_PKEY_CTX_new_from_pkey.restype = _c_void_p

_lib.EVP_PKEY_CTX_free.argtypes = [_c_void_p]
_lib.EVP_PKEY_CTX_free.restype = None

_lib.EVP_PKEY_public_check.argtypes = [_c_void_p]
_lib.EVP_PKEY_public_check.restype = _c_int

_lib.EVP_PKEY_derive_init.argtypes = [_c_void_p]
_lib.EVP_PKEY_derive_init.restype = _c_int

_lib.EVP_PKEY_derive_set_peer.argtypes = [_c_void_p, _c_void_p]
_lib.EVP_PKEY_derive_set_peer.restype = _c_int

_lib.EVP_PKEY_derive.argtypes = [_c_void_p, ctypes.c_char_p, _c_size_p]
_lib.EVP_PKEY_derive.restype = _c_int

_lib.EVP_MD_CTX_new.argtypes = []
_lib.EVP_MD_CTX_new.restype = _c_void_p

_lib.EVP_MD_CTX_free.argtypes = [_c_void_p]
_lib.EVP_MD_CTX_free.restype = None

_lib.EVP_sha256.argtypes = []
_lib.EVP_sha256.restype = _c_void_p

_lib.EVP_DigestSignInit.argtypes = [_c_void_p, _c_void_p, _c_void_p, _c_void_p, _c_void_p]
_lib.EVP_DigestSignInit.restype = _c_int

_lib.EVP_DigestSign.argtypes = [_c_void_p, ctypes.c_char_p, _c_size_p, ctypes.c_char_p, _c_size_t]
_lib.EVP_DigestSign.restype = _c_int

_lib.EVP_DigestVerifyInit.argtypes = [_c_void_p, _c_void_p, _c_void_p, _c_void_p, _c_void_p]
_lib.EVP_DigestVerifyInit.restype = _c_int

_lib.EVP_DigestVerify.argtypes = [_c_void_p, ctypes.c_char_p, _c_size_t, ctypes.c_char_p, _c_size_t]
_lib.EVP_DigestVerify.restype = _c_int

_lib.BIO_new_mem_buf.argtypes = [ctypes.c_char_p, _c_int]
_lib.BIO_new_mem_buf.restype = _c_void_p

_lib.BIO_new.argtypes = [_c_void_p]
_lib.BIO_new.restype = _c_void_p

_lib.BIO_s_mem.argtypes = []
_lib.BIO_s_mem.restype = _c_void_p

_lib.BIO_free.argtypes = [_c_void_p]
_lib.BIO_free.restype = _c_int

_lib.BIO_ctrl.argtypes = [_c_void_p, _c_int, ctypes.c_long, _c_void_p]
_lib.BIO_ctrl.restype = ctypes.c_long

_lib.PEM_read_bio_PrivateKey.argtypes = [_c_void_p, _c_void_p, _c_void_p, _c_void_p]
_lib.PEM_read_bio_PrivateKey.restype = _c_void_p

_lib.PEM_read_bio_PUBKEY.argtypes = [_c_void_p, _c_void_p, _c_void_p, _c_void_p]
_lib.PEM_read_bio_PUBKEY.restype = _c_void_p

_lib.PEM_write_bio_PKCS8PrivateKey.argtypes = [_c_void_p, _c_void_p, _c_void_p, _c_void_p, _c_int, _c_void_p, _c_void_p]
_lib.PEM_write_bio_PKCS8PrivateKey.restype = _c_int

_lib.PEM_write_bio_PUBKEY.argtypes = [_c_void_p, _c_void_p]
_lib.PEM_write_bio_PUBKEY.restype = _c_int

_lib.d2i_PUBKEY_bio.argtypes = [_c_void_p, _c_void_p]
_lib.d2i_PUBKEY_bio.restype = _c_void_p

_lib.i2d_PUBKEY_bio.argtypes = [_c_void_p, _c_void_p]
_lib.i2d_PUBKEY_bio.restype = _c_int

_lib.EVP_CIPHER_CTX_new.argtypes = []
_lib.EVP_CIPHER_CTX_new.restype = _c_void_p

_lib.EVP_CIPHER_CTX_free.argtypes = [_c_void_p]
_lib.EVP_CIPHER_CTX_free.restype = None

_lib.EVP_aes_256_gcm.argtypes = []
_lib.EVP_aes_256_gcm.restype = _c_void_p

_lib.EVP_EncryptInit_ex.argtypes = [_c_void_p, _c_void_p, _c_void_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.EVP_EncryptInit_ex.restype = _c_int

_lib.EVP_EncryptUpdate.argtypes = [_c_void_p, ctypes.c_char_p, _c_int_p, ctypes.c_char_p, _c_int]
_lib.EVP_EncryptUpdate.restype = _c_int

_lib.EVP_EncryptFinal_ex.argtypes = [_c_void_p, ctypes.c_char_p, _c_int_p]
_lib.EVP_EncryptFinal_ex.restype = _c_int

_lib.EVP_DecryptInit_ex.argtypes = [_c_void_p, _c_void_p, _c_void_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.EVP_DecryptInit_ex.restype = _c_int

_lib.EVP_DecryptUpdate.argtypes = [_c_void_p, ctypes.c_char_p, _c_int_p, ctypes.c_char_p, _c_int]
_lib.EVP_DecryptUpdate.restype = _c_int

_lib.EVP_DecryptFinal_ex.argtypes = [_c_void_p, ctypes.c_char_p, _c_int_p]
_lib.EVP_DecryptFinal_ex.restype = _c_int

_lib.EVP_CIPHER_CTX_ctrl.argtypes = [_c_void_p, _c_int, _c_int, _c_void_p]
_lib.EVP_CIPHER_CTX_ctrl.restype = _c_int

_BIO_CTRL_INFO = 3
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def _bio_to_bytes(bio: _c_void_p) -> bytes:
    ptr = ctypes.c_char_p()
    length = _lib.BIO_ctrl(bio, _BIO_CTRL_INFO, 0, ctypes.byref(ptr))
    if length <= 0:
        return b""
    return ctypes.string_at(ptr, length)


def _dup_public_pkey(priv_pkey: _c_void_p) -> _c_void_p:
    bio = _lib.BIO_new(_lib.BIO_s_mem())
    if not bio:
        raise RuntimeError("BIO_new failed")
    try:
        if _lib.i2d_PUBKEY_bio(bio, priv_pkey) != 1:
            raise ValueError("Failed to serialize public key")
        raw = _bio_to_bytes(bio)
    finally:
        _lib.BIO_free(bio)

    bio2 = _lib.BIO_new_mem_buf(raw, len(raw))
    if not bio2:
        raise RuntimeError("BIO_new_mem_buf failed")
    try:
        pub = _lib.d2i_PUBKEY_bio(bio2, None)
        if not pub:
            raise ValueError("Failed to deserialize public key")
        return pub
    finally:
        _lib.BIO_free(bio2)


class _Hashes:
    class SHA256:
        name = "sha256"
        digest_size = 32


hashes = _Hashes()


class HKDF:
    def __init__(self, algorithm: Any, length: int, salt: Optional[bytes], info: Optional[bytes]):
        if getattr(algorithm, "name", "") != "sha256":
            raise ValueError("Only SHA256 HKDF is supported.")
        self.length = length
        self.salt = salt if salt is not None else b"\x00" * 32
        if len(self.salt) == 0:
            self.salt = b"\x00" * 32
        self.info = info if info is not None else b""

    def derive(self, key_material: bytes) -> bytes:
        prk = _hmac.new(self.salt, key_material, hashlib.sha256).digest()
        n = (self.length + 31) // 32
        okm = bytearray()
        t = b""
        for i in range(1, n + 1):
            t = _hmac.new(prk, t + self.info + bytes([i]), hashlib.sha256).digest()
            okm.extend(t)
        return bytes(okm[: self.length])


class AESGCM:
    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("AESGCM requires a 256-bit (32-byte) key.")
        self._key = bytes(key)

    def encrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes]) -> bytes:
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) == 0:
            raise ValueError("Nonce must be non-empty bytes.")
        aad = bytes(associated_data) if associated_data else b""
        pt = bytes(data)

        ctx = _lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("EVP_CIPHER_CTX_new failed")
        try:
            if _lib.EVP_EncryptInit_ex(ctx, _lib.EVP_aes_256_gcm(), None, None, None) != 1:
                raise RuntimeError("EVP_EncryptInit_ex failed")
            if _lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
                raise RuntimeError("EVP_CTRL_GCM_SET_IVLEN failed")
            if _lib.EVP_EncryptInit_ex(ctx, None, None, self._key, bytes(nonce)) != 1:
                raise RuntimeError("EVP_EncryptInit_ex key/iv failed")

            outl = _c_int(0)
            if aad:
                if _lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(outl), aad, len(aad)) != 1:
                    raise RuntimeError("EVP_EncryptUpdate AAD failed")

            out_buf = ctypes.create_string_buffer(len(pt) + 16)
            total = 0
            if pt:
                if _lib.EVP_EncryptUpdate(ctx, out_buf, ctypes.byref(outl), pt, len(pt)) != 1:
                    raise RuntimeError("EVP_EncryptUpdate pt failed")
                total += outl.value

            fin_buf = ctypes.create_string_buffer(16)
            fin_len = _c_int(0)
            if _lib.EVP_EncryptFinal_ex(ctx, fin_buf, ctypes.byref(fin_len)) != 1:
                raise RuntimeError("EVP_EncryptFinal_ex failed")

            tag_buf = ctypes.create_string_buffer(16)
            if _lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_GET_TAG, 16, tag_buf) != 1:
                raise RuntimeError("EVP_CTRL_GCM_GET_TAG failed")

            return out_buf.raw[:total] + fin_buf.raw[: fin_len.value] + tag_buf.raw[:16]
        finally:
            _lib.EVP_CIPHER_CTX_free(ctx)

    def decrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes]) -> bytes:
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) == 0:
            raise ValueError("Nonce must be non-empty bytes.")
        combined = bytes(data)
        if len(combined) < 16:
            raise InvalidTag("Ciphertext missing 16-byte authentication tag.")
        ct = combined[:-16]
        tag = combined[-16:]
        aad = bytes(associated_data) if associated_data else b""

        ctx = _lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("EVP_CIPHER_CTX_new failed")
        try:
            if _lib.EVP_DecryptInit_ex(ctx, _lib.EVP_aes_256_gcm(), None, None, None) != 1:
                raise RuntimeError("EVP_DecryptInit_ex failed")
            if _lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
                raise RuntimeError("EVP_CTRL_GCM_SET_IVLEN failed")
            if _lib.EVP_DecryptInit_ex(ctx, None, None, self._key, bytes(nonce)) != 1:
                raise RuntimeError("EVP_DecryptInit_ex key/iv failed")

            outl = _c_int(0)
            if aad:
                if _lib.EVP_DecryptUpdate(ctx, None, ctypes.byref(outl), aad, len(aad)) != 1:
                    raise RuntimeError("EVP_DecryptUpdate AAD failed")

            out_buf = ctypes.create_string_buffer(len(ct) + 16)
            total = 0
            if ct:
                if _lib.EVP_DecryptUpdate(ctx, out_buf, ctypes.byref(outl), ct, len(ct)) != 1:
                    raise InvalidTag("EVP_DecryptUpdate failed")
                total += outl.value

            tag_mut = ctypes.create_string_buffer(tag, 16)
            if _lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_TAG, 16, tag_mut) != 1:
                raise InvalidTag("EVP_CTRL_GCM_SET_TAG failed")

            fin_buf = ctypes.create_string_buffer(16)
            fin_len = _c_int(0)
            if _lib.EVP_DecryptFinal_ex(ctx, fin_buf, ctypes.byref(fin_len)) != 1:
                raise InvalidTag("AES-GCM authentication tag verification failed.")

            return out_buf.raw[:total] + fin_buf.raw[: fin_len.value]
        finally:
            _lib.EVP_CIPHER_CTX_free(ctx)


def _der_encode_int(n: int) -> bytes:
    if n < 0:
        raise ValueError("Negative integer not allowed")
    b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def _der_decode_len(buf: bytes, offset: int) -> Tuple[int, int]:
    first = buf[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    nbytes = first & 0x7F
    if nbytes == 0 or offset + nbytes > len(buf):
        raise ValueError("Invalid DER length")
    return int.from_bytes(buf[offset : offset + nbytes], "big"), offset + nbytes


def encode_dss_signature(r: int, s: int) -> bytes:
    body = _der_encode_int(r) + _der_encode_int(s)
    if len(body) >= 0x80:
        lb = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
        return b"\x30" + bytes([0x80 | len(lb)]) + lb + body
    return b"\x30" + bytes([len(body)]) + body


def decode_dss_signature(signature: bytes) -> Tuple[int, int]:
    if not signature or signature[0] != 0x30:
        raise ValueError("Invalid DER ECDSA signature")
    seq_len, idx = _der_decode_len(signature, 1)
    if idx + seq_len != len(signature):
        raise ValueError("Invalid DER signature length")
    if signature[idx] != 0x02:
        raise ValueError("Invalid DER integer tag for r")
    r_len, idx = _der_decode_len(signature, idx + 1)
    r = int.from_bytes(signature[idx : idx + r_len], "big")
    idx += r_len
    if signature[idx] != 0x02:
        raise ValueError("Invalid DER integer tag for s")
    s_len, idx = _der_decode_len(signature, idx + 1)
    s = int.from_bytes(signature[idx : idx + s_len], "big")
    idx += s_len
    if idx != len(signature):
        raise ValueError("Trailing bytes in DER signature")
    return r, s


class _SECP256R1:
    name = "secp256r1"


class _ECDH:
    pass


class _ECDSA:
    def __init__(self, algorithm: Any):
        self.algorithm = algorithm


class _EllipticCurvePublicNumbers:
    def __init__(self, x: int, y: int, curve: Any):
        self.x = x
        self.y = y
        self.curve = curve

    def public_key(self) -> "EllipticCurvePublicKey":
        x_bytes = self.x.to_bytes(32, "big")
        y_bytes = self.y.to_bytes(32, "big")
        return EllipticCurvePublicKey.from_encoded_point(self.curve, b"\x04" + x_bytes + y_bytes)


class EllipticCurvePublicKey:
    def __init__(self, pkey: _c_void_p, curve_name: str = "secp256r1"):
        self._pkey = pkey
        self.curve = _SECP256R1() if curve_name in ("secp256r1", "prime256v1") else type("OtherCurve", (), {"name": curve_name})()

    def __del__(self):
        pkey = getattr(self, "_pkey", None)
        if pkey:
            _lib.EVP_PKEY_free(pkey)
            self._pkey = None

    @classmethod
    def from_encoded_point(cls, curve: Any, data: bytes) -> "EllipticCurvePublicKey":
        if not isinstance(curve, _SECP256R1):
            raise ValueError("Only SECP256R1 supported")
        if len(data) != 65 or data[0] != 0x04:
            raise ValueError("Expected uncompressed 65-byte SEC1 EC point")
        spki = _P256_SPKI_PREFIX + bytes(data)
        bio = _lib.BIO_new_mem_buf(spki, len(spki))
        if not bio:
            raise RuntimeError("BIO_new_mem_buf failed")
        try:
            pkey = _lib.d2i_PUBKEY_bio(bio, None)
            if not pkey:
                raise ValueError("Invalid P-256 public key bytes")
        finally:
            _lib.BIO_free(bio)

        pctx = _lib.EVP_PKEY_CTX_new_from_pkey(None, pkey, None)
        if not pctx:
            _lib.EVP_PKEY_free(pkey)
            raise ValueError("Failed to validate EC public key")
        try:
            if _lib.EVP_PKEY_public_check(pctx) != 1:
                _lib.EVP_PKEY_free(pkey)
                raise ValueError("Point is not valid on P-256 curve")
        finally:
            _lib.EVP_PKEY_CTX_free(pctx)

        return cls(pkey, "secp256r1")

    def public_numbers(self) -> _EllipticCurvePublicNumbers:
        buf = ctypes.create_string_buffer(128)
        out_len = _c_size_t(0)
        if _lib.EVP_PKEY_get_octet_string_param(self._pkey, b"encoded-pub-key", buf, 128, ctypes.byref(out_len)) != 1:
            raise ValueError("Failed to read encoded EC public point")
        raw = buf.raw[: out_len.value]
        if len(raw) != 65 or raw[0] != 0x04:
            raise ValueError("Unsupported EC point encoding")
        x = int.from_bytes(raw[1:33], "big")
        y = int.from_bytes(raw[33:65], "big")
        return _EllipticCurvePublicNumbers(x, y, self.curve)

    def public_bytes(self, encoding: Any, format: Any) -> bytes:
        bio = _lib.BIO_new(_lib.BIO_s_mem())
        if not bio:
            raise RuntimeError("BIO_new failed")
        try:
            if _lib.PEM_write_bio_PUBKEY(bio, self._pkey) != 1:
                raise ValueError("Failed to export EC public key PEM")
            return _bio_to_bytes(bio)
        finally:
            _lib.BIO_free(bio)

    def verify(self, signature: bytes, data: bytes, signature_algorithm: Any) -> None:
        md_ctx = _lib.EVP_MD_CTX_new()
        if not md_ctx:
            raise RuntimeError("EVP_MD_CTX_new failed")
        try:
            if _lib.EVP_DigestVerifyInit(md_ctx, None, _lib.EVP_sha256(), None, self._pkey) != 1:
                raise InvalidSignature("DigestVerifyInit failed")
            rc = _lib.EVP_DigestVerify(md_ctx, signature, len(signature), data, len(data))
            if rc != 1:
                raise InvalidSignature("ECDSA signature verification failed")
        finally:
            _lib.EVP_MD_CTX_free(md_ctx)


class EllipticCurvePrivateKey:
    def __init__(self, pkey: _c_void_p, curve_name: str = "secp256r1"):
        self._pkey = pkey
        self.curve = _SECP256R1() if curve_name in ("secp256r1", "prime256v1") else type("OtherCurve", (), {"name": curve_name})()

    def __del__(self):
        pkey = getattr(self, "_pkey", None)
        if pkey:
            _lib.EVP_PKEY_free(pkey)
            self._pkey = None

    def public_key(self) -> EllipticCurvePublicKey:
        pub_pkey = _dup_public_pkey(self._pkey)
        return EllipticCurvePublicKey(pub_pkey, self.curve.name)

    def private_bytes(self, encoding: Any, format: Any, encryption_algorithm: Any) -> bytes:
        bio = _lib.BIO_new(_lib.BIO_s_mem())
        if not bio:
            raise RuntimeError("BIO_new failed")
        try:
            if _lib.PEM_write_bio_PKCS8PrivateKey(bio, self._pkey, None, None, 0, None, None) != 1:
                raise ValueError("Failed to export EC private key PEM")
            return _bio_to_bytes(bio)
        finally:
            _lib.BIO_free(bio)

    def sign(self, data: bytes, signature_algorithm: Any) -> bytes:
        md_ctx = _lib.EVP_MD_CTX_new()
        if not md_ctx:
            raise RuntimeError("EVP_MD_CTX_new failed")
        try:
            if _lib.EVP_DigestSignInit(md_ctx, None, _lib.EVP_sha256(), None, self._pkey) != 1:
                raise RuntimeError("EVP_DigestSignInit failed")
            sig_len = _c_size_t(0)
            if _lib.EVP_DigestSign(md_ctx, None, ctypes.byref(sig_len), data, len(data)) != 1:
                raise RuntimeError("EVP_DigestSign sizing failed")
            sig_buf = ctypes.create_string_buffer(sig_len.value)
            if _lib.EVP_DigestSign(md_ctx, sig_buf, ctypes.byref(sig_len), data, len(data)) != 1:
                raise RuntimeError("EVP_DigestSign failed")
            return sig_buf.raw[: sig_len.value]
        finally:
            _lib.EVP_MD_CTX_free(md_ctx)

    def exchange(self, algorithm: Any, peer_public_key: EllipticCurvePublicKey) -> bytes:
        ctx = _lib.EVP_PKEY_CTX_new(self._pkey, None)
        if not ctx:
            raise RuntimeError("EVP_PKEY_CTX_new failed")
        try:
            if _lib.EVP_PKEY_derive_init(ctx) != 1:
                raise ValueError("EVP_PKEY_derive_init failed")
            if _lib.EVP_PKEY_derive_set_peer(ctx, peer_public_key._pkey) != 1:
                raise ValueError("EVP_PKEY_derive_set_peer failed")
            secret_len = _c_size_t(0)
            if _lib.EVP_PKEY_derive(ctx, None, ctypes.byref(secret_len)) != 1:
                raise ValueError("EVP_PKEY_derive sizing failed")
            out_buf = ctypes.create_string_buffer(secret_len.value)
            if _lib.EVP_PKEY_derive(ctx, out_buf, ctypes.byref(secret_len)) != 1:
                raise ValueError("EVP_PKEY_derive failed")
            return out_buf.raw[: secret_len.value]
        finally:
            _lib.EVP_PKEY_CTX_free(ctx)


class _ECModule:
    SECP256R1 = _SECP256R1
    ECDH = _ECDH
    ECDSA = _ECDSA
    EllipticCurvePublicNumbers = _EllipticCurvePublicNumbers
    EllipticCurvePublicKey = EllipticCurvePublicKey
    EllipticCurvePrivateKey = EllipticCurvePrivateKey

    @staticmethod
    def generate_private_key(curve: Any) -> EllipticCurvePrivateKey:
        if not isinstance(curve, _SECP256R1):
            raise ValueError("Only SECP256R1 supported")
        pkey = _evp_pkey_q_keygen_ec(None, None, b"EC", b"prime256v1")
        if not pkey:
            raise RuntimeError("Failed to generate P-256 EC key")
        return EllipticCurvePrivateKey(pkey, "secp256r1")


ec = _ECModule()


class X25519PublicKey:
    def __init__(self, pkey: _c_void_p):
        self._pkey = pkey

    def __del__(self):
        pkey = getattr(self, "_pkey", None)
        if pkey:
            _lib.EVP_PKEY_free(pkey)
            self._pkey = None

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "X25519PublicKey":
        if not isinstance(data, (bytes, bytearray)) or len(data) != 32:
            raise ValueError("X25519 public key must be exactly 32 bytes.")
        raw = bytes(data)
        if raw == b"\x00" * 32:
            raise ValueError("All-zero X25519 public key is invalid.")
        pkey = _lib.EVP_PKEY_new_raw_public_key(_EVP_PKEY_X25519, None, raw, 32)
        if not pkey:
            raise ValueError("Failed to import raw X25519 public key.")
        return cls(pkey)

    def public_bytes(self, encoding: Any = None, format: Any = None) -> bytes:
        if encoding is not None and getattr(encoding, "value", None) == "PEM":
            bio = _lib.BIO_new(_lib.BIO_s_mem())
            if not bio:
                raise RuntimeError("BIO_new failed")
            try:
                if _lib.PEM_write_bio_PUBKEY(bio, self._pkey) != 1:
                    raise ValueError("Failed to export X25519 public key PEM")
                return _bio_to_bytes(bio)
            finally:
                _lib.BIO_free(bio)
        buf = ctypes.create_string_buffer(32)
        out_len = _c_size_t(32)
        if _lib.EVP_PKEY_get_raw_public_key(self._pkey, buf, ctypes.byref(out_len)) != 1:
            raise ValueError("Failed to extract raw X25519 public bytes")
        return buf.raw[: out_len.value]


class X25519PrivateKey:
    def __init__(self, pkey: _c_void_p):
        self._pkey = pkey

    def __del__(self):
        pkey = getattr(self, "_pkey", None)
        if pkey:
            _lib.EVP_PKEY_free(pkey)
            self._pkey = None

    @classmethod
    def generate(cls) -> "X25519PrivateKey":
        pkey = _evp_pkey_q_keygen_raw(None, None, b"X25519")
        if not pkey:
            raise RuntimeError("Failed to generate X25519 key")
        return cls(pkey)

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "X25519PrivateKey":
        if not isinstance(data, (bytes, bytearray)) or len(data) != 32:
            raise ValueError("X25519 private key must be exactly 32 bytes.")
        raw = bytes(data)
        if raw == b"\x00" * 32:
            raise ValueError("All-zero X25519 private key is invalid.")
        pkey = _lib.EVP_PKEY_new_raw_private_key(_EVP_PKEY_X25519, None, raw, 32)
        if not pkey:
            raise ValueError("Failed to import raw X25519 private key.")
        return cls(pkey)

    def public_key(self) -> X25519PublicKey:
        buf = ctypes.create_string_buffer(32)
        out_len = _c_size_t(32)
        if _lib.EVP_PKEY_get_raw_public_key(self._pkey, buf, ctypes.byref(out_len)) != 1:
            raise ValueError("Failed to derive X25519 public key")
        return X25519PublicKey.from_public_bytes(buf.raw[: out_len.value])

    def private_bytes(self, encoding: Any = None, format: Any = None, encryption_algorithm: Any = None) -> bytes:
        if encoding is not None and getattr(encoding, "value", None) == "PEM":
            bio = _lib.BIO_new(_lib.BIO_s_mem())
            if not bio:
                raise RuntimeError("BIO_new failed")
            try:
                if _lib.PEM_write_bio_PKCS8PrivateKey(bio, self._pkey, None, None, 0, None, None) != 1:
                    raise ValueError("Failed to export X25519 private key PEM")
                return _bio_to_bytes(bio)
            finally:
                _lib.BIO_free(bio)
        buf = ctypes.create_string_buffer(32)
        out_len = _c_size_t(32)
        if _lib.EVP_PKEY_get_raw_private_key(self._pkey, buf, ctypes.byref(out_len)) != 1:
            raise ValueError("Failed to extract raw X25519 private bytes")
        return buf.raw[: out_len.value]

    def exchange(self, peer_public_key: X25519PublicKey) -> bytes:
        ctx = _lib.EVP_PKEY_CTX_new(self._pkey, None)
        if not ctx:
            raise RuntimeError("EVP_PKEY_CTX_new failed")
        try:
            if _lib.EVP_PKEY_derive_init(ctx) != 1:
                raise ValueError("X25519 derive_init failed")
            if _lib.EVP_PKEY_derive_set_peer(ctx, peer_public_key._pkey) != 1:
                raise ValueError("X25519 derive_set_peer failed")
            secret_len = _c_size_t(0)
            if _lib.EVP_PKEY_derive(ctx, None, ctypes.byref(secret_len)) != 1:
                raise ValueError("X25519 derive sizing failed")
            out_buf = ctypes.create_string_buffer(secret_len.value)
            if _lib.EVP_PKEY_derive(ctx, out_buf, ctypes.byref(secret_len)) != 1:
                raise ValueError("X25519 derive failed")
            shared = out_buf.raw[: secret_len.value]
            if shared == b"\x00" * 32:
                raise ValueError("X25519 derived an invalid all-zero shared secret.")
            return shared
        finally:
            _lib.EVP_PKEY_CTX_free(ctx)


class _X25519Module:
    X25519PrivateKey = X25519PrivateKey
    X25519PublicKey = X25519PublicKey


x25519 = _X25519Module()


class _Encoding:
    class PEM:
        value = "PEM"

    class Raw:
        value = "Raw"


class _PrivateFormat:
    class PKCS8:
        value = "PKCS8"

    class Raw:
        value = "Raw"


class _PublicFormat:
    class SubjectPublicKeyInfo:
        value = "SubjectPublicKeyInfo"

    class Raw:
        value = "Raw"


class _NoEncryption:
    pass


def _wrap_pkey_private(pkey: _c_void_p):
    pid = _lib.EVP_PKEY_get_id(pkey)
    if pid == _EVP_PKEY_X25519:
        return X25519PrivateKey(pkey)
    if pid == _EVP_PKEY_EC:
        group_buf = ctypes.create_string_buffer(64)
        out_len = _c_size_t(0)
        _lib.EVP_PKEY_get_utf8_string_param(pkey, b"group", group_buf, 64, ctypes.byref(out_len))
        group_name = group_buf.value.decode("utf-8", errors="ignore") or "secp256r1"
        return EllipticCurvePrivateKey(pkey, group_name)
    _lib.EVP_PKEY_free(pkey)
    raise ValueError(f"Unsupported private key EVP type id={pid}")


def _wrap_pkey_public(pkey: _c_void_p):
    pid = _lib.EVP_PKEY_get_id(pkey)
    if pid == _EVP_PKEY_X25519:
        return X25519PublicKey(pkey)
    if pid == _EVP_PKEY_EC:
        group_buf = ctypes.create_string_buffer(64)
        out_len = _c_size_t(0)
        _lib.EVP_PKEY_get_utf8_string_param(pkey, b"group", group_buf, 64, ctypes.byref(out_len))
        group_name = group_buf.value.decode("utf-8", errors="ignore") or "secp256r1"
        return EllipticCurvePublicKey(pkey, group_name)
    _lib.EVP_PKEY_free(pkey)
    raise ValueError(f"Unsupported public key EVP type id={pid}")


class _SerializationModule:
    Encoding = _Encoding
    PrivateFormat = _PrivateFormat
    PublicFormat = _PublicFormat
    NoEncryption = _NoEncryption

    @staticmethod
    def load_pem_private_key(data: bytes, password: Optional[bytes] = None):
        bio = _lib.BIO_new_mem_buf(data, len(data))
        if not bio:
            raise RuntimeError("BIO_new_mem_buf failed")
        try:
            pkey = _lib.PEM_read_bio_PrivateKey(bio, None, None, None)
            if not pkey:
                raise ValueError("Invalid PEM private key")
            return _wrap_pkey_private(pkey)
        finally:
            _lib.BIO_free(bio)

    @staticmethod
    def load_pem_public_key(data: bytes):
        bio = _lib.BIO_new_mem_buf(data, len(data))
        if not bio:
            raise RuntimeError("BIO_new_mem_buf failed")
        try:
            pkey = _lib.PEM_read_bio_PUBKEY(bio, None, None, None)
            if not pkey:
                raise ValueError("Invalid PEM public key")
            return _wrap_pkey_public(pkey)
        finally:
            _lib.BIO_free(bio)


serialization = _SerializationModule()
