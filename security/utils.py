import base64
import hashlib
import os

from django.conf import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_master_key() -> bytes:
    encoded = os.getenv("MASTER_ENCRYPTION_KEY")
    if encoded:
        key = base64.urlsafe_b64decode(encoded)
        if len(key) != 32:
            raise ValueError("MASTER_ENCRYPTION_KEY doit contenir une clé AES-256 encodée en base64.")
        return key
    return hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()


def encrypt_bytes(data: bytes, key: bytes | None = None):
    dek = key or AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, data, None)
    sha256 = hashlib.sha256(data).hexdigest()
    nonce_dek = os.urandom(12)
    encrypted_dek = nonce_dek + AESGCM(get_master_key()).encrypt(nonce_dek, dek, None)
    return ciphertext, nonce, encrypted_dek, sha256


def decrypt_bytes(ciphertext: bytes, nonce: bytes, encrypted_dek: bytes) -> bytes:
    if len(encrypted_dek) < 28:
        raise ValueError("DEK chiffrée invalide.")
    dek_nonce = encrypted_dek[:12]
    dek = AESGCM(get_master_key()).decrypt(dek_nonce, encrypted_dek[12:], None)
    return AESGCM(dek).decrypt(nonce, ciphertext, None)


def load_key(key_str: str | None = None) -> bytes:
    if key_str:
        key = base64.urlsafe_b64decode(key_str)
        if len(key) == 32:
            return key
    return get_master_key()