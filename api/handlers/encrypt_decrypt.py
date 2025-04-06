import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY = base64.b64decode(os.environ['AES_KEY'])  # 32-byte base64-encoded string

def encrypt_display_name(name: str, key: bytes = AES_KEY) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, name.encode('utf-8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_display_name(encrypted: str, key: bytes = AES_KEY) -> str:
    aesgcm = AESGCM(key)
    encrypted_data = base64.b64decode(encrypted.encode('utf-8'))
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
