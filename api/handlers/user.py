from tornado.web import authenticated
from tornado.gen import coroutine

from .auth import AuthHandler

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

from api.conf import AES_KEY

key_bytes = bytes(AES_KEY, "utf-8")

def decrypt_field(hex_data: str) -> str:
    if not hex_data:
        return ''
    combined = bytes.fromhex(hex_data)
    nonce_bytes = combined[:16]
    ciphertext_bytes = combined[16:]

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce_bytes))
    decryptor = cipher.decryptor()
    plaintext_bytes = decryptor.update(ciphertext_bytes)
    return plaintext_bytes.decode('utf-8')

class UserHandler(AuthHandler):

    @authenticated
    @coroutine
    def get(self):
        self.set_status(200)

        self.response.update({
            'email': decrypt_field(self.current_user['email']),
            'displayName': decrypt_field(self.current_user['displayName']),
            'phoneNumber': decrypt_field(self.current_user.get('phoneNumber', '')),
            'address': decrypt_field(self.current_user.get('address', '')),
            'disability': decrypt_field(self.current_user.get('disability', ''))  # Decrypt disability too
        })

        self.write_json()