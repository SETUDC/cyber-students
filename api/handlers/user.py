from tornado.web import authenticated

from .auth import AuthHandler

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

from api.conf import AES_KEY
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

key_bytes = bytes(AES_KEY, "utf-8")


def decrypt_field(encoded_text: str) -> str:
    if not encoded_text:
        return ''
    raw = base64.b64decode(encoded_text)
    nonce = raw[:16]
    ciphertext = raw[16:]
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce))
    decryptor = cipher.decryptor()

    plaintext_bytes = decryptor.update(ciphertext)
    return plaintext_bytes.decode('utf-8')

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = decrypt_field(self.current_user['email'])
        self.response['displayName'] = decrypt_field(self.current_user['displayName'])
        self.response['phoneNumber'] = decrypt_field(self.current_user.get('phoneNumber', ''))
        self.response['address'] = decrypt_field(self.current_user.get('address', ''))
        self.response['disability'] = self.current_user.get('disability', '')
        self.write_json()
