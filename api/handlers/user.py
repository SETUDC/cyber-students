from tornado.web import authenticated
from tornado.gen import coroutine

from .auth import AuthHandler

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

from api.conf import AES_KEY

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
    @coroutine
    def get(self):
        # Decrypt user fields
        decrypted_email = decrypt_field(self.current_user['email'])
        decrypted_display_name = decrypt_field(self.current_user['displayName'])
        decrypted_phone_number = decrypt_field(self.current_user.get('phoneNumber', ''))
        decrypted_address = decrypt_field(self.current_user.get('address', ''))
        disability = self.current_user.get('disability', '')  # disability is stored plaintext

        # Build and send the response
        self.set_status(200)
        self.response.update({
            'email': decrypted_email,
            'displayName': decrypted_display_name,
            'phoneNumber': decrypted_phone_number,
            'address': decrypted_address,
            'disability': disability,
        })
        self.write_json()