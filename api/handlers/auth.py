from datetime import datetime
from time import mktime
from tornado.gen import coroutine

from .base import BaseHandler

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

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
                raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'displayName': 1,
            'expiresIn': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        decrypted_email = decrypt_field(user['email'])
        decrypted_display_name = decrypt_field(user['displayName'])

        self.current_user = {
            'email': decrypted_email,
            'display_name': decrypted_display_name
        }