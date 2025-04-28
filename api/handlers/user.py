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

   # @authenticated
    #def get(self):
     #   self.set_status(200)
      #  self.response['email'] = self.current_user['email']
       # self.response['displayName'] = self.current_user['display_name']
        #self.write_json()
        
    @authenticated
    @coroutine
    
    def get(self):
        self.set_status(200)
        self.response['email'] = decrypt_field(self.current_user['email'])
        self.response['displayName'] = decrypt_field(self.current_user['displayName'])
        self.response['phoneNumber'] = decrypt_field(self.current_user.get('phoneNumber', ''))
        self.response['address'] = decrypt_field(self.current_user.get('address', ''))
        self.response['disability'] = self.current_user.get('disability', '')
        self.write_json()

        token = self.get_secure_cookie('token')
        if not token:
            self.send_error(401, message='Unauthorized')
            return

        user = yield self.db.users.find_one({'token': token.decode('utf-8')}, {})

        if not user:
            self.send_error(404, message='User not found')
            return

        try:
            decrypted_email = decrypt_field(user['email'], AES_KEY)
            decrypted_display_name = decrypt_field(user['displayName'], AES_KEY)
            decrypted_has_disability = decrypt_field(user['hasDisability'], AES_KEY)
            has_disability = decrypted_has_disability.lower() == 'true'

            self.set_status(200)
            self.response['email'] = decrypted_email
            self.response['displayName'] = decrypted_display_name
            self.response['hasDisability'] = has_disability
            self.write_json()

        except Exception:
            self.send_error(500, message='Decryption failed')

    @authenticated
    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)