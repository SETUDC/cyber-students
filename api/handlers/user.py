from tornado.web import authenticated
from .auth import AuthHandler

from tornado.escape import json_decode
from tornado.gen import coroutine
#from .encrypt_decrypt import encrypt_display_name
from api.conf import AES_KEY
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os

def encrypt_field(value: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, value.encode('utf-8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')
    
def decrypt_field(ciphertext_b64: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    data = base64.b64decode(ciphertext_b64.encode('utf-8'))
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')


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
