from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4
import bcrypt   # for hashing

from .base import BaseHandler
from .encrypt_decrypt import decrypt_display_name


class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {
          'password': 1,
          'displayName': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return
            
        if not user.get('password'):
            self.send_error(403, message='The email address and password are invalid!')
            return
            
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            self.send_error(403, message='The email address and password are invalid!')
            return
            
        try:
            decrypted_display_name = decrypt_display_name(user.get('displayName', ''))   #decrupt display name
        except Exception:
            decrypted_display_name = '[decryption not successful]'
            
        token = yield self.generate_token(email) 

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']
        self.response['displayName'] = decrypted_display_name

        self.write_json()