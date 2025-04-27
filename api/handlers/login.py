from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4

from .base import BaseHandler

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Helper: hash email
def hash_email(email: str) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(email.encode('utf-8'))
    return digest.finalize().hex()

# Helper: hash password
def hash_password(password: str) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode('utf-8'))
    return digest.finalize().hex()

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, hashed_email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': hashed_email
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

        # Hash email and password
        hashed_email = hash_email(email)
        hashed_password_input = hash_password(password)

        user = yield self.db.users.find_one({
            'email': hashed_email
        }, {
            'password': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        if user['password'] != hashed_password_input:
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = yield self.generate_token(hashed_email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()