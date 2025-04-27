from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from .base import BaseHandler

from api.conf import AES_KEY

def encrypt_field(value: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, value.encode('utf-8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def hash_email(email: str) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(email.encode('utf-8'))
    return digest.finalize().hex()

def hash_password(password: str) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode('utf-8'))
    return digest.finalize().hex()

class RegistrationHandler(BaseHandler):

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

            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()

            has_disability = body.get('hasDisability')
            if not isinstance(has_disability, bool):
                raise Exception()

            # Hash email and password
            hashed_email = hash_email(email)
            hashed_password = hash_password(password)

            # Encrypt display name and hasDisability
            encrypted_display_name = encrypt_field(display_name, AES_KEY)
            encrypted_has_disability = encrypt_field(str(has_disability), AES_KEY)

        except Exception:
            self.send_error(400, message='You must provide an email address, password, display name and disability status!')
            return

        # Check if user already exists
        user = yield self.db.users.find_one({
            'email': hashed_email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # Insert into database
        yield self.db.users.insert_one({
            'email': hashed_email,
            'password': hashed_password,
            'displayName': encrypted_display_name,
            'hasDisability': encrypted_has_disability
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.response['hasDisability'] = has_disability
        self.write_json()