from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.user import UserHandler

from .base import BaseTest

import urllib.parse

# Crypto imports
from api.conf import AES_KEY
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os

key_bytes = bytes(AES_KEY, "utf-8")

def encrypt_field(plaintext: str) -> str:
    if not plaintext:
        return ''
    nonce = os.urandom(16)
    aes_ctr_cipher = Cipher(algorithms.AES(key_bytes), mode=modes.CTR(nonce))
    aes_ctr_encryptor = aes_ctr_cipher.encryptor()

    plaintext_bytes = bytes(plaintext, "utf-8")
    ciphertext_bytes = aes_ctr_encryptor.update(plaintext_bytes)

    combined = nonce + ciphertext_bytes
    return combined.hex()

def hash_password(password: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode('utf-8'))
    hashed = digest.finalize()
    return hashed.hex()

class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/user', UserHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        yield self.get_app().db.users.insert_one({
            'email': self.email,
            'password': self.password,
            'displayName': self.display_name
        })

    @coroutine
    def login(self):
        yield self.get_app().db.users.update_one({
            'email': self.email
        }, {
            '$set': { 'token': self.token, 'expiresIn': 2147483647 }
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.display_name = 'testDisplayName'
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_user(self):
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(self.email, body_2['email'])
        self.assertEqual(self.display_name, body_2['displayName'])

    def test_user_without_token(self):
        response = self.fetch('/user')
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})

        response = self.fetch('/user')
        self.assertEqual(400, response.code)
