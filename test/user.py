from json import dumps
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.web import Application
from tornado.ioloop import IOLoop
from tornado.gen import coroutine

from api.handlers.user import UserHandler

from .base import BaseTest

import urllib.parse

class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(cls):
        cls.my_app = Application([(r'/user', UserHandler)])
        super(UserHandlerTest, cls).setUpClass()

    @coroutine
    def register(self):
        encrypted_email = self.encrypt_field(self.email)
        encrypted_display_name = self.encrypt_field(self.display_name)
        encrypted_phone_number = self.encrypt_field(self.phone_number)
        encrypted_address = self.encrypt_field(self.address)
        encrypted_disability = self.encrypt_field(self.disability)
        hashed_pw = self.hash_password(self.password)

        yield self.get_app().db.users.insert_one({
            'email': encrypted_email,
            'password': hashed_pw,
            'displayName': encrypted_display_name,
            'phoneNumber': encrypted_phone_number,
            'address': encrypted_address,
            'disability': encrypted_disability,
            'token': self.token,
            'expiresIn': 2147483647
        })

    def setUp(self):
        super().setUp()

        self.email = 'testuser@test.com'
        self.password = 'userPassword123'
        self.display_name = 'Test User Display'
        self.phone_number = '555-123-4567'
        self.address = '999 Test Street'
        self.disability = 'None'
        self.token = 'testUserToken'

        IOLoop.current().run_sync(self.register)

    def encrypt_field(self, plaintext: str) -> str:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import os
        from api.conf import AES_KEY

        key_bytes = bytes(AES_KEY, "utf-8")
        nonce_bytes = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce_bytes))
        encryptor = cipher.encryptor()
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext_bytes = encryptor.update(plaintext_bytes)
        combined = nonce_bytes + ciphertext_bytes
        return combined.hex()

    def hash_password(self, password: str) -> str:
        from cryptography.hazmat.primitives import hashes

        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('utf-8'))
        return digest.finalize().hex()

    def test_user(self):
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(self.email, body_2['email'])
        self.assertEqual(self.display_name, body_2['displayName'])
        self.assertEqual(self.phone_number, body_2['phoneNumber'])
        self.assertEqual(self.address, body_2['address'])
        self.assertEqual(self.disability, body_2['disability'])

    def test_user_without_token(self):
        response = self.fetch('/user')
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(400, response.code)