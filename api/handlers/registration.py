from json import dumps
from logging import info
from tornado.escape import json_decode
from tornado.gen import coroutine

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .base import BaseHandler
from api.conf import AES_KEY

# Prepare AES key
key_bytes = bytes(AES_KEY, "utf-8")

def encrypt_field(plaintext: str) -> str:
    if not plaintext:
        return ''
    nonce_bytes = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce_bytes))
    encryptor = cipher.encryptor()
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext_bytes = encryptor.update(plaintext_bytes)

    # Combine nonce + ciphertext, encode as hex
    combined = nonce_bytes + ciphertext_bytes
    return combined.hex()

def hash_password(password: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode('utf-8'))
    hashed = digest.finalize()
    return hashed.hex()

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

            display_name = body.get('displayName', email)
            if not isinstance(display_name, str):
                raise Exception()

            phone_number = body.get('phoneNumber', '').strip()
            if not isinstance(phone_number, str):
                raise Exception()

            address = body.get('address', '').strip()
            if not isinstance(address, str):
                raise Exception()

            disability = body.get('disability', '').strip()
            if not isinstance(disability, str):
                raise Exception()

        except Exception:
            self.send_error(400, message='You must provide an email address, password, display name, and valid additional information!')
            return

        if not email or not password:
            self.send_error(400, message='Invalid email or password!')
            return

        encrypted_email = encrypt_field(email)
        encrypted_display_name = encrypt_field(display_name)
        encrypted_phone_number = encrypt_field(phone_number)
        encrypted_address = encrypt_field(address)
        encrypted_disability = encrypt_field(disability)
        hashed_password = hash_password(password)

        # Check if user already exists
        user = yield self.db.users.find_one({'email': encrypted_email}, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # Insert into database
        yield self.db.users.insert_one({
            'email': encrypted_email,
            'password': hashed_password,
            'displayName': encrypted_display_name,
            'phoneNumber': encrypted_phone_number,
            'address': encrypted_address,
            'disability': encrypted_disability
        })

        self.set_status(200)
        self.response.update({
            'email': email,
            'displayName': display_name,
            'phoneNumber': phone_number,
            'address': address,
            'disability': disability,
        })
        self.write_json()