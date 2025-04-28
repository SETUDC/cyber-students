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

<<<<<<< HEAD
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

key_bytes = bytes(AES_KEY, "utf-8")
print("Key: " + AES_KEY) 


def encrypt_field(plaintext: str) -> str:
    if not plaintext:
        return ''
    nonce_bytes = os.urandom(16)
    aes_ctr_cipher = Cipher(algorithms.AES(key_bytes), mode=modes.CTR(nonce_bytes))
    aes_ctr_encryptor = aes_ctr_cipher.encryptor()

    plaintext_bytes = bytes(plaintext, "utf-8")
    ciphertext_bytes = aes_ctr_encryptor.update(plaintext_bytes)

    # Store nonce + ciphertext together, then hex encode
    combined = nonce_bytes + ciphertext_bytes
    return combined.hex()

def hash_password(password: str) -> str:
    from cryptography.hazmat.primitives import hashes
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode('utf-8'))
    hashed = digest.finalize()
    return hashed.hex()
=======
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
>>>>>>> 2a96aa0b95a23bd57c8c910ff67ee918bad095b5

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
<<<<<<< HEAD
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

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        encrypted_email = encrypt_field(email)
        encrypted_display_name = encrypt_field(display_name)
        encrypted_phone_number = encrypt_field(phone_number)
        encrypted_address = encrypt_field(address)
        hashed_password = hash_password(password)
=======

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
>>>>>>> 2a96aa0b95a23bd57c8c910ff67ee918bad095b5

        # Check if user already exists
        user = yield self.db.users.find_one({
<<<<<<< HEAD
            'email': encrypted_email
=======
            'email': hashed_email
>>>>>>> 2a96aa0b95a23bd57c8c910ff67ee918bad095b5
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # Insert into database
        yield self.db.users.insert_one({
<<<<<<< HEAD
            'email': encrypted_email,
            'password': hashed_password,
            'displayName': encrypted_display_name,
            'phoneNumber': encrypted_phone_number,
            'address': encrypted_address,
            'disability': disability
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
=======
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
>>>>>>> 2a96aa0b95a23bd57c8c910ff67ee918bad095b5
