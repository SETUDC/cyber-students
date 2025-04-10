from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import bcrypt

from .base import BaseHandler
from .encrypt_decrypt import encrypt_display_name

AES_KEY = AESGCM.generate_key(bit_length=256) #generate AES key

def encrypt_display_name(name: str, key:bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, name.encode('utf-8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')
    
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
                
            encrypted_display_name = encrypt_display_name(display_name, AES_KEY)
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return
            
        if not has_disability:
            self.send_error(400, message='Yes or No')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        yield self.db.users.insert_one ({
            'email': email,
            'password': hashed_password,
            'displayName': encrypted_display_name,
            'hasDisability': has_disability
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.response['hasDisability'] = has_disability
        

        self.write_json()
