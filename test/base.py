from concurrent.futures import ThreadPoolExecutor
from motor import MotorClient
from tornado.ioloop import IOLoop
from tornado.testing import AsyncHTTPTestCase
import os

from .conf import MONGODB_HOST, MONGODB_DBNAME, WORKERS, AES_KEY

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key_bytes = bytes(AES_KEY, "utf-8")

def encrypt_field(plaintext: str) -> str:
    if not plaintext:
        return ''
    nonce_bytes = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce_bytes))
    encryptor = cipher.encryptor()
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext_bytes = encryptor.update(plaintext_bytes)
    combined = nonce_bytes + ciphertext_bytes
    return combined.hex()

def hash_password(password: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode('utf-8'))
    return digest.finalize().hex()

class BaseTest(AsyncHTTPTestCase):

    @classmethod
    def setUpClass(cls):
        cls.my_app.db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]
        cls.my_app.executor = ThreadPoolExecutor(WORKERS)

    def get_new_ioloop(self):
        return IOLoop.current()

    def get_app(self):
        return self.my_app

    def setUp(self):
        super().setUp()
        self.get_app().db.users.drop()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.display_name = 'Test User'
        self.phone_number = '123-456-7890'
        self.address = '123 Main Street'
        self.disability = 'None'
        self.token = 'testToken'

        self.insert_test_user()

    def tearDown(self):
        super().tearDown()
        self.get_app().db.users.drop()

    def insert_test_user(self):
        encrypted_email = encrypt_field(self.email)
        encrypted_display_name = encrypt_field(self.display_name)
        encrypted_phone_number = encrypt_field(self.phone_number)
        encrypted_address = encrypt_field(self.address)
        encrypted_disability = encrypt_field(self.disability)
        hashed_pw = hash_password(self.password)

        user_doc = {
            'email': encrypted_email,
            'password': hashed_pw,
            'displayName': encrypted_display_name,
            'phoneNumber': encrypted_phone_number,
            'address': encrypted_address,
            'disability': encrypted_disability,
            'token': self.token,
            'expiresIn': 2147483647  # Arbitrary large expiration for tests
        }

        self.get_app().db.users.insert_one(user_doc)
