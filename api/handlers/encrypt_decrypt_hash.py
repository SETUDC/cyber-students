from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# hash a passphrase using SHA256
def hash_passphrase(passphrase: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(passphrase.encode('utf-8'))
    return digest.finalize()

# encrypt names or phone numbers
def encrypt_data(data: str, passphrase: str) -> str:
    # create a key using PBKDF2 and passphrase
    salt = os.urandom(16)  # creata  random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    # generate a random Initialization Vector
    iv = os.urandom(16)
    
    # AES CBC mode for encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # pad data to be a multiple of 16 bytes (AES block size)
    padded_data = data.encode('utf-8')
    padding_length = 16 - (len(padded_data) % 16)
    padded_data += bytes([padding_length]) * padding_length
    
    # encrypt data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # combine salt, IV, and encrypted data 
    encrypted_message = base64.b64encode(salt + iv + encrypted_data).decode('utf-8')
    
    return encrypted_message

# decrypt data
def decrypt_data(encrypted_data: str, passphrase: str) -> str:
    encrypted_data = base64.b64decode(encrypted_data)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_message = encrypted_data[32:]
    
    # get key againfrom the passphrase and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    # decrypt using AES CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # remove padding
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]
    
    return decrypted_data.decode('utf-8')
