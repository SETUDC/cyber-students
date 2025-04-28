import click
from motor.motor_tornado import MotorClient
from tornado.gen import coroutine
from tornado.ioloop import IOLoop

from api.conf import MONGODB_HOST, MONGODB_DBNAME, AES_KEY

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Prepare AES key
key_bytes = AES_KEY

# Use AES_KEY directly
key_bytes = AES_KEY

def decrypt_field(hex_data: str) -> str:
    if not hex_data:
        return ''
    combined = bytes.fromhex(hex_data)
    nonce_bytes = combined[:16]
    ciphertext_bytes = combined[16:]
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce_bytes))
    decryptor = cipher.decryptor()
    plaintext_bytes = decryptor.update(ciphertext_bytes)
    return plaintext_bytes.decode('utf-8')

@coroutine
def get_users(db):
    cur = db.users.find({}, {
        'email': 1,
        'password': 1,
        'displayName': 1,
        'phoneNumber': 1,
        'address': 1,
        'disability': 1
    })
    docs = yield cur.to_list(length=None)
    print('There are ' + str(len(docs)) + ' registered users:')
    
    for doc in docs:
    decrypted_doc = {}

    # Decrypt only fields that were encrypted
    if 'email' in doc:
        decrypted_doc['email'] = decrypt_field(doc['email'])
    if 'displayName' in doc:
        decrypted_doc['displayName'] = decrypt_field(doc['displayName'])
    if 'phoneNumber' in doc:
        decrypted_doc['phoneNumber'] = decrypt_field(doc['phoneNumber'])
    if 'address' in doc:
        decrypted_doc['address'] = decrypt_field(doc['address'])
    if 'disability' in doc:
        decrypted_doc['disability'] = decrypt_field(doc['disability'])

    # Password is hashed! Don't decrypt it
    decrypted_doc['password'] = doc.get('password', '(missing)')

    click.echo(decrypted_doc)

@click.group()
def cli():
    pass

@cli.command()
def list():
    db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]
    IOLoop.current().run_sync(lambda: get_users(db))

if __name__ == '__main__':
    cli()