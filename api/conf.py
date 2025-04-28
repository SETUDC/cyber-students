import base64

PORT = 4000

MONGODB_HOST = {
    'host': 'localhost',
    'port': 27017
}

MONGODB_DBNAME = 'cyberStudents'

WORKERS = 32

<<<<<<< HEAD
AES_KEY = "thebestsecretkeyintheentireworld"
=======
AES_KEY_B64 = "z2MiS2h09tv3Hy8+6vBQ8kkDj7zP8MdTYekPvKXXmDM="
AES_KEY = base64.b64decode(AES_KEY_B64)
>>>>>>> 2a96aa0b95a23bd57c8c910ff67ee918bad095b5
