from logging import basicConfig, INFO, info
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from pymongo import MongoClient  # MongoDB client
from api.conf import PORT
from api.app import Application
from api import encrypt_data, hash_password  

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")  
db = client["cyber_students_db"]  
users_collection = db["users"]  

# user registration and store data in MongoDB
def handle_user_registration(name, phone_number, password):
    # hash the password before storing
    hashed_password = hash_password(password)

    # encrypt sensitive data
    encrypted_name = encrypt_data(name, password)
    encrypted_phone_number = encrypt_data(phone_number, password)

    # store encrypted data and hashed password in MongoDB
    user_data = {
        "name": encrypted_name,
        "phone_number": encrypted_phone_number,
        "password_hash": hashed_password.hex()  # store hash as hex string
    }
    
    # Insert the user data into the MongoDB collection
    users_collection.insert_one(user_data)

    print(f"Encrypted Name: {encrypted_name}")
    print(f"Encrypted Phone Number: {encrypted_phone_number}")
    print(f"Hashed Password: {hashed_password.hex()}")

def main():
    basicConfig(level=INFO)

    
    example_name = "John Doe"
    example_phone_number = "1234567890"
    example_password = "SuperSecretPassword"

   
    handle_user_registration(example_name, example_phone_number, example_password)

    # Start the HTTP server
    http_server = HTTPServer(Application())
    http_server.listen(PORT)

    info(f'Starting server on port {PORT}...')
    IOLoop.current().start()

if __name__ == '__main__':
    main()