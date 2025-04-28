from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.registration import RegistrationHandler

from .base import BaseTest

import urllib.parse

class RegistrationHandlerTest(BaseTest):

    @classmethod
    def setUpClass(cls):
        cls.my_app = Application([(r'/registration', RegistrationHandler)])
        super(RegistrationHandlerTest, cls).setUpClass()

    def test_registration(self):
        email = 'test_new@test.com'
        password = 'testPassword123'
        display_name = 'TestDisplayName'
        phone_number = '123-456-7890'
        address = '456 Elm Street'
        disability = 'None'

        body = {
            'email': email,
            'password': password,
            'displayName': display_name,
            'phoneNumber': phone_number,
            'address': address,
            'disability': disability
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(display_name, body_2['displayName'])
        self.assertEqual(phone_number, body_2['phoneNumber'])
        self.assertEqual(address, body_2['address'])
        self.assertEqual(disability, body_2['disability'])

    def test_registration_without_display_name(self):
        email = 'test_nodisplay@test.com'
        password = 'anotherPassword456'
        phone_number = '987-654-3210'
        address = '789 Maple Avenue'
        disability = 'None'

        body = {
            'email': email,
            'password': password,
            'phoneNumber': phone_number,
            'address': address,
            'disability': disability
            
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(email, body_2['displayName']) 
        self.assertEqual(phone_number, body_2['phoneNumber'])
        self.assertEqual(address, body_2['address'])
        self.assertEqual(disability, body_2['disability'])

    def test_registration_twice(self):
        email = 'test_twice@test.com'
        password = 'repeatPassword789'
        display_name = 'TestTwice'
        phone_number = '111-222-3333'
        address = '321 Oak Street'
        disability = 'None'

        body = {
            'email': email,
            'password': password,
            'displayName': display_name,
            'phoneNumber': phone_number,
            'address': address,
            'disability': disability
        }
        
        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(409, response_2.code)  # Conflict expected