from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.registration import RegistrationHandler

from .base import BaseTest

import urllib.parse

class RegistrationHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/registration', RegistrationHandler)])
        super().setUpClass()

    def make_registration_body(self, email=None, password=None, display_name=None, phone_number=None, address=None, disability=None):
        return {
            'email': email or 'test@test.com',
            'password': password or 'testPassword',
            'displayName': display_name or 'testDisplayName',
            'phoneNumber': phone_number or '123-456-7890',
            'address': address or '123 Main Street',
            'disability': disability or 'None'
        }

    def test_registration(self):
        email = 'test@test.com'
        password = 'testPassword'
        display_name = 'testDisplayName'
        phone_number = '123-456-7890'
        address = '123 Main Street'
        disability = 'None'

        body = self.make_registration_body(email, password, display_name, phone_number, address, disability)

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(display_name, body_2['displayName'])
        self.assertEqual(phone_number, body_2['phoneNumber'])
        self.assertEqual(address, body_2['address'])
        self.assertEqual(disability, body_2['disability'])

    def test_registration_without_display_name(self):
        email = 'test@test.com'
        password = 'testPassword'
        phone_number = '123-456-7890'
        address = '123 Main Street'
        disability = 'None'

        body = self.make_registration_body(
            email=email,
            password=password,
            display_name=None,  # omit display name
            phone_number=phone_number,
            address=address,
            disability=disability
        )

        # Remove 'displayName' from the body explicitly
        del body['displayName']

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(email, body_2['displayName'])  # Should fallback to email
        self.assertEqual(phone_number, body_2['phoneNumber'])
        self.assertEqual(address, body_2['address'])
        self.assertEqual(disability, body_2['disability'])

    def test_registration_twice(self):
        body = self.make_registration_body()

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(409, response_2.code)