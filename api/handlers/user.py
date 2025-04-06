from tornado.web import authenticated
from .auth import AuthHandler

from tornado.escape import json_decode
from tornado.gen import coroutine
from .encrypt_decrypt import encrypt_display_name

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['display_name']
        self.write_json()
        
    @authenticated
    @coroutine
    
    def post(self):
        try:
            body = json_decode(self.request.body)

            updates = {}

            if 'displayName' in body:
                display_name = body['displayName']
                if not isinstance(display_name, str) or not display_name.strip():
                    self.send_error(400, message="Invalid display name.")
                    return
                encrypted_display_name = encrypt_display_name(display_name)
                updates['displayName'] = encrypted_display_name

            if 'hasDisability' in body:
                has_disability = body['hasDisability']
                if not isinstance(has_disability, bool):
                    self.send_error(400, message="Invalid value for hasDisability.")
                    return
                updates['hasDisability'] = has_disability

            if not updates:
                self.send_error(400, message="No valid fields to update.")
                return

            yield self.db.users.update_one(    # update in db
                {'email': self.current_user['email']},
                {'$set': updates}
            )

            self.set_status(200)
            self.response['message'] = "Profile updated successfully."
            self.write_json()

        except Exception:
            self.send_error(500, message="Failed to update profile.")    
