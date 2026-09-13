from flask import Flask

from marks_toolkit.auth import AuthKit
from marks_toolkit.auth.user_store import UserStore


class TestUserStore(UserStore):

    def find_by_identity(self, identity):
        return None

    def find_by_auth_id(self, auth_id):
        return None

    def identity_exists(self, email, username):
        return False
    
    def create_user(self, email, username, password):
        return None


app = Flask(__name__)

auth_kit = AuthKit()
user_store = TestUserStore()

auth_kit.init_app(
    app,
    user_store=user_store
)


state = app.extensions["marks_auth"]

print(
    state.identity_service.normalize_email(
        " Test@Example.com "
    )
)

print(state.password_service)
print(app.extensions["marks_auth"])

if __name__ == "__main__":
    app.run(debug=True)