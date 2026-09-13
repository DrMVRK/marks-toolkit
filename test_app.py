import secrets

from flask import Flask

from marks_toolkit.auth import AuthKit
from marks_toolkit.auth.user_contract import AuthUser
from marks_toolkit.auth.user_store import UserStore
from marks_toolkit.auth.captcha import TestCaptchaProvider


class TestUser(AuthUser):
    def __init__(
        self,
        auth_id,
        email,
        username,
        password_hash,
        is_active=True
    ):
        self.auth_id = auth_id
        self.email = email
        self.username = username
        self.password_hash = password_hash
        self.active = is_active

    @property
    def is_active(self):
        return self.active


class TestUserStore(UserStore):
    def __init__(self):
        self.users = []

    def find_by_identity(self, identity):
        for user in self.users:
            if user.email == identity or user.username == identity:
                return user

        return None

    def find_by_auth_id(self, auth_id):
        for user in self.users:
            if user.auth_id == auth_id:
                return user

        return None

    def identity_exists(self, email, username):
        return any(
            user.email == email or user.username == username
            for user in self.users
        )

    def create_user(self, email, username, password_hash):
        user = TestUser(
            auth_id=secrets.token_urlsafe(32),
            email=email,
            username=username,
            password_hash=password_hash
        )

        self.users.append(user)

        return user

    def rotate_auth_id(self, user):
        user.auth_id = secrets.token_urlsafe(32)

        return user.auth_id

    def update_password(self, user, password_hash):
        user.password_hash = password_hash


app = Flask(__name__)

# Development/testing only.
# A real application should load this from an environment variable
# or another secure secrets-management system.
app.config["SECRET_KEY"] = "dev-only-secret-key"

app.config["MARKS_AUTH_RESET_URL"] = (
    "http://127.0.0.1:5000/reset-password"
)

auth_kit = AuthKit()
user_store = TestUserStore()
captcha_provider = TestCaptchaProvider()

app.config["MARKS_AUTH_CAPTCHA_SITE_KEY"] = "test-site-key"

auth_kit.init_app(
    app,
    user_store=user_store,
    captcha_provider=captcha_provider
)

state = app.extensions["marks_auth"]


# --------------------------------------------------
# Create one test user
# --------------------------------------------------


test_hash = state.password_service.hash_password(
    "TestingPassword123!"
)

test_user = user_store.create_user(
    email="mark@example.com",
    username="Mark",
    password_hash=test_hash
)

# --------------------------------------------------
# Start Flask
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)