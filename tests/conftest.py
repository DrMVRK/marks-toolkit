import secrets

import pytest
from flask import Flask

from marks_toolkit.auth import AuthKit
from marks_toolkit.auth.captcha import TestCaptchaProvider
from marks_toolkit.auth.user_contract import AuthUser
from marks_toolkit.auth.user_store import UserStore


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

    def find_by_identity(self, identity_key):
        for user in self.users:
            if (
                user.email.casefold() == identity_key
                or user.username.casefold() == identity_key
            ):
                return user

        return None

    def find_by_auth_id(self, auth_id):
        for user in self.users:
            if user.auth_id == auth_id:
                return user

        return None

    def email_exists(self, email_key):
        return any(
            user.email.casefold() == email_key
            for user in self.users
        )

    def username_exists(self, username_key):
        return any(
            user.username.casefold() == username_key
            for user in self.users
        )

    def create_user(
        self,
        email,
        username,
        password_hash
    ):
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

    def update_password(
        self,
        user,
        password_hash
    ):
        user.password_hash = password_hash

    def update_password_and_rotate_auth_id(
        self,
        user,
        password_hash
    ):
        user.password_hash = password_hash
        user.auth_id = secrets.token_urlsafe(32)

        return user.auth_id

@pytest.fixture
def app():
    app = Flask(__name__)

    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "pytest-secret-key"

    app.config["MARKS_AUTH_RESET_URL"] = (
        "http://localhost/reset-password"
    )

    app.config["MARKS_AUTH_COOKIE_SECURE"] = False

    app.config[
        "MARKS_AUTH_CAPTCHA_SITE_KEY"
    ] = "test-site-key"

    app.config[
        "MARKS_AUTH_LOGIN_CAPTCHA_THRESHOLD"
    ] = 2

    app.config[
        "MARKS_AUTH_LOGIN_BLOCK_THRESHOLD"
    ] = 4

    app.config[
        "MARKS_AUTH_LOGIN_FAILURE_WINDOW"
    ] = 900

    app.config[
        "MARKS_AUTH_FORGOT_PASSWORD_LIMIT"
    ] = 3

    app.config[
        "MARKS_AUTH_RESET_PASSWORD_LIMIT"
    ] = 3

    user_store = TestUserStore()

    auth_kit = AuthKit()

    auth_kit.init_app(
        app,
        user_store=user_store,
        captcha_provider=TestCaptchaProvider()
    )

    app.test_user_store = user_store

    return app

@pytest.fixture
def client(app):
    return app.test_client()