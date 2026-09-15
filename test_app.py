import logging
import secrets

from cryptography.fernet import Fernet
from flask import Flask

from marks_toolkit.auth import AuthKit
from marks_toolkit.auth.captcha import TurnstileCaptchaProvider
from marks_toolkit.auth.memory_mfa_store import MemoryMFAStore
from marks_toolkit.auth.user_contract import AuthUser
from marks_toolkit.auth.user_store import UserStore


# --------------------------------------------------
# Logging
# --------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)


# --------------------------------------------------
# Test user model
# --------------------------------------------------

class TestUser(AuthUser):
    def __init__(
        self,
        user_id,
        auth_id,
        email,
        username,
        password_hash,
        is_active=True
    ):
        self.id = user_id
        self.auth_id = auth_id
        self.email = email
        self.username = username
        self.password_hash = password_hash
        self.active = is_active

    @property
    def is_active(self):
        return self.active


# --------------------------------------------------
# Test user store
# --------------------------------------------------

class TestUserStore(UserStore):
    def __init__(self):
        self.users = []
        self.next_id = 1

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
            user_id=self.next_id,
            auth_id=secrets.token_urlsafe(32),
            email=email,
            username=username,
            password_hash=password_hash
        )

        self.next_id += 1
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


# --------------------------------------------------
# Flask application
# --------------------------------------------------

app = Flask(__name__)


# --------------------------------------------------
# Core development configuration
# --------------------------------------------------

# Development/testing only.
# Production applications should load this from
# an environment variable or secrets manager.
app.config["SECRET_KEY"] = (
    "dev-only-secret-key"
)

app.config["MARKS_AUTH_RESET_URL"] = (
    "http://127.0.0.1:5173/reset-password"
)

app.config[
    "MARKS_AUTH_COOKIE_SECURE"
] = False

app.config[
    "MARKS_AUTH_ALLOW_INSECURE_RESET_URL"
] = True

app.config[
    "MARKS_AUTH_ALLOW_CONSOLE_MAILER"
] = True

app.config[
    "MARKS_AUTH_PROXY_FIX_ENABLED"
] = False

# --------------------------------------------------
# CAPTCHA configuration
# --------------------------------------------------

# Cloudflare official test site key.
app.config[
    "MARKS_AUTH_CAPTCHA_SITE_KEY"
] = "1x00000000000000000000AA"

captcha_provider = TurnstileCaptchaProvider(
    secret_key=(
        "1x0000000000000000000000000000000AA"
    ),
    allowed_hostnames=[
        "127.0.0.1",
        "localhost",
    ],
)

# --------------------------------------------------
# Authentication risk configuration
# --------------------------------------------------

app.config[
    "MARKS_AUTH_LOGIN_CAPTCHA_THRESHOLD"
] = 2

app.config[
    "MARKS_AUTH_LOGIN_BLOCK_THRESHOLD"
] = 4

app.config[
    "MARKS_AUTH_LOGIN_FAILURE_WINDOW"
] = 900


# --------------------------------------------------
# Password-reset throttling
# --------------------------------------------------

app.config[
    "MARKS_AUTH_FORGOT_PASSWORD_LIMIT"
] = 3

app.config[
    "MARKS_AUTH_FORGOT_PASSWORD_WINDOW"
] = 900

app.config[
    "MARKS_AUTH_RESET_PASSWORD_LIMIT"
] = 3

app.config[
    "MARKS_AUTH_RESET_PASSWORD_WINDOW"
] = 900


# --------------------------------------------------
# MFA configuration
# --------------------------------------------------

app.config[
    "MARKS_AUTH_MFA_ENABLED"
] = True

# Development only.
#
# This key is regenerated every time Flask restarts.
# That is acceptable because the development MFA
# store below is also entirely in memory.
app.config[
    "MARKS_AUTH_MFA_ENCRYPTION_KEY"
] = Fernet.generate_key().decode("utf-8")

app.config[
    "MARKS_AUTH_RECOVERY_CODE_KEY"
] = "dev-only-recovery-code-key"

app.config[
    "MARKS_AUTH_TOTP_ISSUER"
] = "MARKS Auth Dev"

app.config[
    "MARKS_AUTH_MFA_CHALLENGE_TTL"
] = 300

app.config[
    "MARKS_AUTH_MFA_CHALLENGE_ATTEMPT_LIMIT"
] = 5

app.config[
    "MARKS_AUTH_MFA_CHALLENGE_ATTEMPT_WINDOW"
] = 300



# --------------------------------------------------
# Development stores
# --------------------------------------------------

user_store = TestUserStore()
mfa_store = MemoryMFAStore()


# --------------------------------------------------
# Initialize AuthKit
# --------------------------------------------------

auth_kit = AuthKit()

auth_kit.init_app(
    app,
    user_store=user_store,
    captcha_provider=captcha_provider,
    mfa_store=mfa_store
)

state = app.extensions["marks_auth"]



# --------------------------------------------------
# Create one development user
# --------------------------------------------------

test_hash = (
    state.password_service.hash_password(
        "TestingPassword123!"
    )
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