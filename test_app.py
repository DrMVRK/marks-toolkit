import secrets

from flask import Flask

from marks_toolkit.auth import AuthKit
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

auth_kit.init_app(
    app,
    user_store=user_store
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


reset_token = state.password_reset_service.create_reset_token(
    "mark@example.com"
)
print("Reset token:", reset_token)


state.login_service.authenticate(
    "mark@example.com",
    "TestingPassword123!"
)



test_hash = state.password_service.hash_password(
    "TestingPassword123!"
)

test_user = user_store.create_user(
    email="mark@example.com",
    username="Mark",
    password_hash=test_hash
)

print("\n--- PASSWORD RESET TEST ---")

# 1. Generate a reset token for our test user
reset_token = state.password_reset_service.create_reset_token(
    "mark@example.com"
)

print("Reset token generated:", reset_token is not None)


# 2. Verify the old password works BEFORE the reset
try:
    state.login_service.authenticate(
        "mark@example.com",
        "TestingPassword123!"
    )

    print("Old password works before reset: PASS")

except Exception as error:
    print("Old password works before reset: FAIL")
    print(error)


# 3. Perform the password reset
try:
    state.password_reset_service.reset_password(
        reset_token,
        "NewTestingPassword456!"
    )

    print("Password reset completed: PASS")

except Exception as error:
    print("Password reset completed: FAIL")
    print(error)


# 4. Verify the OLD password no longer works
try:
    state.login_service.authenticate(
        "mark@example.com",
        "TestingPassword123!"
    )

    print("Old password rejected after reset: FAIL")

except Exception:
    print("Old password rejected after reset: PASS")


# 5. Verify the NEW password works
try:
    state.login_service.authenticate(
        "mark@example.com",
        "NewTestingPassword456!"
    )

    print("New password works: PASS")

except Exception as error:
    print("New password works: FAIL")
    print(error)


# 6. Try using the SAME reset token again
try:
    state.password_reset_service.reset_password(
        reset_token,
        "AnotherPassword789!"
    )

    print("Reset token reuse rejected: FAIL")

except Exception:
    print("Reset token reuse rejected: PASS")
    

# --------------------------------------------------
# Start Flask
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)