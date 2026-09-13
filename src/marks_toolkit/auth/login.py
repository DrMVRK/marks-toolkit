from .exceptions import AuthError


class LoginError(AuthError):
    code = "INVALID_CREDENTIALS"
    status_code = 401


class LoginService:
    def __init__(self, user_store, password_service):
        self.user_store = user_store
        self.password_service = password_service

    def authenticate(self, identity, password):
        user = self.user_store.find_by_identity(identity)

        if user is None:
            raise LoginError("Invalid login credentials.")

        if not user.is_active:
            raise LoginError("Invalid login credentials.")

        if not self.password_service.verify_password(
            user.password_hash,
            password
        ):
            raise LoginError("Invalid login credentials.")

        return user