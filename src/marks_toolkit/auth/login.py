from .exceptions import AuthError


class LoginError(AuthError):
    code = "INVALID_CREDENTIALS"
    status_code = 401


class LoginService:
    def __init__(
            self, 
            user_store, 
            password_service,
            identity_service
    ):
        self.user_store = user_store
        self.password_service = password_service
        self.identity_service = identity_service

    def authenticate(self, identity, password):
        try:
            identity_key = self.identity_service.identity_key(identity)
        except ValueError:
            raise LoginError("Invalid login credentials.")

        user = self.user_store.find_by_identity(identity_key)

        if user is None:
            raise LoginError("Invalid login credentials.")

        if not user.is_active:
            raise LoginError("Invalid login credentials.")

        if not self.password_service.verify_password(
            user.password_hash,
            password
        ):
            raise LoginError("Invalid login credentials.")

        if self.password_service.needs_rehash(
            user.password_hash
        ):
            new_password_hash = (
                self.password_service.hash_password(
                    password
                )
            )

            self.user_store.update_password(
                user,
                new_password_hash
            )

        return user