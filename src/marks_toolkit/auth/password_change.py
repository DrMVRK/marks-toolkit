from .exceptions import AuthError


class IncorrectCurrentPasswordError(AuthError):
    code = "INCORRECT_CURRENT_PASSWORD"
    status_code = 400


class PasswordChangeService:
    def __init__(
        self,
        user_store,
        password_service,
    ):
        self.user_store = user_store
        self.password_service = password_service

    def change_password(
        self,
        user,
        current_password,
        new_password,
    ):
        if not self.password_service.verify_password(
            user.password_hash,
            current_password,
        ):
            raise IncorrectCurrentPasswordError(
                "Current password is incorrect."
            )

        new_password_hash = (
            self.password_service.hash_password(
                new_password
            )
        )

        self.user_store.update_password_and_rotate_auth_id(
            user,
            new_password_hash,
        )

        return user