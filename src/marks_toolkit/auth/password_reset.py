from .exceptions import AuthError


class InvalidResetTokenError(AuthError):
    code = "INVALID_RESET_TOKEN"
    status_code = 400


class PasswordResetService:
    def __init__(
            self,
            user_store,
            identity_service,
            password_service,
            reset_token_service,
            mailer
    ):
        self.user_store = user_store
        self.identity_service = identity_service
        self.password_service = password_service
        self.reset_token_service = reset_token_service
        self.mailer = mailer

    def request_reset(self, email, reset_url):
        try:
            email = self.identity_service.normalize_email(email)
        except ValueError:
            return

        user = self.user_store.find_by_identity(email)

        if user is None:
            return

        token = self.reset_token_service.generate(
            user.auth_id
        )

        separator = "&" if "?" in reset_url else "?"

        full_reset_url = (
            f"{reset_url}{separator}token={token}"
        )

        self.mailer.send_password_reset(
            email=user.email,
            reset_url=full_reset_url
        )

    def reset_password(self, token, new_password):
        payload = self.reset_token_service.verify(token)

        if payload is None:
            raise InvalidResetTokenError(
                "Password reset link is invalid or expired."
            )

        auth_id = payload.get("auth_id")

        if not auth_id:
            raise InvalidResetTokenError(
                "Password reset link is invalid or expired."
            )

        user = self.user_store.find_by_auth_id(auth_id)

        if user is None:
            raise InvalidResetTokenError(
                "Password reset link is invalid or expired."
            )

        password_hash = self.password_service.hash_password(
            new_password
        )

        self.user_store.update_password_and_rotate_auth_id(
            user,
            password_hash
        )

        self.user_store.rotate_auth_id(user)

        return user