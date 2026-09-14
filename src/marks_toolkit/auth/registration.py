from .exceptions import (
    IdentityUnavailableError,
    InvalidIdentityError,
    WeakPasswordError,
)


class RegistrationService:
    def __init__(self, identity_service, password_service, user_store):
        self.identity_service = identity_service
        self.password_service = password_service
        self.user_store = user_store

    def register(self, email, username, password):
        try:

            email = self.identity_service.normalize_email(email)
            username = self.identity_service.normalize_username(username)
            email_key = email.casefold()
            username_key = self.identity_service.username_key(username)

        except ValueError as error:
            raise InvalidIdentityError(str(error)) from error

        try:
            password_hash = self.password_service.hash_password(password)
        except ValueError as error:
            raise WeakPasswordError(str(error)) from error
        

        if self.user_store.email_exists(email_key):
            raise IdentityUnavailableError(
                "Email or username is already in use."
            )

        if self.user_store.username_exists(username_key):
            raise IdentityUnavailableError(
                "Email or username is already in use."
            )
        
        return self.user_store.create_user(
            email,
            username,
            password_hash
        )