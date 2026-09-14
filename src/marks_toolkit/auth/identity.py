import re
from email_validator import EmailNotValidError, validate_email

class IdentityService:
    USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

    def normalize_email(self, email):
        if not isinstance(email, str):
            raise ValueError("Email must be a string.")

        email = email.strip()

        if not email:
            raise ValueError("Email is required.")

        try:
            validated = validate_email(
                email,
                check_deliverability=False
            )

        except EmailNotValidError:
            raise ValueError(
                "Invalid email address."
            )

        return validated.normalized


    def normalize_username(self, username):
        if not isinstance(username, str):
            raise ValueError("Username must be a string.")

        username = username.strip()

        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters long.")

        if len(username) > 64:
            raise ValueError("Username must be at most 64 characters long.")
        
        if not self.USERNAME_PATTERN.fullmatch(username):
            raise ValueError("Username can only contain letters, numbers, dots, underscores, and hyphens.")
        
        return username


    def username_key(self, username):
        username = self.normalize_username(username)
        return username.casefold()


    def identity_key(self, identity):
        if not isinstance(identity, str):
            raise ValueError("Identity must be a string.")

        identity = identity.strip()

        if not identity:
            raise ValueError("Identity is required.")

        return identity.casefold()