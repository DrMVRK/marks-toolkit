from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .exceptions import WeakPasswordError


class PasswordService:
    def __init__(self, min_length=12, max_length=256):
        self.min_length = min_length
        self.max_length = max_length
        self.hasher = PasswordHasher()

    def validate_password(self, password):
        if not isinstance(password, str):
            raise WeakPasswordError(
                "Password must be a string."
            )

        if len(password) < self.min_length:
            raise WeakPasswordError(
                f"Password must be at least "
                f"{self.min_length} characters long."
            )

        if len(password) > self.max_length:
            raise WeakPasswordError(
                f"Password must be no more than "
                f"{self.max_length} characters long."
            )
        
        return True

    def hash_password(self, password):
        self.validate_password(password)
        return self.hasher.hash(password)

    def verify_password(self, stored_hash, password):
        try:
            return self.hasher.verify(stored_hash, password)
        except VerifyMismatchError:
            return False

    def needs_rehash(self, stored_hash):
        return self.hasher.check_needs_rehash(stored_hash)