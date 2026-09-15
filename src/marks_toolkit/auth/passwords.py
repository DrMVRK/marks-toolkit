from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .exceptions import WeakPasswordError


class PasswordService:
    def __init__(
        self,
        min_length=12,
        max_length=256,
    ):
        self.min_length = min_length
        self.max_length = max_length

        self.hasher = PasswordHasher()

        # Pre-compute a valid Argon2 hash used when an
        # authentication attempt references an account
        # that does not exist.
        #
        # This makes unknown-account authentication perform
        # approximately the same expensive password work as
        # authentication against a real account.
        self._dummy_password_hash = (
            self.hasher.hash(
                "MARKS-Auth-Dummy-Password-Value"
            )
        )

    def validate_password(
        self,
        password,
    ):
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

    def hash_password(
        self,
        password,
    ):
        self.validate_password(
            password
        )

        return self.hasher.hash(
            password
        )

    def verify_password(
        self,
        stored_hash,
        password,
    ):
        try:
            return self.hasher.verify(
                stored_hash,
                password,
            )

        except VerifyMismatchError:
            return False

    def verify_dummy_password(
        self,
        password,
    ):
        """
        Perform Argon2 verification work for an unknown
        account without allowing authentication.
        """
        try:
            self.verify_password(
                self._dummy_password_hash,
                password,
            )

        except Exception:
            # Authentication must still fail generically if
            # malformed password input causes Argon2 to reject
            # the value.
            pass

        return False

    def needs_rehash(
        self,
        stored_hash,
    ):
        return self.hasher.check_needs_rehash(
            stored_hash
        )