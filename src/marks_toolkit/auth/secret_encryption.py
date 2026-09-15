from cryptography.fernet import Fernet, InvalidToken


class SecretEncryptionError(Exception):
    pass


class SecretEncryptionService:

    def __init__(self, encryption_key):
        if not encryption_key:
            raise ValueError(
                "An encryption key is required."
            )

        if isinstance(encryption_key, str):
            encryption_key = (
                encryption_key.encode("utf-8")
            )

        try:
            self.fernet = Fernet(encryption_key)

        except (TypeError, ValueError) as error:
            raise ValueError(
                "Invalid encryption key."
            ) from error

    def encrypt(self, plaintext):
        if not isinstance(plaintext, str):
            raise ValueError(
                "Secret must be a string."
            )

        if not plaintext:
            raise ValueError(
                "Secret cannot be empty."
            )

        return self.fernet.encrypt(
            plaintext.encode("utf-8")
        )

    def decrypt(self, encrypted_value):
        if not isinstance(
            encrypted_value,
            bytes
        ):
            raise ValueError(
                "Encrypted secret must be bytes."
            )

        try:
            plaintext = self.fernet.decrypt(
                encrypted_value
            )

        except InvalidToken as error:
            raise SecretEncryptionError(
                "Unable to decrypt secret."
            ) from error

        return plaintext.decode("utf-8")