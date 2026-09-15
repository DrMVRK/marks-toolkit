import pyotp

from .mfa import (
    InvalidMFAPasswordError,
    InvalidTotpCodeError,
    TotpAlreadyEnabledError,
    TotpEnrollmentNotFoundError,
)


class TotpService:

    def __init__(
        self,
        mfa_store,
        encryption_service,
        issuer_name,
    ):
        self.mfa_store = mfa_store
        self.encryption_service = (
            encryption_service
        )
        self.issuer_name = issuer_name

    def begin_enrollment(self, user):
        existing = self.mfa_store.get_totp(
            user.id
        )

        if (
            existing is not None
            and existing.enabled
        ):
            raise TotpAlreadyEnabledError(
                "TOTP is already enabled."
            )

        # Remove an abandoned or unfinished enrollment.
        if existing is not None:
            self.mfa_store.delete_totp(
                user.id
            )

        secret = pyotp.random_base32()

        encrypted_secret = (
            self.encryption_service.encrypt(
                secret
            )
        )

        self.mfa_store.create_totp(
            user_id=user.id,
            encrypted_secret=encrypted_secret,
        )

        totp = pyotp.TOTP(secret)

        provisioning_uri = (
            totp.provisioning_uri(
                name=user.email,
                issuer_name=self.issuer_name,
            )
        )

        return {
            "secret": secret,
            "provisioning_uri": (
                provisioning_uri
            ),
        }

    def verify_enrollment(
        self,
        user,
        code,
    ):
        enrollment = (
            self.mfa_store.get_totp(
                user.id
            )
        )

        if enrollment is None:
            raise TotpEnrollmentNotFoundError(
                "TOTP enrollment has not been started."
            )

        if enrollment.enabled:
            raise TotpAlreadyEnabledError(
                "TOTP is already enabled."
            )

        secret = (
            self.encryption_service.decrypt(
                enrollment.encrypted_secret
            )
        )

        totp = pyotp.TOTP(secret)

        if not totp.verify(
            str(code),
            valid_window=1,
        ):
            raise InvalidTotpCodeError(
                "Invalid authentication code."
            )

        self.mfa_store.enable_totp(
            user.id
        )

        return True

    def verify_code(
        self,
        user,
        code,
    ):
        enrollment = (
            self.mfa_store.get_totp(
                user.id
            )
        )

        if (
            enrollment is None
            or not enrollment.enabled
        ):
            return False

        secret = (
            self.encryption_service.decrypt(
                enrollment.encrypted_secret
            )
        )

        totp = pyotp.TOTP(secret)

        return totp.verify(
            str(code),
            valid_window=1,
        )

    def disable_totp(
        self,
        user,
        current_password,
        password_service,
    ):
        if not password_service.verify_password(
            user.password_hash,
            current_password,
        ):
            raise InvalidMFAPasswordError(
                "Current password is incorrect."
            )

        enrollment = self.mfa_store.get_totp(
            user.id
        )

        if (
            enrollment is None
            or not enrollment.enabled
        ):
            raise TotpEnrollmentNotFoundError(
                "TOTP is not enabled."
            )

        self.mfa_store.delete_totp(
            user.id
        )

        return True