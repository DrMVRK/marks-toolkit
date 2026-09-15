import pyotp
import time

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

    def begin_enrollment(
        self,
        user,
        current_password,
        password_service,
    ):
        if (
            not isinstance(current_password, str)
            or not current_password
        ):
            raise InvalidMFAPasswordError(
                "Current password is incorrect."
            )

        if not password_service.verify_password(
            user.password_hash,
            current_password,
        ):
            raise InvalidMFAPasswordError(
                "Current password is incorrect."
            )

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
        record = self.mfa_store.get_totp(
            user.id
        )

        if (
            record is None
            or not record.enabled
        ):
            return False

        if not isinstance(code, str):
            return False

        code = code.strip()

        if not code:
            return False

        secret = (
            self.encryption_service
            .decrypt(record.encrypted_secret)
        )

        totp = pyotp.TOTP(secret)

        current_step = (
            int(time.time())
            // totp.interval
        )

        matching_step = None

        for offset in (-1, 0, 1):
            candidate_step = (
                current_step
                + offset
            )

            candidate_time = (
                candidate_step
                * totp.interval
            )

            if totp.verify(
                code,
                for_time=candidate_time,
                valid_window=0,
            ):
                matching_step = candidate_step
                break

        if matching_step is None:
            return False

        return self.mfa_store.claim_totp_step(
            user.id,
            matching_step,
        )

    def disable_totp(
        self,
        user,
        current_password,
        password_service,
    ):
        if (
            not isinstance(current_password, str)
            or not current_password
        ):
            raise InvalidMFAPasswordError(
                "Current password is incorrect."
            )

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

        self.mfa_store.replace_recovery_codes(
            user.id,
            [],
        )

        return True
