from .exceptions import AuthError


class RecoveryCodeAuthenticationError(
    AuthError
):
    code = "INVALID_MFA_PASSWORD"
    status_code = 400

    def __init__(
        self,
        message="Current password is incorrect.",
    ):
        super().__init__(message)


class RecoveryCodeManager:
    def __init__(
        self,
        mfa_store,
        recovery_code_service,
        password_service,
    ):
        self.mfa_store = mfa_store

        self.recovery_code_service = (
            recovery_code_service
        )

        self.password_service = (
            password_service
        )

    def generate_codes(
        self,
        user,
        current_password,
    ):
        if not isinstance(
            current_password,
            str,
        ):
            raise (
                RecoveryCodeAuthenticationError()
            )

        if not current_password:
            raise (
                RecoveryCodeAuthenticationError()
            )

        valid_password = (
            self.password_service
            .verify_password(
                user.password_hash,
                current_password,
            )
        )

        if not valid_password:
            raise (
                RecoveryCodeAuthenticationError()
            )

        codes = (
            self.recovery_code_service
            .generate_codes()
        )

        code_hashes = (
            self.recovery_code_service
            .hash_codes(
                codes
            )
        )

        self.mfa_store.replace_recovery_codes(
            user.id,
            code_hashes,
        )

        return codes

    def count_unused_codes(
        self,
        user,
    ):
        records = (
            self.mfa_store
            .list_unused_recovery_codes(
                user.id
            )
        )

        return len(records)

    def verify_and_consume(
        self,
        user,
        recovery_code,
    ):
        if not isinstance(
            recovery_code,
            str,
        ):
            return False

        if not recovery_code.strip():
            return False

        try:
            code_hash = (
                self.recovery_code_service
                .hash_code(
                    recovery_code
                )
            )

        except ValueError:
            return False

        return (
            self.mfa_store
            .consume_recovery_code(
                user.id,
                code_hash,
            )
        )