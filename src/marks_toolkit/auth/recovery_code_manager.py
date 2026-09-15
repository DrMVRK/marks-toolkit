from .mfa import InvalidMFAPasswordError


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
        if not self.password_service.verify_password(
            user.password_hash,
            current_password,
        ):
            raise InvalidMFAPasswordError(
                "Current password is incorrect."
            )

        codes = (
            self.recovery_code_service
            .generate_codes()
        )

        code_hashes = (
            self.recovery_code_service
            .hash_codes(codes)
        )

        self.mfa_store.replace_recovery_codes(
            user_id=user.id,
            code_hashes=code_hashes,
        )

        return codes

    def count_unused_codes(
        self,
        user,
    ):
        codes = (
            self.mfa_store
            .list_unused_recovery_codes(
                user.id
            )
        )

        return len(codes)

    def verify_and_consume(
        self,
        user,
        submitted_code,
    ):
        unused_codes = (
            self.mfa_store
            .list_unused_recovery_codes(
                user.id
            )
        )

        for recovery_code in unused_codes:
            if (
                self.recovery_code_service
                .verify_code(
                    submitted_code,
                    recovery_code.code_hash,
                )
            ):
                self.mfa_store.mark_recovery_code_used(
                    recovery_code
                )

                return True

        return False