from dataclasses import dataclass
from datetime import datetime, timezone

from .mfa_store import MFAStore


@dataclass
class MemoryTotp:
    user_id: int
    encrypted_secret: bytes
    enabled: bool = False
    verified_at: datetime | None = None


@dataclass
class MemoryPasskey:
    id: int
    user_id: int
    credential_id: bytes
    public_key: bytes
    sign_count: int
    name: str | None = None
    last_used_at: datetime | None = None


@dataclass
class MemoryRecoveryCode:
    id: int
    user_id: int
    code_hash: str
    used: bool = False
    used_at: datetime | None = None


class MemoryMFAStore(MFAStore):

    def __init__(self):
        self.totp_records = {}
        self.passkeys = []
        self.recovery_codes = []

        self.next_passkey_id = 1
        self.next_recovery_code_id = 1

    # -------------------------
    # TOTP
    # -------------------------

    def get_totp(self, user_id):
        return self.totp_records.get(user_id)

    def create_totp(
        self,
        user_id,
        encrypted_secret,
    ):
        record = MemoryTotp(
            user_id=user_id,
            encrypted_secret=encrypted_secret,
        )

        self.totp_records[user_id] = record

        return record

    def enable_totp(self, user_id):
        record = self.totp_records.get(user_id)

        if record is None:
            raise RuntimeError(
                "TOTP configuration does not exist."
            )

        record.enabled = True
        record.verified_at = datetime.now(
            timezone.utc
        )

        return True

    def delete_totp(self, user_id):
        self.totp_records.pop(
            user_id,
            None,
        )

    # -------------------------
    # Passkeys
    # -------------------------

    def list_passkeys(self, user_id):
        return [
            passkey
            for passkey in self.passkeys
            if passkey.user_id == user_id
        ]

    def find_passkey_by_credential_id(
        self,
        credential_id,
    ):
        for passkey in self.passkeys:
            if (
                passkey.credential_id
                == credential_id
            ):
                return passkey

        return None

    def create_passkey(
        self,
        user_id,
        credential_id,
        public_key,
        sign_count,
        name=None,
    ):
        passkey = MemoryPasskey(
            id=self.next_passkey_id,
            user_id=user_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            name=name,
        )

        self.next_passkey_id += 1
        self.passkeys.append(passkey)

        return passkey

    def update_passkey_sign_count(
        self,
        passkey,
        sign_count,
    ):
        passkey.sign_count = sign_count
        passkey.last_used_at = datetime.now(
            timezone.utc
        )

    def delete_passkey(
        self,
        user_id,
        passkey_id,
    ):
        self.passkeys = [
            passkey
            for passkey in self.passkeys
            if not (
                passkey.user_id == user_id
                and passkey.id == passkey_id
            )
        ]

    # -------------------------
    # Recovery codes
    # -------------------------

    def replace_recovery_codes(
        self,
        user_id,
        code_hashes,
    ):
        self.recovery_codes = [
            code
            for code in self.recovery_codes
            if code.user_id != user_id
        ]

        for code_hash in code_hashes:
            self.recovery_codes.append(
                MemoryRecoveryCode(
                    id=self.next_recovery_code_id,
                    user_id=user_id,
                    code_hash=code_hash,
                )
            )

            self.next_recovery_code_id += 1

    def list_unused_recovery_codes(
        self,
        user_id,
    ):
        return [
            code
            for code in self.recovery_codes
            if (
                code.user_id == user_id
                and not code.used
            )
        ]

    def mark_recovery_code_used(
        self,
        recovery_code,
    ):
        recovery_code.used = True
        recovery_code.used_at = datetime.now(
            timezone.utc
        )

    # -------------------------
    # MFA status
    # -------------------------

    def has_enabled_mfa(self, user_id):
        totp = self.get_totp(user_id)

        if (
            totp is not None
            and totp.enabled
        ):
            return True

        return any(
            passkey.user_id == user_id
            for passkey in self.passkeys
        )