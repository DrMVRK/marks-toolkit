from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock

from .mfa_store import MFAStore


def _utcnow():
    return datetime.now(timezone.utc)


@dataclass
class MemoryTotpRecord:
    user_id: int
    encrypted_secret: bytes
    enabled: bool = False
    created_at: datetime | None = None
    verified_at: datetime | None = None
    last_used_step: int | None = None


@dataclass
class MemoryPasskeyRecord:
    id: int
    user_id: int
    credential_id: bytes
    public_key: bytes
    sign_count: int = 0
    name: str | None = None
    created_at: datetime | None = None
    last_used_at: datetime | None = None


@dataclass
class MemoryRecoveryCodeRecord:
    id: int
    user_id: int
    code_hash: str
    used: bool = False
    created_at: datetime | None = None
    used_at: datetime | None = None


class MemoryMFAStore(MFAStore):
    def __init__(self):
        self._totp = {}
        self._passkeys = {}
        self._recovery_codes = {}

        self._next_passkey_id = 1
        self._next_recovery_id = 1

        self._lock = Lock()

    # ============================================================
    # TOTP
    # ============================================================

    def get_totp(self, user_id):
        return self._totp.get(user_id)

    def create_totp(
        self,
        user_id,
        encrypted_secret,
    ):
        record = MemoryTotpRecord(
            user_id=user_id,
            encrypted_secret=encrypted_secret,
            enabled=False,
            created_at=_utcnow(),
        )

        self._totp[user_id] = record

        return record

    def enable_totp(self, user_id):
        record = self._totp.get(user_id)

        if record is None:
            return False

        record.enabled = True
        record.verified_at = _utcnow()

        return True

    def delete_totp(self, user_id):
        self._totp.pop(
            user_id,
            None,
        )

    def claim_totp_step(
        self,
        user_id,
        step,
    ):
        with self._lock:
            record = self._totp.get(
                user_id
            )

            if (
                record is None
                or not record.enabled
            ):
                return False

            if (
                record.last_used_step
                is not None
                and step
                <= record.last_used_step
            ):
                return False

            record.last_used_step = step

            return True

    # ============================================================
    # PASSKEYS
    # ============================================================

    def list_passkeys(self, user_id):
        return [
            record
            for record in self._passkeys.values()
            if record.user_id == user_id
        ]

    def find_passkey_by_credential_id(
        self,
        credential_id,
    ):
        for record in self._passkeys.values():
            if (
                record.credential_id
                == credential_id
            ):
                return record

        return None

    def create_passkey(
        self,
        user_id,
        credential_id,
        public_key,
        sign_count=0,
        name=None,
    ):
        record = MemoryPasskeyRecord(
            id=self._next_passkey_id,
            user_id=user_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            name=name,
            created_at=_utcnow(),
        )

        self._passkeys[
            self._next_passkey_id
        ] = record

        self._next_passkey_id += 1

        return record

    def update_passkey_sign_count(
        self,
        credential_id,
        sign_count,
    ):
        record = (
            self.find_passkey_by_credential_id(
                credential_id
            )
        )

        if record is None:
            return False

        record.sign_count = sign_count
        record.last_used_at = _utcnow()

        return True

    def delete_passkey(
        self,
        user_id,
        credential_id,
    ):
        for record_id, record in list(
            self._passkeys.items()
        ):
            if (
                record.user_id == user_id
                and record.credential_id
                == credential_id
            ):
                del self._passkeys[
                    record_id
                ]

                return True

        return False

    # ============================================================
    # RECOVERY CODES
    # ============================================================

    def replace_recovery_codes(
        self,
        user_id,
        code_hashes,
    ):
        with self._lock:
            self._recovery_codes[
                user_id
            ] = []

            records = []

            for code_hash in code_hashes:
                record = (
                    MemoryRecoveryCodeRecord(
                        id=self._next_recovery_id,
                        user_id=user_id,
                        code_hash=code_hash,
                        used=False,
                        created_at=_utcnow(),
                    )
                )

                self._next_recovery_id += 1

                self._recovery_codes[
                    user_id
                ].append(record)

                records.append(record)

            return records

    def list_unused_recovery_codes(
        self,
        user_id,
    ):
        return [
            record
            for record
            in self._recovery_codes.get(
                user_id,
                [],
            )
            if not record.used
        ]

    def mark_recovery_code_used(
        self,
        record,
    ):
        with self._lock:
            if record.used:
                return False

            record.used = True
            record.used_at = _utcnow()

            return True

    def consume_recovery_code(
        self,
        user_id,
        code_hash,
    ):
        with self._lock:
            records = (
                self._recovery_codes.get(
                    user_id,
                    [],
                )
            )

            for record in records:
                if (
                    record.code_hash
                    != code_hash
                ):
                    continue

                if record.used:
                    return False

                record.used = True
                record.used_at = _utcnow()

                return True

            return False

    # ============================================================
    # GENERAL MFA
    # ============================================================

    def has_enabled_mfa(
        self,
        user_id,
    ):
        totp = self.get_totp(
            user_id
        )

        if (
            totp is not None
            and totp.enabled
        ):
            return True

        if self.list_passkeys(
            user_id
        ):
            return True

        return False