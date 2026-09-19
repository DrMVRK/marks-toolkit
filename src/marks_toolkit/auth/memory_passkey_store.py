from datetime import datetime
from threading import Lock

from .passkey_store import (
    PasskeyCredential,
    PasskeyStore,
)


class MemoryPasskeyStore(PasskeyStore):
    def __init__(self):
        self._credentials: dict[
            bytes,
            PasskeyCredential,
        ] = {}

        self._lock = Lock()

    # ============================================================
    # CREATE
    # ============================================================

    def create(
        self,
        credential: PasskeyCredential,
    ) -> PasskeyCredential:
        if not isinstance(
            credential,
            PasskeyCredential,
        ):
            raise TypeError(
                "credential must be a "
                "PasskeyCredential"
            )

        credential_id = (
            credential.credential_id
        )

        if not isinstance(
            credential_id,
            bytes,
        ):
            raise TypeError(
                "credential_id must be bytes"
            )

        with self._lock:
            if (
                credential_id
                in self._credentials
            ):
                raise ValueError(
                    "Passkey credential already exists."
                )

            self._credentials[
                credential_id
            ] = credential

            return credential

    # ============================================================
    # LOOKUP
    # ============================================================

    def get_by_credential_id(
        self,
        credential_id: bytes,
    ) -> PasskeyCredential | None:
        if not isinstance(
            credential_id,
            bytes,
        ):
            return None

        with self._lock:
            return self._credentials.get(
                credential_id
            )

    def list_for_user(
        self,
        user_id: str,
    ) -> list[PasskeyCredential]:
        with self._lock:
            return [
                credential
                for credential
                in self._credentials.values()
                if credential.user_id
                == user_id
            ]

    # ============================================================
    # USAGE UPDATE
    # ============================================================

    def update_usage(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        last_used_at: datetime,
    ) -> None:
        with self._lock:
            credential = (
                self._credentials.get(
                    credential_id
                )
            )

            if credential is None:
                raise KeyError(
                    "Passkey credential not found."
                )

            credential.sign_count = (
                sign_count
            )

            credential.last_used_at = (
                last_used_at
            )

    # ============================================================
    # DELETE
    # ============================================================

    def delete(
        self,
        user_id: str,
        credential_id: bytes,
    ) -> bool:
        with self._lock:
            credential = (
                self._credentials.get(
                    credential_id
                )
            )

            if credential is None:
                return False

            if credential.user_id != user_id:
                return False

            del self._credentials[
                credential_id
            ]

            return True