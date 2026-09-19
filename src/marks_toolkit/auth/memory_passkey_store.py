from dataclasses import replace
from threading import Lock

from .passkey_store import (
    PasskeyCredential,
    PasskeyStore,
)


class MemoryPasskeyStore(PasskeyStore):
    def __init__(self):
        self._credentials = {}
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

        if not isinstance(
            credential.credential_id,
            bytes,
        ):
            raise TypeError(
                "credential_id must be bytes"
            )

        with self._lock:
            if (
                credential.credential_id
                in self._credentials
            ):
                raise ValueError(
                    "Passkey credential already exists."
                )

            self._credentials[
                credential.credential_id
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
        user_id: int | str,
    ) -> list[PasskeyCredential]:
        with self._lock:
            credentials = [
                credential
                for credential
                in self._credentials.values()
                if credential.user_id
                == user_id
            ]

            return sorted(
                credentials,
                key=lambda credential: (
                    credential.created_at,
                    str(
                        credential.id
                        if credential.id
                        is not None
                        else ""
                    ),
                ),
            )

    # ============================================================
    # NAME UPDATE
    # ============================================================

    def update_name(
        self,
        user_id: int | str,
        credential_id: bytes,
        *,
        name: str | None,
    ) -> bool:
        with self._lock:
            credential = (
                self._credentials.get(
                    credential_id
                )
            )

            if credential is None:
                return False

            if (
                credential.user_id
                != user_id
            ):
                return False

            self._credentials[
                credential_id
            ] = replace(
                credential,
                name=name,
            )

            return True

    # ============================================================
    # USAGE UPDATE
    # ============================================================

    def update_usage(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        last_used_at,
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

            self._credentials[
                credential_id
            ] = replace(
                credential,
                sign_count=sign_count,
                last_used_at=last_used_at,
            )

    # ============================================================
    # DELETE
    # ============================================================

    def delete(
        self,
        user_id: int | str,
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

            if (
                credential.user_id
                != user_id
            ):
                return False

            del self._credentials[
                credential_id
            ]

            return True