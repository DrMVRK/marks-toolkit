from dataclasses import replace
from threading import Lock

from .session_store import (
    SessionRecord,
    SessionStore,
)


class MemorySessionStore(SessionStore):

    def __init__(self):
        self._sessions: dict[
            str,
            SessionRecord,
        ] = {}

        self._lock = Lock()

    def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        if not isinstance(
            session,
            SessionRecord,
        ):
            raise TypeError(
                "session must be a SessionRecord."
            )

        if not session.id:
            raise ValueError(
                "Session ID is required."
            )

        with self._lock:
            if (
                session.id
                in self._sessions
            ):
                raise ValueError(
                    "Session ID already exists."
                )

            stored = replace(
                session
            )

            self._sessions[
                session.id
            ] = stored

            return replace(
                stored
            )

    def get(
        self,
        session_id: str,
    ) -> SessionRecord | None:
        with self._lock:
            record = (
                self._sessions.get(
                    session_id
                )
            )

            if record is None:
                return None

            return replace(
                record
            )

    def list_for_user(
        self,
        user_id,
        *,
        include_revoked=False,
    ):
        with self._lock:
            records = [
                replace(record)
                for record
                in self._sessions.values()
                if (
                    record.user_id
                    == user_id
                    and (
                        include_revoked
                        or record.revoked_at
                        is None
                    )
                )
            ]

        records.sort(
            key=lambda record:
                record.created_at,
            reverse=True,
        )

        return records

    def touch(
        self,
        session_id,
        *,
        user_id,
        last_seen_at,
    ):
        with self._lock:
            record = (
                self._sessions.get(
                    session_id
                )
            )

            if record is None:
                return False

            if (
                record.user_id
                != user_id
            ):
                return False

            if (
                record.revoked_at
                is not None
            ):
                return False

            record.last_seen_at = (
                last_seen_at
            )

            return True

    def revoke(
        self,
        session_id,
        *,
        user_id,
        revoked_at,
    ):
        with self._lock:
            record = (
                self._sessions.get(
                    session_id
                )
            )

            if record is None:
                return False

            if (
                record.user_id
                != user_id
            ):
                return False

            if (
                record.revoked_at
                is not None
            ):
                return False

            record.revoked_at = (
                revoked_at
            )

            return True

    def revoke_others(
        self,
        user_id,
        *,
        current_session_id,
        revoked_at,
    ):
        revoked_count = 0

        with self._lock:
            for record in (
                self._sessions.values()
            ):
                if (
                    record.user_id
                    != user_id
                ):
                    continue

                if (
                    record.id
                    == current_session_id
                ):
                    continue

                if (
                    record.revoked_at
                    is not None
                ):
                    continue

                record.revoked_at = (
                    revoked_at
                )

                revoked_count += 1

        return revoked_count

    def revoke_all(
        self,
        user_id,
        *,
        revoked_at,
    ):
        revoked_count = 0

        with self._lock:
            for record in (
                self._sessions.values()
            ):
                if (
                    record.user_id
                    != user_id
                ):
                    continue

                if (
                    record.revoked_at
                    is not None
                ):
                    continue

                record.revoked_at = (
                    revoked_at
                )

                revoked_count += 1

        return revoked_count