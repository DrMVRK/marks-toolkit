from datetime import (
    datetime,
    timedelta,
    timezone,
)
import secrets

from .session_store import (
    SessionRecord,
)


def _utcnow():
    return datetime.now(
        timezone.utc
    )


class SessionService:

    def __init__(
        self,
        *,
        session_store,
        touch_interval_seconds=60,
    ):
        if (
            not isinstance(
                touch_interval_seconds,
                int,
            )
            or touch_interval_seconds < 0
        ):
            raise ValueError(
                "touch_interval_seconds must "
                "be a non-negative integer."
            )

        self.session_store = (
            session_store
        )

        self.touch_interval = (
            timedelta(
                seconds=(
                    touch_interval_seconds
                )
            )
        )

    # ============================================================
    # CREATE
    # ============================================================

    def create_session(
        self,
        *,
        user,
        ip_address=None,
        user_agent=None,
        authentication_method=None,
        remembered=False,
        now=None,
    ) -> SessionRecord:
        if user is None:
            raise ValueError(
                "A user is required."
            )

        user_id = getattr(
            user,
            "id",
            None,
        )

        auth_id = getattr(
            user,
            "auth_id",
            None,
        )

        if user_id is None:
            raise ValueError(
                "User does not have a "
                "persistent ID."
            )

        if not auth_id:
            raise ValueError(
                "User does not have an "
                "authentication ID."
            )

        created_at = (
            now
            if now is not None
            else _utcnow()
        )

        session_id = (
            secrets.token_urlsafe(32)
        )

        record = SessionRecord(
            id=session_id,
            user_id=user_id,
            auth_id=auth_id,
            created_at=created_at,
            last_seen_at=created_at,
            ip_address=ip_address,
            user_agent=user_agent,
            authentication_method=(
                authentication_method
            ),
            remembered=bool(
                remembered
            ),
            revoked_at=None,
        )

        return (
            self.session_store.create(
                record
            )
        )

    # ============================================================
    # VALIDATE
    # ============================================================

    def validate_session(
        self,
        *,
        session_id,
        user,
        now=None,
    ) -> bool:
        if not session_id:
            return False

        if user is None:
            return False

        user_id = getattr(
            user,
            "id",
            None,
        )

        auth_id = getattr(
            user,
            "auth_id",
            None,
        )

        if (
            user_id is None
            or not auth_id
        ):
            return False

        record = (
            self.session_store.get(
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
            record.auth_id
            != auth_id
        ):
            return False

        if (
            record.revoked_at
            is not None
        ):
            return False

        checked_at = (
            now
            if now is not None
            else _utcnow()
        )

        if (
            checked_at
            - record.last_seen_at
            >= self.touch_interval
        ):
            touched = (
                self.session_store.touch(
                    session_id,
                    user_id=user_id,
                    last_seen_at=(
                        checked_at
                    ),
                )
            )

            if not touched:
                return False

        return True

    # ============================================================
    # REVOKE CURRENT
    # ============================================================

    def revoke_session(
        self,
        *,
        session_id,
        user,
        now=None,
    ) -> bool:
        if (
            not session_id
            or user is None
        ):
            return False

        user_id = getattr(
            user,
            "id",
            None,
        )

        if user_id is None:
            return False

        revoked_at = (
            now
            if now is not None
            else _utcnow()
        )

        return (
            self.session_store.revoke(
                session_id,
                user_id=user_id,
                revoked_at=revoked_at,
            )
        )

    # ============================================================
    # REVOKE OTHERS
    # ============================================================

    def revoke_other_sessions(
        self,
        *,
        current_session_id,
        user,
        now=None,
    ) -> int:
        if user is None:
            return 0

        user_id = getattr(
            user,
            "id",
            None,
        )

        if (
            user_id is None
            or not current_session_id
        ):
            return 0

        revoked_at = (
            now
            if now is not None
            else _utcnow()
        )

        return (
            self.session_store
            .revoke_others(
                user_id,
                current_session_id=(
                    current_session_id
                ),
                revoked_at=(
                    revoked_at
                ),
            )
        )

    # ============================================================
    # REVOKE ALL
    # ============================================================

    def revoke_all_sessions(
        self,
        *,
        user,
        now=None,
    ) -> int:
        if user is None:
            return 0

        user_id = getattr(
            user,
            "id",
            None,
        )

        if user_id is None:
            return 0

        revoked_at = (
            now
            if now is not None
            else _utcnow()
        )

        return (
            self.session_store
            .revoke_all(
                user_id,
                revoked_at=(
                    revoked_at
                ),
            )
        )