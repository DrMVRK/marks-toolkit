from datetime import (
    datetime,
    timezone,
)
import secrets


class SessionService:
    def __init__(
        self,
        *,
        session_store,
        touch_interval_seconds=60,
        idle_timeout_seconds=43200,
        absolute_timeout_seconds=604800,
        remembered_absolute_timeout_seconds=2592000,
    ):
        self.session_store = session_store

        self.touch_interval_seconds = (
            self._validate_timeout(
                touch_interval_seconds,
                "touch_interval_seconds",
                allow_zero=True,
            )
        )

        self.idle_timeout_seconds = (
            self._validate_timeout(
                idle_timeout_seconds,
                "idle_timeout_seconds",
                allow_zero=True,
            )
        )

        self.absolute_timeout_seconds = (
            self._validate_timeout(
                absolute_timeout_seconds,
                "absolute_timeout_seconds",
                allow_zero=True,
            )
        )

        self.remembered_absolute_timeout_seconds = (
            self._validate_timeout(
                remembered_absolute_timeout_seconds,
                (
                    "remembered_absolute_"
                    "timeout_seconds"
                ),
                allow_zero=True,
            )
        )


    @staticmethod
    def _validate_timeout(
        value,
        name,
        *,
        allow_zero,
    ):
        if isinstance(
            value,
            bool,
        ):
            raise TypeError(
                f"{name} must be an integer."
            )

        if not isinstance(
            value,
            int,
        ):
            raise TypeError(
                f"{name} must be an integer."
            )

        minimum = (
            0
            if allow_zero
            else 1
        )

        if value < minimum:
            raise ValueError(
                f"{name} must be at least "
                f"{minimum}."
            )

        return value


    @staticmethod
    def _utc_now():
        return datetime.now(
            timezone.utc
        )


    @staticmethod
    def _as_utc(
        value,
    ):
        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value.astimezone(
            timezone.utc
        )


    def create_session(
        self,
        *,
        user,
        ip_address=None,
        user_agent=None,
        authentication_method=None,
        remembered=False,
        now=None,
    ):
        if now is None:
            now = self._utc_now()

        now = self._as_utc(
            now
        )

        if user is None:
            raise ValueError(
                "user is required"
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
                "User must have an ID."
            )

        if (
            not isinstance(
                auth_id,
                str,
            )
            or not auth_id
        ):
            raise ValueError(
                "User must have an auth ID."
            )

        from .session_store import (
            SessionRecord,
        )

        record = SessionRecord(
            id=secrets.token_urlsafe(
                32
            ),
            user_id=user_id,
            auth_id=auth_id,
            created_at=now,
            last_seen_at=now,
            ip_address=ip_address,
            user_agent=user_agent,
            authentication_method=(
                authentication_method
            ),
            remembered=bool(
                remembered
            ),
        )

        return (
            self.session_store.create(
                record
            )
        )


    def _is_idle_expired(
        self,
        record,
        now,
    ):
        if (
            self.idle_timeout_seconds
            == 0
        ):
            return False

        last_seen = self._as_utc(
            record.last_seen_at
        )

        elapsed = (
            now
            - last_seen
        ).total_seconds()

        return (
            elapsed
            >= self.idle_timeout_seconds
        )


    def _is_absolute_expired(
        self,
        record,
        now,
    ):
        if record.remembered:
            timeout = (
                self
                .remembered_absolute_timeout_seconds
            )
        else:
            timeout = (
                self
                .absolute_timeout_seconds
            )

        if timeout == 0:
            return False

        created_at = self._as_utc(
            record.created_at
        )

        elapsed = (
            now
            - created_at
        ).total_seconds()

        return elapsed >= timeout


    def _expire_record(
        self,
        record,
        *,
        now,
    ):
        self.session_store.revoke(
            record.id,
            user_id=record.user_id,
            revoked_at=now,
        )


    def validate_session(
        self,
        *,
        session_id,
        user,
        now=None,
    ):
        if (
            not isinstance(
                session_id,
                str,
            )
            or not session_id
        ):
            return False

        if now is None:
            now = self._utc_now()

        now = self._as_utc(
            now
        )

        record = (
            self.session_store.get(
                session_id
            )
        )

        if record is None:
            return False

        if (
            record.revoked_at
            is not None
        ):
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
            record.user_id
            != user_id
        ):
            return False

        if (
            record.auth_id
            != auth_id
        ):
            return False

        if self._is_idle_expired(
            record,
            now,
        ):
            self._expire_record(
                record,
                now=now,
            )

            return False

        if self._is_absolute_expired(
            record,
            now,
        ):
            self._expire_record(
                record,
                now=now,
            )

            return False

        last_seen = self._as_utc(
            record.last_seen_at
        )

        seconds_since_touch = (
            now
            - last_seen
        ).total_seconds()

        if (
            seconds_since_touch
            >= self.touch_interval_seconds
        ):
            self.session_store.touch(
                session_id,
                user_id=user_id,
                last_seen_at=now,
            )

        return True


    def revoke_session(
        self,
        *,
        session_id,
        user,
        now=None,
    ):
        if now is None:
            now = self._utc_now()

        now = self._as_utc(
            now
        )

        user_id = getattr(
            user,
            "id",
            None,
        )

        if user_id is None:
            return False

        return (
            self.session_store.revoke(
                session_id,
                user_id=user_id,
                revoked_at=now,
            )
        )


    def revoke_other_sessions(
        self,
        *,
        current_session_id,
        user,
        now=None,
    ):
        if now is None:
            now = self._utc_now()

        now = self._as_utc(
            now
        )

        user_id = getattr(
            user,
            "id",
            None,
        )

        if user_id is None:
            return 0

        return (
            self.session_store
            .revoke_others(
                user_id,
                current_session_id=(
                    current_session_id
                ),
                revoked_at=now,
            )
        )


    def revoke_all_sessions(
        self,
        *,
        user,
        now=None,
    ):
        if now is None:
            now = self._utc_now()

        now = self._as_utc(
            now
        )

        user_id = getattr(
            user,
            "id",
            None,
        )

        if user_id is None:
            return 0

        return (
            self.session_store
            .revoke_all(
                user_id,
                revoked_at=now,
            )
        )