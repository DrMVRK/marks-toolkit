from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass
class SessionRecord:
    id: str
    user_id: int | str
    auth_id: str

    created_at: datetime
    last_seen_at: datetime

    ip_address: str | None = None
    user_agent: str | None = None

    authentication_method: str | None = None
    remembered: bool = False

    revoked_at: datetime | None = None


class SessionStore(Protocol):

    def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        """
        Persist a new authenticated session.

        Session IDs must be unique.
        """
        ...

    def get(
        self,
        session_id: str,
    ) -> SessionRecord | None:
        """
        Return a session by its opaque session ID.
        """
        ...

    def list_for_user(
        self,
        user_id: int | str,
        *,
        include_revoked: bool = False,
    ) -> list[SessionRecord]:
        """
        Return sessions belonging to the user.

        Revoked sessions are excluded by default.
        """
        ...

    def touch(
        self,
        session_id: str,
        *,
        user_id: int | str,
        last_seen_at: datetime,
    ) -> bool:
        """
        Update last_seen_at for an active session.

        Return False if the session does not exist,
        belongs to another user, or is revoked.
        """
        ...

    def revoke(
        self,
        session_id: str,
        *,
        user_id: int | str,
        revoked_at: datetime,
    ) -> bool:
        """
        Revoke one active session owned by the user.

        Return False if the session does not exist,
        belongs to another user, or was already revoked.
        """
        ...

    def revoke_others(
        self,
        user_id: int | str,
        *,
        current_session_id: str,
        revoked_at: datetime,
    ) -> int:
        """
        Revoke every active session for the user except
        the supplied current session.

        Return the number of sessions revoked.
        """
        ...

    def revoke_all(
        self,
        user_id: int | str,
        *,
        revoked_at: datetime,
    ) -> int:
        """
        Revoke every active session belonging to the user.

        Return the number of sessions revoked.
        """
        ...