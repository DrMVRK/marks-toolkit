import secrets
import time

from flask import session

from .exceptions import AuthError
from .mfa_challenge_store import (
    MFAChallengeRecord,
    MFAChallengeStore,
)


class MFAChallengeError(AuthError):
    code = "INVALID_MFA_CHALLENGE"
    status_code = 401


class MFAChallengeService:
    SESSION_KEY = "_marks_auth_mfa_challenge"

    def __init__(
        self,
        store: MFAChallengeStore,
        ttl_seconds: int = 300,
    ):
        self.store = store
        self.ttl_seconds = ttl_seconds

    def create(
        self,
        user,
        remember=False,
    ):
        challenge_id = (
            secrets.token_urlsafe(32)
        )

        record = MFAChallengeRecord(
            challenge_id=challenge_id,
            auth_id=str(
                user.auth_id
            ),
            remember=bool(
                remember
            ),
            created_at=int(time.time()),
        )

        self.store.create(
            record,
            self.ttl_seconds,
        )

        session[
            self.SESSION_KEY
        ] = challenge_id

        session.modified = True

        return challenge_id

    def get(
        self,
        challenge_id,
    ):
        if (
            not isinstance(
                challenge_id,
                str,
            )
            or not challenge_id
        ):
            raise MFAChallengeError(
                "Invalid MFA challenge."
            )

        session_challenge_id = (
            session.get(
                self.SESSION_KEY
            )
        )

        if (
            not isinstance(
                session_challenge_id,
                str,
            )
            or not secrets.compare_digest(
                session_challenge_id,
                challenge_id,
            )
        ):
            raise MFAChallengeError(
                "Invalid MFA challenge."
            )

        record = self.store.get(
            challenge_id
        )

        if record is None:
            self.clear_session()

            raise MFAChallengeError(
                "Invalid or expired MFA challenge."
            )

        return {
            "auth_id":
                record.auth_id,

            "remember":
                record.remember,
        }

    def consume(
        self,
        challenge_id,
    ):
        """
        Atomically consume a successfully verified challenge.

        A challenge that has already been consumed cannot be restored
        by replaying an older Flask session cookie.
        """

        if (
            not isinstance(
                challenge_id,
                str,
            )
            or not challenge_id
        ):
            raise MFAChallengeError(
                "Invalid MFA challenge."
            )

        session_challenge_id = (
            session.get(
                self.SESSION_KEY
            )
        )

        if (
            not isinstance(
                session_challenge_id,
                str,
            )
            or not secrets.compare_digest(
                session_challenge_id,
                challenge_id,
            )
        ):
            raise MFAChallengeError(
                "Invalid MFA challenge."
            )

        record = self.store.consume(
            challenge_id
        )

        self.clear_session()

        if record is None:
            raise MFAChallengeError(
                "Invalid or expired MFA challenge."
            )

        return {
            "auth_id":
                record.auth_id,

            "remember":
                record.remember,
        }

    def clear(
        self):
        challenge_id = session.get(
            self.SESSION_KEY
        )

        if isinstance(
            challenge_id,
            str,
        ):
            self.store.delete(
                challenge_id
            )

        self.clear_session()

    def clear_session(self):
        session.pop(
            self.SESSION_KEY,
            None,
        )

        session.modified = True