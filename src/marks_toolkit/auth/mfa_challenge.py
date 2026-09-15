import secrets
import time

from flask import session

from .exceptions import AuthError


class MFAChallengeError(AuthError):
    code = "INVALID_MFA_CHALLENGE"
    status_code = 401


class MFAChallengeService:

    SESSION_KEY = "_marks_auth_mfa_challenge"

    def __init__(self, ttl_seconds=300):
        self.ttl_seconds = ttl_seconds

    def create(
        self,
        user,
        remember=False,
    ):
        challenge_id = secrets.token_urlsafe(32)

        session[self.SESSION_KEY] = {
            "challenge_id": challenge_id,
            "auth_id": user.auth_id,
            "remember": bool(remember),
            "created_at": int(time.time()),
        }

        session.modified = True

        return challenge_id

    def get(self, challenge_id):
        challenge = session.get(
            self.SESSION_KEY
        )

        if not isinstance(challenge, dict):
            raise MFAChallengeError(
                "MFA challenge is invalid or expired."
            )

        stored_challenge_id = challenge.get(
            "challenge_id"
        )

        if not stored_challenge_id:
            self.clear()

            raise MFAChallengeError(
                "MFA challenge is invalid or expired."
            )

        if not secrets.compare_digest(
            stored_challenge_id,
            str(challenge_id or ""),
        ):
            raise MFAChallengeError(
                "MFA challenge is invalid or expired."
            )

        created_at = challenge.get(
            "created_at"
        )

        if not isinstance(created_at, int):
            self.clear()

            raise MFAChallengeError(
                "MFA challenge is invalid or expired."
            )

        age = int(time.time()) - created_at

        if age > self.ttl_seconds:
            self.clear()

            raise MFAChallengeError(
                "MFA challenge is invalid or expired."
            )

        auth_id = challenge.get("auth_id")

        if not auth_id:
            self.clear()

            raise MFAChallengeError(
                "MFA challenge is invalid or expired."
            )

        return {
            "auth_id": auth_id,
            "remember": bool(
                challenge.get(
                    "remember",
                    False,
                )
            ),
        }

    def clear(self):
        session.pop(
            self.SESSION_KEY,
            None,
        )

        session.modified = True