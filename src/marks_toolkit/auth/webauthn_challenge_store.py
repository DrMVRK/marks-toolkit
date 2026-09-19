import base64
import json
from dataclasses import dataclass
from threading import Lock
from time import time
from typing import Protocol

from redis import Redis


@dataclass
class WebAuthnChallenge:
    id: str
    challenge: bytes
    ceremony: str
    user_id: int | str | None
    expires_at: float
    user_handle: bytes | None = None


class WebAuthnChallengeStore(Protocol):
    def create(
        self,
        challenge: WebAuthnChallenge,
    ) -> None:
        ...

    def consume(
        self,
        challenge_id: str,
    ) -> WebAuthnChallenge | None:
        ...

    def delete(
        self,
        challenge_id: str,
    ) -> bool:
        ...


# ============================================================
# MEMORY STORE
# ============================================================


class MemoryWebAuthnChallengeStore:
    def __init__(self):
        self._challenges: dict[
            str,
            WebAuthnChallenge,
        ] = {}

        self._lock = Lock()

    def create(
        self,
        challenge: WebAuthnChallenge,
    ) -> None:
        if not isinstance(
            challenge,
            WebAuthnChallenge,
        ):
            raise TypeError(
                "challenge must be a "
                "WebAuthnChallenge"
            )

        with self._lock:
            self._cleanup_expired_locked()

            if (
                challenge.id
                in self._challenges
            ):
                raise ValueError(
                    "WebAuthn challenge already exists."
                )

            self._challenges[
                challenge.id
            ] = challenge

    def consume(
        self,
        challenge_id: str,
    ) -> WebAuthnChallenge | None:
        with self._lock:
            self._cleanup_expired_locked()

            challenge = (
                self._challenges.pop(
                    challenge_id,
                    None,
                )
            )

            if challenge is None:
                return None

            if (
                challenge.expires_at
                <= time()
            ):
                return None

            return challenge

    def delete(
        self,
        challenge_id: str,
    ) -> bool:
        with self._lock:
            return (
                self._challenges.pop(
                    challenge_id,
                    None,
                )
                is not None
            )

    def _cleanup_expired_locked(
        self,
    ) -> None:
        now = time()

        expired_ids = [
            challenge_id
            for (
                challenge_id,
                challenge,
            )
            in self._challenges.items()
            if (
                challenge.expires_at
                <= now
            )
        ]

        for challenge_id in expired_ids:
            self._challenges.pop(
                challenge_id,
                None,
            )


# ============================================================
# REDIS STORE
# ============================================================


class RedisWebAuthnChallengeStore:
    _CONSUME_SCRIPT = """
local value = redis.call(
    'GET',
    KEYS[1]
)

if not value then
    return nil
end

redis.call(
    'DEL',
    KEYS[1]
)

return value
"""

    def __init__(
        self,
        redis_url,
        key_prefix="marks:auth",
        socket_connect_timeout=2.0,
        socket_timeout=2.0,
    ):
        if not redis_url:
            raise ValueError(
                "Redis URL is required."
            )

        self.redis = Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=(
                socket_connect_timeout
            ),
            socket_timeout=(
                socket_timeout
            ),
            health_check_interval=30,
        )

        self.key_prefix = (
            key_prefix
        )

    def _redis_key(
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
            raise ValueError(
                "A valid challenge ID "
                "is required."
            )

        return (
            f"{self.key_prefix}:"
            f"webauthn:challenge:"
            f"{challenge_id}"
        )

    def _serialize(
        self,
        challenge,
    ):
        if not isinstance(
            challenge,
            WebAuthnChallenge,
        ):
            raise TypeError(
                "challenge must be a "
                "WebAuthnChallenge"
            )

        return json.dumps(
            {
                "id":
                    challenge.id,

                "challenge":
                    base64.urlsafe_b64encode(
                        challenge.challenge
                    ).decode("ascii"),

                "ceremony":
                    challenge.ceremony,

                "user_id":
                    challenge.user_id,

                "expires_at":
                    challenge.expires_at,

                "user_handle": (
                    base64.urlsafe_b64encode(
                        challenge.user_handle
                    ).decode("ascii")
                    if (
                        challenge.user_handle
                        is not None
                    )
                    else None
                ),
            },
            separators=(",", ":"),
        )

    def _deserialize(
        self,
        value,
    ):
        try:
            data = json.loads(
                value
            )

            user_handle = (
                base64.urlsafe_b64decode(
                    data["user_handle"]
                )
                if (
                    data.get(
                        "user_handle"
                    )
                    is not None
                )
                else None
            )

            return WebAuthnChallenge(
                id=data["id"],

                challenge=(
                    base64.urlsafe_b64decode(
                        data["challenge"]
                    )
                ),

                ceremony=(
                    data["ceremony"]
                ),

                user_id=(
                    data.get(
                        "user_id"
                    )
                ),

                expires_at=float(
                    data["expires_at"]
                ),

                user_handle=(
                    user_handle
                ),
            )

        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise ValueError(
                "Stored WebAuthn challenge "
                "is invalid."
            ) from error

    def create(
        self,
        challenge: WebAuthnChallenge,
    ) -> None:
        now = time()

        ttl_seconds = (
            challenge.expires_at
            - now
        )

        if ttl_seconds <= 0:
            raise ValueError(
                "WebAuthn challenge is "
                "already expired."
            )

        redis_key = self._redis_key(
            challenge.id
        )

        payload = self._serialize(
            challenge
        )

        created = self.redis.set(
            redis_key,
            payload,
            ex=max(
                1,
                int(
                    ttl_seconds
                    + 0.999999
                ),
            ),
            nx=True,
        )

        if not created:
            raise ValueError(
                "WebAuthn challenge "
                "already exists."
            )

    def consume(
        self,
        challenge_id: str,
    ) -> WebAuthnChallenge | None:
        redis_key = self._redis_key(
            challenge_id
        )

        value = self.redis.eval(
            self._CONSUME_SCRIPT,
            1,
            redis_key,
        )

        if value is None:
            return None

        challenge = (
            self._deserialize(
                value
            )
        )

        if (
            challenge.expires_at
            <= time()
        ):
            return None

        return challenge

    def delete(
        self,
        challenge_id: str,
    ) -> bool:
        redis_key = self._redis_key(
            challenge_id
        )

        return bool(
            self.redis.delete(
                redis_key
            )
        )