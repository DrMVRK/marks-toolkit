from abc import ABC, abstractmethod
from dataclasses import dataclass
from threading import Lock
import json
import time

import redis


@dataclass(frozen=True)
class MFAChallengeRecord:
    challenge_id: str
    auth_id: str
    remember: bool
    created_at: int


class MFAChallengeStore(ABC):
    """
    Persistent/server-side storage contract for
    pending MFA challenges.

    Challenge state must not rely solely on Flask's
    client-side signed session cookie because an older
    valid cookie could otherwise restore a previously
    completed challenge.
    """

    @abstractmethod
    def create(
        self,
        record: MFAChallengeRecord,
        ttl_seconds: int,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def get(
        self,
        challenge_id: str,
    ) -> MFAChallengeRecord | None:
        raise NotImplementedError

    @abstractmethod
    def consume(
        self,
        challenge_id: str,
    ) -> MFAChallengeRecord | None:
        """
        Atomically return and delete a challenge.

        Exactly one caller may successfully consume
        a challenge.
        """
        raise NotImplementedError

    @abstractmethod
    def delete(
        self,
        challenge_id: str,
    ) -> None:
        raise NotImplementedError


class MemoryMFAChallengeStore(MFAChallengeStore):
    """
    Thread-safe in-memory challenge store.

    Suitable for:
    - tests
    - local development
    - single-process demonstrations

    Not suitable for multi-worker production deployments.
    """

    def __init__(self):
        self._records = {}
        self._expires_at = {}
        self._lock = Lock()

    def _remove_if_expired(
        self,
        challenge_id: str,
        now: float | None = None,
    ) -> bool:
        if now is None:
            now = time.time()

        expires_at = self._expires_at.get(
            challenge_id
        )

        if expires_at is None:
            return False

        if now < expires_at:
            return False

        self._records.pop(
            challenge_id,
            None,
        )

        self._expires_at.pop(
            challenge_id,
            None,
        )

        return True

    def create(
        self,
        record: MFAChallengeRecord,
        ttl_seconds: int,
    ) -> None:
        expires_at = (
            time.time()
            + ttl_seconds
        )

        with self._lock:
            self._records[
                record.challenge_id
            ] = record

            self._expires_at[
                record.challenge_id
            ] = expires_at

    def get(
        self,
        challenge_id: str,
    ) -> MFAChallengeRecord | None:
        with self._lock:
            if self._remove_if_expired(
                challenge_id
            ):
                return None

            return self._records.get(
                challenge_id
            )

    def consume(
        self,
        challenge_id: str,
    ) -> MFAChallengeRecord | None:
        with self._lock:
            if self._remove_if_expired(
                challenge_id
            ):
                return None

            record = self._records.pop(
                challenge_id,
                None,
            )

            self._expires_at.pop(
                challenge_id,
                None,
            )

            return record

    def delete(
        self,
        challenge_id: str,
    ) -> None:
        with self._lock:
            self._records.pop(
                challenge_id,
                None,
            )

            self._expires_at.pop(
                challenge_id,
                None,
            )


class RedisMFAChallengeStore(MFAChallengeStore):
    """
    Redis-backed MFA challenge store.

    Suitable for multi-worker and multi-process
    deployments where every application worker shares
    the same Redis instance.
    """

    KEY_PREFIX = "marks-auth:mfa-challenge:"

    def __init__(
        self,
        redis_url: str,
    ):
        if not redis_url:
            raise ValueError(
                "Redis URL is required."
            )

        self.redis = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
        )

    def _key(
        self,
        challenge_id: str,
    ) -> str:
        return (
            self.KEY_PREFIX
            + challenge_id
        )

    def _serialize(
        self,
        record: MFAChallengeRecord,
    ) -> str:
        return json.dumps(
            {
                "challenge_id":
                    record.challenge_id,
                "auth_id":
                    record.auth_id,
                "remember":
                    record.remember,
                "created_at":
                    record.created_at,
            },
            separators=(",", ":"),
        )

    def _deserialize(
        self,
        value,
    ) -> MFAChallengeRecord | None:
        if not isinstance(
            value,
            str,
        ):
            return None

        try:
            data = json.loads(
                value
            )

            challenge_id = data[
                "challenge_id"
            ]

            auth_id = data[
                "auth_id"
            ]

            remember = data[
                "remember"
            ]

            created_at = data[
                "created_at"
            ]

            if not isinstance(
                challenge_id,
                str,
            ):
                return None

            if not isinstance(
                auth_id,
                str,
            ):
                return None

            if not isinstance(
                remember,
                bool,
            ):
                return None

            if not isinstance(
                created_at,
                int,
            ):
                return None

            return MFAChallengeRecord(
                challenge_id=challenge_id,
                auth_id=auth_id,
                remember=remember,
                created_at=created_at,
            )

        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            return None

    def create(
        self,
        record: MFAChallengeRecord,
        ttl_seconds: int,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError(
                "MFA challenge TTL must be "
                "greater than zero."
            )

        self.redis.set(
            self._key(
                record.challenge_id
            ),
            self._serialize(
                record
            ),
            ex=ttl_seconds,
        )

    def get(
        self,
        challenge_id: str,
    ) -> MFAChallengeRecord | None:
        value = self.redis.get(
            self._key(
                challenge_id
            )
        )

        return self._deserialize(
            value
        )

    def consume(
        self,
        challenge_id: str,
    ) -> MFAChallengeRecord | None:
        value = self.redis.getdel(
            self._key(
                challenge_id
            )
        )

        return self._deserialize(
            value
        )

    def delete(
        self,
        challenge_id: str,
    ) -> None:
        self.redis.delete(
            self._key(
                challenge_id
            )
        )