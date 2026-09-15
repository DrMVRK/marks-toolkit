from abc import ABC, abstractmethod
from dataclasses import dataclass
from threading import Lock
import time


@dataclass(frozen=True)
class MFAChallengeRecord:
    challenge_id: str
    auth_id: str
    remember: bool
    created_at: int


class MFAChallengeStore(ABC):
    """
    Persistent/server-side storage contract for pending MFA challenges.

    Challenge state must not rely solely on Flask's client-side
    signed session cookie because an older valid cookie could otherwise
    restore a previously completed challenge.
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

        Exactly one caller may successfully consume a challenge.
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