from dataclasses import dataclass
from threading import Lock
from time import time
from typing import Protocol


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

            challenge = self._challenges.pop(
                challenge_id,
                None,
            )

            if challenge is None:
                return None

            if challenge.expires_at <= time():
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
            if challenge.expires_at <= now
        ]

        for challenge_id in expired_ids:
            self._challenges.pop(
                challenge_id,
                None,
            )