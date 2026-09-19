from time import time

from marks_toolkit.auth.webauthn_challenge_store import (
    MemoryWebAuthnChallengeStore,
    WebAuthnChallenge,
)


def make_challenge(
    *,
    challenge_id="challenge-1",
    expires_at=None,
):
    if expires_at is None:
        expires_at = time() + 300

    return WebAuthnChallenge(
        id=challenge_id,
        challenge=b"challenge-bytes",
        ceremony="registration",
        user_id=1,
        expires_at=expires_at,
    )


def test_create_and_consume_challenge():
    store = MemoryWebAuthnChallengeStore()

    challenge = make_challenge()

    store.create(challenge)

    consumed = store.consume(
        "challenge-1"
    )

    assert consumed == challenge


def test_challenge_is_single_use():
    store = MemoryWebAuthnChallengeStore()

    store.create(
        make_challenge()
    )

    first = store.consume(
        "challenge-1"
    )

    second = store.consume(
        "challenge-1"
    )

    assert first is not None
    assert second is None


def test_expired_challenge_cannot_be_consumed():
    store = MemoryWebAuthnChallengeStore()

    store.create(
        make_challenge(
            expires_at=time() - 1
        )
    )

    consumed = store.consume(
        "challenge-1"
    )

    assert consumed is None


def test_delete_challenge():
    store = MemoryWebAuthnChallengeStore()

    store.create(
        make_challenge()
    )

    assert (
        store.delete(
            "challenge-1"
        )
        is True
    )

    assert (
        store.consume(
            "challenge-1"
        )
        is None
    )


def test_delete_missing_challenge():
    store = MemoryWebAuthnChallengeStore()

    assert (
        store.delete(
            "missing"
        )
        is False
    )


def test_expired_challenges_are_cleaned():
    store = MemoryWebAuthnChallengeStore()

    store.create(
        make_challenge(
            challenge_id="expired",
            expires_at=time() - 1,
        )
    )

    store.create(
        make_challenge(
            challenge_id="active",
        )
    )

    assert (
        store.consume(
            "expired"
        )
        is None
    )

    assert (
        store.consume(
            "active"
        )
        is not None
    )