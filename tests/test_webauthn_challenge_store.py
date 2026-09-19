import time

import pytest

from marks_toolkit.auth.webauthn_challenge_store import (
    MemoryWebAuthnChallengeStore,
    RedisWebAuthnChallengeStore,
    WebAuthnChallenge,
)


class FakeRedis:
    """
    Minimal Redis stand-in for testing
    WebAuthn challenge storage without
    requiring a live Redis server.
    """

    def __init__(self):
        self.values = {}

    def set(
        self,
        key,
        value,
        *,
        ex=None,
        nx=False,
    ):
        if nx and key in self.values:
            return False

        self.values[key] = {
            "value": value,
            "expires_at": (
                time.time() + ex
                if ex is not None
                else None
            ),
        }

        return True

    def eval(
        self,
        script,
        number_of_keys,
        *args,
    ):
        assert number_of_keys == 1

        key = args[0]

        if (
            script
            != RedisWebAuthnChallengeStore
            ._CONSUME_SCRIPT
        ):
            raise AssertionError(
                "Unexpected Redis Lua script."
            )

        record = self.values.get(
            key
        )

        if record is None:
            return None

        expires_at = record[
            "expires_at"
        ]

        if (
            expires_at is not None
            and expires_at
            <= time.time()
        ):
            self.values.pop(
                key,
                None,
            )

            return None

        self.values.pop(
            key,
            None,
        )

        return record["value"]

    def delete(
        self,
        key,
    ):
        existed = (
            key in self.values
        )

        self.values.pop(
            key,
            None,
        )

        return int(existed)


def make_redis_store():
    store = (
        RedisWebAuthnChallengeStore(
            "redis://localhost:6379/0"
        )
    )

    store.redis = FakeRedis()

    return store


def make_challenge(
    *,
    challenge_id="challenge-1",
    expires_at=None,
    ceremony="registration",
    user_id=1,
    user_handle=None,
):
    if expires_at is None:
        expires_at = (
            time.time() + 300
        )

    return WebAuthnChallenge(
        id=challenge_id,
        challenge=b"challenge-bytes",
        ceremony=ceremony,
        user_id=user_id,
        expires_at=expires_at,
        user_handle=user_handle,
    )


@pytest.mark.parametrize(
    "store_factory",
    [
        MemoryWebAuthnChallengeStore,
        make_redis_store,
    ],
)
def test_create_and_consume_challenge(
    store_factory,
):
    store = store_factory()

    challenge = make_challenge(
        user_handle=b"user-handle"
    )

    store.create(
        challenge
    )

    consumed = store.consume(
        "challenge-1"
    )

    assert consumed is not None
    assert consumed.id == challenge.id
    assert (
        consumed.challenge
        == challenge.challenge
    )
    assert (
        consumed.ceremony
        == challenge.ceremony
    )
    assert (
        consumed.user_id
        == challenge.user_id
    )
    assert (
        consumed.user_handle
        == challenge.user_handle
    )


@pytest.mark.parametrize(
    "store_factory",
    [
        MemoryWebAuthnChallengeStore,
        make_redis_store,
    ],
)
def test_challenge_is_single_use(
    store_factory,
):
    store = store_factory()

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


def test_memory_expired_challenge_cannot_be_consumed():
    store = (
        MemoryWebAuthnChallengeStore()
    )

    store.create(
        make_challenge(
            expires_at=(
                time.time() - 1
            )
        )
    )

    consumed = store.consume(
        "challenge-1"
    )

    assert consumed is None


def test_redis_expired_challenge_cannot_be_created():
    store = make_redis_store()

    with pytest.raises(
        ValueError
    ):
        store.create(
            make_challenge(
                expires_at=(
                    time.time() - 1
                )
            )
        )


@pytest.mark.parametrize(
    "store_factory",
    [
        MemoryWebAuthnChallengeStore,
        make_redis_store,
    ],
)
def test_delete_challenge(
    store_factory,
):
    store = store_factory()

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


@pytest.mark.parametrize(
    "store_factory",
    [
        MemoryWebAuthnChallengeStore,
        make_redis_store,
    ],
)
def test_delete_missing_challenge(
    store_factory,
):
    store = store_factory()

    assert (
        store.delete(
            "missing"
        )
        is False
    )


def test_expired_challenges_are_cleaned():
    store = (
        MemoryWebAuthnChallengeStore()
    )

    store.create(
        make_challenge(
            challenge_id="expired",
            expires_at=(
                time.time() - 1
            ),
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


@pytest.mark.parametrize(
    "store_factory",
    [
        MemoryWebAuthnChallengeStore,
        make_redis_store,
    ],
)
def test_duplicate_challenge_id_is_rejected(
    store_factory,
):
    store = store_factory()

    store.create(
        make_challenge(
            challenge_id="duplicate"
        )
    )

    with pytest.raises(
        ValueError
    ):
        store.create(
            make_challenge(
                challenge_id="duplicate"
            )
        )


@pytest.mark.parametrize(
    "store_factory",
    [
        MemoryWebAuthnChallengeStore,
        make_redis_store,
    ],
)
def test_missing_challenge_returns_none(
    store_factory,
):
    store = store_factory()

    assert (
        store.consume(
            "does-not-exist"
        )
        is None
    )


def test_redis_preserves_none_user_values():
    store = make_redis_store()

    challenge = make_challenge(
        ceremony="authentication",
        user_id=None,
        user_handle=None,
    )

    store.create(
        challenge
    )

    consumed = store.consume(
        challenge.id
    )

    assert consumed is not None
    assert consumed.user_id is None
    assert (
        consumed.user_handle
        is None
    )


def test_redis_preserves_string_user_id():
    store = make_redis_store()

    challenge = make_challenge(
        user_id="user-abc",
        user_handle=b"user-handle",
    )

    store.create(
        challenge
    )

    consumed = store.consume(
        challenge.id
    )

    assert consumed is not None
    assert (
        consumed.user_id
        == "user-abc"
    )


def test_redis_uses_namespaced_key():
    store = (
        RedisWebAuthnChallengeStore(
            "redis://localhost:6379/0",
            key_prefix="custom:auth",
        )
    )

    store.redis = FakeRedis()

    challenge = make_challenge(
        challenge_id=(
            "namespace-test"
        )
    )

    store.create(
        challenge
    )

    expected_key = (
        "custom:auth:"
        "webauthn:challenge:"
        "namespace-test"
    )

    assert (
        expected_key
        in store.redis.values
    )


def test_redis_store_configures_connection_timeouts(
    monkeypatch,
):
    captured = {}

    class FakeClient:
        pass

    def fake_from_url(
        redis_url,
        **kwargs,
    ):
        captured[
            "redis_url"
        ] = redis_url

        captured.update(
            kwargs
        )

        return FakeClient()

    monkeypatch.setattr(
        "marks_toolkit.auth."
        "webauthn_challenge_store."
        "Redis.from_url",
        fake_from_url,
    )

    RedisWebAuthnChallengeStore(
        "redis://example.test:6379/0",
        socket_connect_timeout=1.5,
        socket_timeout=2.5,
    )

    assert (
        captured["redis_url"]
        == (
            "redis://example.test:"
            "6379/0"
        )
    )

    assert (
        captured[
            "socket_connect_timeout"
        ]
        == 1.5
    )

    assert (
        captured[
            "socket_timeout"
        ]
        == 2.5
    )

    assert (
        captured[
            "health_check_interval"
        ]
        == 30
    )