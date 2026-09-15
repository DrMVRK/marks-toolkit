from marks_toolkit.auth.mfa_challenge_store import (
    MFAChallengeRecord,
    RedisMFAChallengeStore,
)


class FakeRedis:
    def __init__(self):
        self.data = {}

    def set(
        self,
        key,
        value,
        ex=None,
    ):
        self.data[key] = value
        return True

    def get(
        self,
        key,
    ):
        return self.data.get(
            key
        )

    def getdel(
        self,
        key,
    ):
        return self.data.pop(
            key,
            None,
        )

    def delete(
        self,
        key,
    ):
        existed = key in self.data

        self.data.pop(
            key,
            None,
        )

        return int(existed)


def make_store():
    store = RedisMFAChallengeStore(
        "redis://localhost:6379/0"
    )

    store.redis = FakeRedis()

    return store


def make_record():
    return MFAChallengeRecord(
        challenge_id="challenge-123",
        auth_id="auth-123",
        remember=True,
        created_at=123456789,
    )


def test_redis_challenge_round_trip():
    store = make_store()
    record = make_record()

    store.create(
        record,
        ttl_seconds=300,
    )

    loaded = store.get(
        record.challenge_id
    )

    assert loaded == record


def test_redis_challenge_consumed_once():
    store = make_store()
    record = make_record()

    store.create(
        record,
        ttl_seconds=300,
    )

    first = store.consume(
        record.challenge_id
    )

    second = store.consume(
        record.challenge_id
    )

    assert first == record
    assert second is None


def test_redis_challenge_delete():
    store = make_store()
    record = make_record()

    store.create(
        record,
        ttl_seconds=300,
    )

    store.delete(
        record.challenge_id
    )

    assert (
        store.get(
            record.challenge_id
        )
        is None
    )


def test_redis_challenge_rejects_invalid_payload():
    store = make_store()

    key = store._key(
        "challenge-123"
    )

    store.redis.data[key] = (
        '{"bad":"payload"}'
    )

    assert (
        store.get(
            "challenge-123"
        )
        is None
    )