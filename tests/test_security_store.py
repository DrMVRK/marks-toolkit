import time

import pytest

from marks_toolkit.auth.security_store import (
    MemorySecurityStore,
    RedisSecurityStore,
)


class FakeRedis:
    """
    Small Redis stand-in for testing the security-store
    contract without requiring a real Redis server.
    """

    def __init__(self):
        self.sorted_sets = {}
        self.now_ms = 1_000_000
        self.deleted = []

    def _prune(
        self,
        key,
        cutoff,
    ):
        entries = self.sorted_sets.get(
            key,
            {},
        )

        remaining = {
            member: score
            for member, score in entries.items()
            if score > cutoff
        }

        if remaining:
            self.sorted_sets[key] = remaining
        else:
            self.sorted_sets.pop(
                key,
                None,
            )

    def eval(
        self,
        script,
        number_of_keys,
        *args,
    ):
        keys = list(
            args[:number_of_keys]
        )

        arguments = list(
            args[number_of_keys:]
        )

        if (
            script
            == RedisSecurityStore
            ._ADD_ATTEMPT_SCRIPT
        ):
            window_ms = int(
                arguments[0]
            )

            member = arguments[1]

            key = keys[0]

            cutoff = (
                self.now_ms
                - window_ms
            )

            self._prune(
                key,
                cutoff,
            )

            self.sorted_sets.setdefault(
                key,
                {},
            )[member] = self.now_ms

            return 1

        if (
            script
            == RedisSecurityStore
            ._COUNT_ATTEMPTS_SCRIPT
        ):
            window_ms = int(
                arguments[0]
            )

            key = keys[0]

            cutoff = (
                self.now_ms
                - window_ms
            )

            self._prune(
                key,
                cutoff,
            )

            return len(
                self.sorted_sets.get(
                    key,
                    {},
                )
            )

        if (
            script
            == RedisSecurityStore
            ._CHECK_AND_ADD_SCRIPT
        ):
            window_ms = int(
                arguments[0]
            )

            limit = int(
                arguments[1]
            )

            member = arguments[2]

            cutoff = (
                self.now_ms
                - window_ms
            )

            for key in keys:
                self._prune(
                    key,
                    cutoff,
                )

                count = len(
                    self.sorted_sets.get(
                        key,
                        {},
                    )
                )

                if count >= limit:
                    return 1

            for key in keys:
                self.sorted_sets.setdefault(
                    key,
                    {},
                )[member] = self.now_ms

            return 0

        raise AssertionError(
            "Unexpected Redis Lua script."
        )

    def delete(
        self,
        key,
    ):
        existed = (
            key in self.sorted_sets
        )

        self.sorted_sets.pop(
            key,
            None,
        )

        self.deleted.append(
            key
        )

        return int(existed)


def make_redis_store():
    store = RedisSecurityStore(
        "redis://localhost:6379/0"
    )

    store.redis = FakeRedis()

    return store


def test_memory_security_store_uses_sliding_window(
    monkeypatch,
):
    store = MemorySecurityStore()

    current_time = [
        1000.0
    ]

    monkeypatch.setattr(
        time,
        "time",
        lambda: current_time[0],
    )

    key = (
        "login",
        "ip",
        "203.0.113.10",
    )

    store.add_attempt(
        key,
        10,
    )

    current_time[0] = 1005.0

    store.add_attempt(
        key,
        10,
    )

    assert (
        store.count_attempts(
            key,
            10,
        )
        == 2
    )

    current_time[0] = 1011.0

    assert (
        store.count_attempts(
            key,
            10,
        )
        == 1
    )


def test_redis_security_store_uses_sliding_window():
    store = make_redis_store()

    key = (
        "login",
        "ip",
        "203.0.113.10",
    )

    store.redis.now_ms = 1_000_000

    store.add_attempt(
        key,
        10,
    )

    store.redis.now_ms = 1_005_000

    store.add_attempt(
        key,
        10,
    )

    assert (
        store.count_attempts(
            key,
            10,
        )
        == 2
    )

    store.redis.now_ms = 1_011_000

    assert (
        store.count_attempts(
            key,
            10,
        )
        == 1
    )


@pytest.mark.parametrize(
    "store_factory",
    [
        MemorySecurityStore,
        make_redis_store,
    ],
)
def test_check_and_add_allows_until_limit_then_blocks(
    store_factory,
):
    store = store_factory()

    key = (
        "password-change",
        "ip",
        "203.0.113.10",
    )

    assert (
        store.check_and_add_attempts(
            [key],
            limit=3,
            window_seconds=60,
        )
        is False
    )

    assert (
        store.check_and_add_attempts(
            [key],
            limit=3,
            window_seconds=60,
        )
        is False
    )

    assert (
        store.check_and_add_attempts(
            [key],
            limit=3,
            window_seconds=60,
        )
        is False
    )

    assert (
        store.check_and_add_attempts(
            [key],
            limit=3,
            window_seconds=60,
        )
        is True
    )


@pytest.mark.parametrize(
    "store_factory",
    [
        MemorySecurityStore,
        make_redis_store,
    ],
)
def test_blocked_request_does_not_record_another_attempt(
    store_factory,
):
    store = store_factory()

    key = (
        "register",
        "ip",
        "203.0.113.10",
    )

    for _ in range(2):
        blocked = (
            store.check_and_add_attempts(
                [key],
                limit=2,
                window_seconds=60,
            )
        )

        assert blocked is False

    assert (
        store.check_and_add_attempts(
            [key],
            limit=2,
            window_seconds=60,
        )
        is True
    )

    assert (
        store.count_attempts(
            key,
            60,
        )
        == 2
    )


@pytest.mark.parametrize(
    "store_factory",
    [
        MemorySecurityStore,
        make_redis_store,
    ],
)
def test_multiple_throttle_identities_are_checked_together(
    store_factory,
):
    store = store_factory()

    ip_key = (
        "forgot-password",
        "ip",
        "203.0.113.10",
    )

    email_key = (
        "forgot-password",
        "email",
        "mark@example.com",
    )

    assert (
        store.check_and_add_attempts(
            [
                ip_key,
                email_key,
            ],
            limit=2,
            window_seconds=60,
        )
        is False
    )

    assert (
        store.check_and_add_attempts(
            [
                ip_key,
                email_key,
            ],
            limit=2,
            window_seconds=60,
        )
        is False
    )

    assert (
        store.check_and_add_attempts(
            [
                ip_key,
                email_key,
            ],
            limit=2,
            window_seconds=60,
        )
        is True
    )

    assert (
        store.count_attempts(
            ip_key,
            60,
        )
        == 2
    )

    assert (
        store.count_attempts(
            email_key,
            60,
        )
        == 2
    )


def test_one_blocked_identity_prevents_all_new_records():
    store = MemorySecurityStore()

    blocked_key = (
        "forgot-password",
        "ip",
        "203.0.113.10",
    )

    clean_key = (
        "forgot-password",
        "email",
        "other@example.com",
    )

    store.check_and_add_attempts(
        [blocked_key],
        limit=1,
        window_seconds=60,
    )

    assert (
        store.check_and_add_attempts(
            [
                blocked_key,
                clean_key,
            ],
            limit=1,
            window_seconds=60,
        )
        is True
    )

    assert (
        store.count_attempts(
            clean_key,
            60,
        )
        == 0
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
        "marks_toolkit.auth.security_store."
        "Redis.from_url",
        fake_from_url,
    )

    RedisSecurityStore(
        "redis://example.test:6379/0",
        socket_connect_timeout=1.5,
        socket_timeout=2.5,
    )

    assert (
        captured["redis_url"]
        == "redis://example.test:6379/0"
    )

    assert (
        captured[
            "socket_connect_timeout"
        ]
        == 1.5
    )

    assert (
        captured["socket_timeout"]
        == 2.5
    )

    assert (
        captured[
            "health_check_interval"
        ]
        == 30
    )