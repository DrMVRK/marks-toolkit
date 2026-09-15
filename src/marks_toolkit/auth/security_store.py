from abc import ABC, abstractmethod
from threading import Lock
import hashlib
import json
import math
import secrets
import time

from redis import Redis


class SecurityStore(ABC):

    @abstractmethod
    def add_attempt(
        self,
        key,
        window_seconds,
    ):
        pass

    @abstractmethod
    def count_attempts(
        self,
        key,
        window_seconds,
    ):
        pass

    @abstractmethod
    def check_and_add_attempts(
        self,
        keys,
        limit,
        window_seconds,
    ):
        """
        Atomically check all supplied keys.

        Returns True when the request is already blocked.

        If none of the keys are blocked, record one attempt
        against every key and return False.
        """
        pass

    @abstractmethod
    def clear(
        self,
        key,
    ):
        pass


class MemorySecurityStore(SecurityStore):

    def __init__(self):
        self._attempts = {}
        self._lock = Lock()

    def _prune_unlocked(
        self,
        key,
        window_seconds,
        now=None,
    ):
        if now is None:
            now = time.time()

        attempts = self._attempts.get(
            key,
            [],
        )

        recent_attempts = [
            timestamp
            for timestamp in attempts
            if (
                now - timestamp
                < window_seconds
            )
        ]

        if recent_attempts:
            self._attempts[
                key
            ] = recent_attempts

        else:
            self._attempts.pop(
                key,
                None,
            )

        return recent_attempts

    def add_attempt(
        self,
        key,
        window_seconds,
    ):
        now = time.time()

        with self._lock:
            recent_attempts = (
                self._prune_unlocked(
                    key,
                    window_seconds,
                    now=now,
                )
            )

            recent_attempts.append(
                now
            )

            self._attempts[
                key
            ] = recent_attempts

    def count_attempts(
        self,
        key,
        window_seconds,
    ):
        with self._lock:
            return len(
                self._prune_unlocked(
                    key,
                    window_seconds,
                )
            )

    def check_and_add_attempts(
        self,
        keys,
        limit,
        window_seconds,
    ):
        if limit <= 0:
            raise ValueError(
                "Throttle limit must be "
                "greater than zero."
            )

        if window_seconds <= 0:
            raise ValueError(
                "Throttle window must be "
                "greater than zero."
            )

        keys = list(keys)

        if not keys:
            return False

        now = time.time()

        with self._lock:
            recent_by_key = {}

            for key in keys:
                recent = (
                    self._prune_unlocked(
                        key,
                        window_seconds,
                        now=now,
                    )
                )

                recent_by_key[
                    key
                ] = recent

                if len(recent) >= limit:
                    return True

            for key in keys:
                recent = recent_by_key[
                    key
                ]

                recent.append(
                    now
                )

                self._attempts[
                    key
                ] = recent

        return False

    def clear(
        self,
        key,
    ):
        with self._lock:
            self._attempts.pop(
                key,
                None,
            )


class RedisSecurityStore(SecurityStore):

    _ADD_ATTEMPT_SCRIPT = """
local now = redis.call('TIME')
local now_ms =
    (tonumber(now[1]) * 1000)
    + math.floor(
        tonumber(now[2]) / 1000
    )

local window_ms = tonumber(ARGV[1])
local member = ARGV[2]
local cutoff = now_ms - window_ms

redis.call(
    'ZREMRANGEBYSCORE',
    KEYS[1],
    '-inf',
    cutoff
)

redis.call(
    'ZADD',
    KEYS[1],
    now_ms,
    member
)

redis.call(
    'PEXPIRE',
    KEYS[1],
    window_ms
)

return 1
"""

    _COUNT_ATTEMPTS_SCRIPT = """
local now = redis.call('TIME')
local now_ms =
    (tonumber(now[1]) * 1000)
    + math.floor(
        tonumber(now[2]) / 1000
    )

local window_ms = tonumber(ARGV[1])
local cutoff = now_ms - window_ms

redis.call(
    'ZREMRANGEBYSCORE',
    KEYS[1],
    '-inf',
    cutoff
)

return redis.call(
    'ZCARD',
    KEYS[1]
)
"""

    _CHECK_AND_ADD_SCRIPT = """
local now = redis.call('TIME')
local now_ms =
    (tonumber(now[1]) * 1000)
    + math.floor(
        tonumber(now[2]) / 1000
    )

local window_ms = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local member = ARGV[3]
local cutoff = now_ms - window_ms

for index, key in ipairs(KEYS) do
    redis.call(
        'ZREMRANGEBYSCORE',
        key,
        '-inf',
        cutoff
    )

    local count = redis.call(
        'ZCARD',
        key
    )

    if count >= limit then
        return 1
    end
end

for index, key in ipairs(KEYS) do
    redis.call(
        'ZADD',
        key,
        now_ms,
        member
    )

    redis.call(
        'PEXPIRE',
        key,
        window_ms
    )
end

return 0
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

        self.key_prefix = key_prefix

    def _redis_key(
        self,
        key,
    ):
        serialized_key = json.dumps(
            key,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        )

        digest = hashlib.sha256(
            serialized_key.encode(
                "utf-8"
            )
        ).hexdigest()

        return (
            f"{self.key_prefix}:"
            "{security}:"
            f"{digest}"
        )

    def _window_ms(
        self,
        window_seconds,
    ):
        if window_seconds <= 0:
            raise ValueError(
                "Security window must be "
                "greater than zero."
            )

        return max(
            1,
            math.ceil(
                window_seconds * 1000
            ),
        )

    def add_attempt(
        self,
        key,
        window_seconds,
    ):
        redis_key = self._redis_key(
            key
        )

        member = (
            secrets.token_hex(16)
        )

        self.redis.eval(
            self._ADD_ATTEMPT_SCRIPT,
            1,
            redis_key,
            self._window_ms(
                window_seconds
            ),
            member,
        )

    def count_attempts(
        self,
        key,
        window_seconds,
    ):
        redis_key = self._redis_key(
            key
        )

        value = self.redis.eval(
            self._COUNT_ATTEMPTS_SCRIPT,
            1,
            redis_key,
            self._window_ms(
                window_seconds
            ),
        )

        return int(value)

    def check_and_add_attempts(
        self,
        keys,
        limit,
        window_seconds,
    ):
        if limit <= 0:
            raise ValueError(
                "Throttle limit must be "
                "greater than zero."
            )

        redis_keys = [
            self._redis_key(key)
            for key in keys
        ]

        if not redis_keys:
            return False

        member = (
            secrets.token_hex(16)
        )

        result = self.redis.eval(
            self._CHECK_AND_ADD_SCRIPT,
            len(redis_keys),
            *redis_keys,
            self._window_ms(
                window_seconds
            ),
            limit,
            member,
        )

        return bool(result)

    def clear(
        self,
        key,
    ):
        redis_key = self._redis_key(
            key
        )

        self.redis.delete(
            redis_key
        )