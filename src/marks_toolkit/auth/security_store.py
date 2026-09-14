from abc import ABC, abstractmethod
import time

import hashlib
import json

from redis import Redis


class SecurityStore(ABC):

    @abstractmethod
    def add_attempt(
        self,
        key,
        window_seconds
    ):
        pass

    @abstractmethod
    def count_attempts(
        self,
        key,
        window_seconds
    ):
        pass

    @abstractmethod
    def clear(self, key):
        pass


class MemorySecurityStore(SecurityStore):

    def __init__(self):
        self._attempts = {}

    def _prune(
        self,
        key,
        window_seconds
    ):
        now = time.time()

        attempts = self._attempts.get(
            key,
            []
        )

        recent_attempts = [
            timestamp
            for timestamp in attempts
            if now - timestamp <= window_seconds
        ]

        if recent_attempts:
            self._attempts[key] = recent_attempts
        else:
            self._attempts.pop(key, None)

        return recent_attempts

    def add_attempt(
        self,
        key,
        window_seconds
    ):
        recent_attempts = self._prune(
            key,
            window_seconds
        )

        recent_attempts.append(time.time())

        self._attempts[key] = recent_attempts

    def count_attempts(
        self,
        key,
        window_seconds
    ):
        return len(
            self._prune(
                key,
                window_seconds
            )
        )

    def clear(self, key):
        self._attempts.pop(key, None)


class RedisSecurityStore(SecurityStore):

    def __init__(
        self,
        redis_url,
        key_prefix="marks:auth"
    ):
        if not redis_url:
            raise ValueError(
                "Redis URL is required."
            )

        self.redis = Redis.from_url(
            redis_url,
            decode_responses=True
        )

        self.key_prefix = key_prefix

    def _redis_key(self, key):
        serialized_key = json.dumps(
            key,
            sort_keys=True,
            default=str
        )

        digest = hashlib.sha256(
            serialized_key.encode("utf-8")
        ).hexdigest()

        return (
            f"{self.key_prefix}:"
            f"security:{digest}"
        )

    def add_attempt(
        self,
        key,
        window_seconds
    ):
        redis_key = self._redis_key(key)

        pipeline = self.redis.pipeline()

        pipeline.incr(redis_key)
        pipeline.expire(
            redis_key,
            window_seconds
        )

        pipeline.execute()

    def count_attempts(
        self,
        key,
        window_seconds
    ):
        redis_key = self._redis_key(key)

        value = self.redis.get(redis_key)

        if value is None:
            return 0

        return int(value)

    def clear(self, key):
        redis_key = self._redis_key(key)

        self.redis.delete(redis_key)