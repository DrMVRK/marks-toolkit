import time


class ThrottleService:
    def __init__(self):
        self.attempts = {}

    def _prune(self, key, window_seconds):
        now = time.time()

        attempts = self.attempts.get(key, [])

        recent_attempts = [
            timestamp
            for timestamp in attempts
            if now - timestamp <= window_seconds
        ]

        self.attempts[key] = recent_attempts

        return recent_attempts

    def is_blocked(
        self,
        key,
        limit,
        window_seconds
    ):
        recent_attempts = self._prune(
            key,
            window_seconds
        )

        return len(recent_attempts) >= limit

    def record(self, key):
        now = time.time()

        if key not in self.attempts:
            self.attempts[key] = []

        self.attempts[key].append(now)

    def clear(self, key):
        self.attempts.pop(key, None)