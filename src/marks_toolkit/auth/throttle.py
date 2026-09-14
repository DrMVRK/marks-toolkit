class ThrottleService:
    def __init__(self, security_store):
        self.security_store = security_store

    def is_blocked(
        self,
        key,
        limit,
        window_seconds
    ):
        attempt_count = (
            self.security_store.count_attempts(
                key,
                window_seconds
            )
        )

        return attempt_count >= limit

    def record(
        self,
        key,
        window_seconds
    ):
        self.security_store.add_attempt(
            key,
            window_seconds
        )

    def clear(self, key):
        self.security_store.clear(key)