class ThrottleService:
    def __init__(
        self,
        security_store,
    ):
        self.security_store = (
            security_store
        )

    def is_blocked(
        self,
        key,
        limit,
        window_seconds,
    ):
        """
        Read-only compatibility helper.

        Security-sensitive request handling should use
        check_and_record() instead.
        """

        attempt_count = (
            self.security_store
            .count_attempts(
                key,
                window_seconds,
            )
        )

        return (
            attempt_count
            >= limit
        )

    def record(
        self,
        key,
        window_seconds,
    ):
        """
        Compatibility helper for callers that intentionally
        record an event without performing a throttle check.
        """

        self.security_store.add_attempt(
            key,
            window_seconds,
        )

    def check_and_record(
        self,
        keys,
        limit,
        window_seconds,
    ):
        """
        Atomically check and record an attempted request.

        Returns True when the request should be blocked.
        """

        if not isinstance(
            keys,
            (list, tuple, set),
        ):
            keys = [
                keys
            ]

        return (
            self.security_store
            .check_and_add_attempts(
                keys=keys,
                limit=limit,
                window_seconds=(
                    window_seconds
                ),
            )
        )

    def clear(
        self,
        key,
    ):
        self.security_store.clear(
            key
        )