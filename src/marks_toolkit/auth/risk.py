from dataclasses import dataclass
import time


@dataclass
class RiskDecision:
    captcha_required: bool
    blocked: bool
    score: int


class RiskService:
    def __init__(
        self,
        captcha_threshold=5,
        block_threshold=15,
        failure_window_seconds=900
    ):
        self.captcha_threshold = captcha_threshold
        self.block_threshold = block_threshold
        self.failure_window_seconds = failure_window_seconds
        self.failures = {}

    def _key(self, action, identity, ip_address):
        return (
            action,
            identity.strip().lower(),
            ip_address
        )


    def record_failure(
        self,
        action,
        identity,
        ip_address
    ):
        key = self._key(
            action,
            identity,
            ip_address
        )

        now = time.time()

        if key not in self.failures:
            self.failures[key] = []

        self.failures[key].append(now)


    def assess(
        self,
        action,
        identity,
        ip_address
    ):
        key = self._key(
            action,
            identity,
            ip_address
        )

        now = time.time()

        failures = self.failures.get(key, [])

        recent_failures = [
            timestamp
            for timestamp in failures
            if now - timestamp <= self.failure_window_seconds
        ]

        self.failures[key] = recent_failures

        score = len(recent_failures)

        return RiskDecision(
            captcha_required=(
                score >= self.captcha_threshold
            ),
            blocked=(
                score >= self.block_threshold
            ),
            score=score
        )


    def record_success(
        self,
        action,
        identity,
        ip_address
    ):
        key = self._key(
            action,
            identity,
            ip_address
        )

        self.failures.pop(key, None)