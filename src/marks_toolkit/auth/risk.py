from dataclasses import dataclass


@dataclass
class RiskDecision:
    captcha_required: bool
    blocked: bool
    score: int


class RiskService:
    def __init__(
        self,
        security_store,
        captcha_threshold=5,
        block_threshold=15,
        failure_window_seconds=900
    ):
        self.security_store = security_store
        self.captcha_threshold = captcha_threshold
        self.block_threshold = block_threshold
        self.failure_window_seconds = failure_window_seconds

    def _key(
        self,
        action,
        identity,
        ip_address
    ):
        return (
            "risk",
            action,
            identity.strip().casefold(),
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

        self.security_store.add_attempt(
            key,
            self.failure_window_seconds
        )

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

        score = self.security_store.count_attempts(
            key,
            self.failure_window_seconds
        )

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

        self.security_store.clear(key)