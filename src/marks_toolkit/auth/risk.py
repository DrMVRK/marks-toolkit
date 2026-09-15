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
        failure_window_seconds=900,
    ):
        self.security_store = security_store
        self.captcha_threshold = captcha_threshold
        self.block_threshold = block_threshold
        self.failure_window_seconds = (
            failure_window_seconds
        )

    # ============================================================
    # KEY GENERATION
    # ============================================================

    def _normalize_identity(
        self,
        identity,
    ):
        if not isinstance(identity, str):
            return ""

        return identity.strip().casefold()

    def _combination_key(
        self,
        action,
        identity,
        ip_address,
    ):
        return (
            "risk",
            action,
            "identity-ip",
            self._normalize_identity(
                identity
            ),
            ip_address,
        )

    def _identity_key(
        self,
        action,
        identity,
    ):
        return (
            "risk",
            action,
            "identity",
            self._normalize_identity(
                identity
            ),
        )

    def _ip_key(
        self,
        action,
        ip_address,
    ):
        return (
            "risk",
            action,
            "ip",
            ip_address,
        )

    # ============================================================
    # FAILURE RECORDING
    # ============================================================

    def record_failure(
        self,
        action,
        identity,
        ip_address,
    ):
        combination_key = (
            self._combination_key(
                action,
                identity,
                ip_address,
            )
        )

        identity_key = (
            self._identity_key(
                action,
                identity,
            )
        )

        ip_key = self._ip_key(
            action,
            ip_address,
        )

        self.security_store.add_attempt(
            combination_key,
            self.failure_window_seconds,
        )

        self.security_store.add_attempt(
            identity_key,
            self.failure_window_seconds,
        )

        self.security_store.add_attempt(
            ip_key,
            self.failure_window_seconds,
        )

    # ============================================================
    # RISK ASSESSMENT
    # ============================================================

    def assess(
        self,
        action,
        identity,
        ip_address,
    ):
        combination_key = (
            self._combination_key(
                action,
                identity,
                ip_address,
            )
        )

        identity_key = (
            self._identity_key(
                action,
                identity,
            )
        )

        ip_key = self._ip_key(
            action,
            ip_address,
        )

        combination_score = (
            self.security_store
            .count_attempts(
                combination_key,
                self.failure_window_seconds,
            )
        )

        identity_score = (
            self.security_store
            .count_attempts(
                identity_key,
                self.failure_window_seconds,
            )
        )

        ip_score = (
            self.security_store
            .count_attempts(
                ip_key,
                self.failure_window_seconds,
            )
        )

        score = max(
            combination_score,
            identity_score,
            ip_score,
        )

        return RiskDecision(
            captcha_required=(
                score
                >= self.captcha_threshold
            ),
            blocked=(
                score
                >= self.block_threshold
            ),
            score=score,
        )

    # ============================================================
    # SUCCESS HANDLING
    # ============================================================

    def record_success(
        self,
        action,
        identity,
        ip_address,
    ):
        combination_key = (
            self._combination_key(
                action,
                identity,
                ip_address,
            )
        )

        identity_key = (
            self._identity_key(
                action,
                identity,
            )
        )

        self.security_store.clear(
            combination_key
        )

        self.security_store.clear(
            identity_key
        )