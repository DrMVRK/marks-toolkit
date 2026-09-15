from datetime import timedelta


class AuthConfig:
    def __init__(self, app):
        self.url_prefix = app.config.get(
            "MARKS_AUTH_URL_PREFIX",
            "/auth",
        )

        self.password_min_length = app.config.get(
            "MARKS_AUTH_PASSWORD_MIN_LENGTH",
            12,
        )

        self.password_max_length = app.config.get(
            "MARKS_AUTH_PASSWORD_MAX_LENGTH",
            256,
        )

        self.remember_days = app.config.get(
            "MARKS_AUTH_REMEMBER_DAYS",
            30,
        )

        self.remember_duration = timedelta(
            days=self.remember_days
        )

        self.reset_token_ttl = app.config.get(
            "MARKS_AUTH_RESET_TOKEN_TTL",
            1800,
        )

        self.reset_url = app.config.get(
            "MARKS_AUTH_RESET_URL"
        )

        self.captcha_site_key = app.config.get(
            "MARKS_AUTH_CAPTCHA_SITE_KEY"
        )

        self.captcha_secret_key = app.config.get(
            "MARKS_AUTH_CAPTCHA_SECRET_KEY"
        )

        # ========================================================
        # REGISTRATION THROTTLING
        # ========================================================

        self.registration_limit = app.config.get(
            "MARKS_AUTH_REGISTRATION_LIMIT",
            5,
        )

        self.registration_window = app.config.get(
            "MARKS_AUTH_REGISTRATION_WINDOW",
            900,
        )

        self.password_change_limit = app.config.get(
            "MARKS_AUTH_PASSWORD_CHANGE_LIMIT",
            5,
        )

        self.password_change_window = app.config.get(
            "MARKS_AUTH_PASSWORD_CHANGE_WINDOW",
            900,
        )

        # ========================================================
        # PASSWORD RESET THROTTLING
        # ========================================================

        self.forgot_password_limit = app.config.get(
            "MARKS_AUTH_FORGOT_PASSWORD_LIMIT",
            5,
        )

        self.forgot_password_window = app.config.get(
            "MARKS_AUTH_FORGOT_PASSWORD_WINDOW",
            900,
        )

        self.reset_password_limit = app.config.get(
            "MARKS_AUTH_RESET_PASSWORD_LIMIT",
            5,
        )

        self.reset_password_window = app.config.get(
            "MARKS_AUTH_RESET_PASSWORD_WINDOW",
            900,
        )

        # ========================================================
        # LOGIN RISK / THROTTLING
        # ========================================================

        self.login_captcha_threshold = app.config.get(
            "MARKS_AUTH_LOGIN_CAPTCHA_THRESHOLD",
            4,
        )

        self.login_block_threshold = app.config.get(
            "MARKS_AUTH_LOGIN_BLOCK_THRESHOLD",
            15,
        )

        self.login_failure_window = app.config.get(
            "MARKS_AUTH_LOGIN_FAILURE_WINDOW",
            900,
        )

        # ========================================================
        # SECURITY STORE
        # ========================================================

        self.security_store_backend = app.config.get(
            "MARKS_AUTH_SECURITY_STORE",
            "memory",
        )

        self.redis_url = app.config.get(
            "MARKS_AUTH_REDIS_URL"
        )

        # ========================================================
        # COOKIE / SESSION SECURITY
        # ========================================================

        self.cookie_secure = app.config.get(
            "MARKS_AUTH_COOKIE_SECURE",
            False,
        )

        self.cookie_samesite = app.config.get(
            "MARKS_AUTH_COOKIE_SAMESITE",
            "Lax",
        )

        self.session_protection = app.config.get(
            "MARKS_AUTH_SESSION_PROTECTION",
            "strong",
        )

        # ========================================================
        # PROXY CONFIGURATION
        # ========================================================

        self.proxy_fix_enabled = app.config.get(
            "MARKS_AUTH_PROXY_FIX_ENABLED",
            False,
        )

        self.proxy_fix_x_for = app.config.get(
            "MARKS_AUTH_PROXY_FIX_X_FOR",
            1,
        )

        self.proxy_fix_x_proto = app.config.get(
            "MARKS_AUTH_PROXY_FIX_X_PROTO",
            1,
        )

        # ========================================================
        # MFA
        # ========================================================

        self.mfa_enabled = app.config.get(
            "MARKS_AUTH_MFA_ENABLED",
            False,
        )

        self.mfa_encryption_key = app.config.get(
            "MARKS_AUTH_MFA_ENCRYPTION_KEY"
        )

        self.recovery_code_key = app.config.get(
            "MARKS_AUTH_RECOVERY_CODE_KEY"
        )

        self.totp_issuer = app.config.get(
            "MARKS_AUTH_TOTP_ISSUER",
            "MARKS Auth",
        )

        self.mfa_challenge_ttl = app.config.get(
            "MARKS_AUTH_MFA_CHALLENGE_TTL",
            300,
        )

        self.mfa_challenge_attempt_limit = app.config.get(
            "MARKS_AUTH_MFA_CHALLENGE_ATTEMPT_LIMIT",
            5,
        )

        self.mfa_challenge_attempt_window = app.config.get(
            "MARKS_AUTH_MFA_CHALLENGE_ATTEMPT_WINDOW",
            300,
        )

        self.mfa_enrollment_verify_limit = app.config.get(
            "MARKS_AUTH_MFA_ENROLLMENT_VERIFY_LIMIT",
            5,
        )

        self.mfa_enrollment_verify_window = app.config.get(
            "MARKS_AUTH_MFA_ENROLLMENT_VERIFY_WINDOW",
            300,
        )

        self.mfa_disable_limit = app.config.get(
            "MARKS_AUTH_MFA_DISABLE_LIMIT",
            5,
        )

        self.mfa_disable_window = app.config.get(
            "MARKS_AUTH_MFA_DISABLE_WINDOW",
            300,
        )

        self.recovery_code_generation_limit = app.config.get(
            "MARKS_AUTH_RECOVERY_CODE_GENERATION_LIMIT",
            5,
        )

        self.recovery_code_generation_window = app.config.get(
            "MARKS_AUTH_RECOVERY_CODE_GENERATION_WINDOW",
            300,
        )