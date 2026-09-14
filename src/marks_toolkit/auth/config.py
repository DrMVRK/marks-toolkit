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
            30
        )

        self.remember_duration = timedelta(
            days=self.remember_days
        )

        self.reset_token_ttl = app.config.get(
            "MARKS_AUTH_RESET_TOKEN_TTL",
            1800
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

        self.forgot_password_limit = app.config.get(
            "MARKS_AUTH_FORGOT_PASSWORD_LIMIT",
            5
        )

        self.forgot_password_window = app.config.get(
            "MARKS_AUTH_FORGOT_PASSWORD_WINDOW",
            900
        )

        self.reset_password_limit = app.config.get(
            "MARKS_AUTH_RESET_PASSWORD_LIMIT",
            5
        )

        self.reset_password_window = app.config.get(
            "MARKS_AUTH_RESET_PASSWORD_WINDOW",
            900
        )

        self.login_captcha_threshold = app.config.get(
            "MARKS_AUTH_LOGIN_CAPTCHA_THRESHOLD",
            4
        )

        self.login_block_threshold = app.config.get(
            "MARKS_AUTH_LOGIN_BLOCK_THRESHOLD",
            15
        )

        self.login_failure_window = app.config.get(
            "MARKS_AUTH_LOGIN_FAILURE_WINDOW",
            900
        )