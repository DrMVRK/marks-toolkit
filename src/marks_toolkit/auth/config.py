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