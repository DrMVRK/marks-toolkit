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