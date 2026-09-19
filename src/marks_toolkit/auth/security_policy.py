SESSION_POLICY_KEYS = (
    "MARKS_AUTH_SESSION_TOUCH_INTERVAL",
    "MARKS_AUTH_SESSION_IDLE_TIMEOUT",
    "MARKS_AUTH_SESSION_ABSOLUTE_TIMEOUT",
    (
        "MARKS_AUTH_REMEMBERED_"
        "SESSION_ABSOLUTE_TIMEOUT"
    ),
)


SECURITY_PROFILES = {
    "basic": {
        "MARKS_AUTH_SESSION_TOUCH_INTERVAL":
            60,

        "MARKS_AUTH_SESSION_IDLE_TIMEOUT":
            86400,

        "MARKS_AUTH_SESSION_ABSOLUTE_TIMEOUT":
            2592000,

        (
            "MARKS_AUTH_REMEMBERED_"
            "SESSION_ABSOLUTE_TIMEOUT"
        ):
            5184000,
    },

    "standard": {
        "MARKS_AUTH_SESSION_TOUCH_INTERVAL":
            60,

        "MARKS_AUTH_SESSION_IDLE_TIMEOUT":
            43200,

        "MARKS_AUTH_SESSION_ABSOLUTE_TIMEOUT":
            604800,

        (
            "MARKS_AUTH_REMEMBERED_"
            "SESSION_ABSOLUTE_TIMEOUT"
        ):
            2592000,
    },

    "high-security": {
        "MARKS_AUTH_SESSION_TOUCH_INTERVAL":
            30,

        "MARKS_AUTH_SESSION_IDLE_TIMEOUT":
            900,

        "MARKS_AUTH_SESSION_ABSOLUTE_TIMEOUT":
            28800,

        (
            "MARKS_AUTH_REMEMBERED_"
            "SESSION_ABSOLUTE_TIMEOUT"
        ):
            86400,
    },
}


PROFILE_ALIASES = {
    "high": "high-security",
    "high_security": "high-security",
}


def normalize_security_profile(
    value,
):
    if value is None:
        return "standard"

    if not isinstance(
        value,
        str,
    ):
        raise RuntimeError(
            "MARKS_AUTH_SECURITY_PROFILE "
            "must be a string."
        )

    profile = (
        value
        .strip()
        .lower()
    )

    profile = PROFILE_ALIASES.get(
        profile,
        profile,
    )

    valid = {
        "basic",
        "standard",
        "high-security",
        "custom",
    }

    if profile not in valid:
        raise RuntimeError(
            "MARKS_AUTH_SECURITY_PROFILE "
            "must be one of: "
            "basic, standard, "
            "high-security, custom."
        )

    return profile


def _validate_policy_value(
    key,
    value,
):
    if isinstance(
        value,
        bool,
    ):
        raise RuntimeError(
            f"{key} must be an integer."
        )

    if not isinstance(
        value,
        int,
    ):
        raise RuntimeError(
            f"{key} must be an integer."
        )

    if value < 0:
        raise RuntimeError(
            f"{key} must be zero or greater."
        )


def _validate_custom_profile(
    app,
):
    missing = [
        key
        for key in SESSION_POLICY_KEYS
        if key not in app.config
    ]

    if missing:
        formatted = ", ".join(
            missing
        )

        raise RuntimeError(
            "MARKS_AUTH_SECURITY_PROFILE="
            "'custom' requires explicit "
            "session policy values for: "
            f"{formatted}."
        )

    for key in SESSION_POLICY_KEYS:
        _validate_policy_value(
            key,
            app.config[key],
        )


def apply_security_profile(
    app,
):
    profile = (
        normalize_security_profile(
            app.config.get(
                "MARKS_AUTH_SECURITY_PROFILE",
                "standard",
            )
        )
    )

    app.config[
        "MARKS_AUTH_SECURITY_PROFILE"
    ] = profile

    if profile == "custom":
        _validate_custom_profile(
            app
        )

        return profile

    defaults = SECURITY_PROFILES[
        profile
    ]

    for key, value in defaults.items():
        app.config.setdefault(
            key,
            value,
        )

    for key in SESSION_POLICY_KEYS:
        _validate_policy_value(
            key,
            app.config[key],
        )

    return profile