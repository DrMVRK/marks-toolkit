import pytest

from flask import Flask

from marks_toolkit.auth.security_policy import (
    apply_security_profile,
)


def make_app():
    return Flask(
        __name__
    )


def test_standard_is_default_profile():
    app = make_app()

    profile = (
        apply_security_profile(
            app
        )
    )

    assert profile == "standard"

    assert (
        app.config[
            "MARKS_AUTH_SECURITY_PROFILE"
        ]
        == "standard"
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_TOUCH_INTERVAL"
        ]
        == 60
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_IDLE_TIMEOUT"
        ]
        == 43200
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_ABSOLUTE_TIMEOUT"
        ]
        == 604800
    )

    assert (
        app.config[
            (
                "MARKS_AUTH_REMEMBERED_"
                "SESSION_ABSOLUTE_TIMEOUT"
            )
        ]
        == 2592000
    )


def test_basic_profile():
    app = make_app()

    app.config[
        "MARKS_AUTH_SECURITY_PROFILE"
    ] = "basic"

    apply_security_profile(
        app
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_IDLE_TIMEOUT"
        ]
        == 86400
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_ABSOLUTE_TIMEOUT"
        ]
        == 2592000
    )

    assert (
        app.config[
            (
                "MARKS_AUTH_REMEMBERED_"
                "SESSION_ABSOLUTE_TIMEOUT"
            )
        ]
        == 5184000
    )


def test_high_security_profile():
    app = make_app()

    app.config[
        "MARKS_AUTH_SECURITY_PROFILE"
    ] = "high-security"

    apply_security_profile(
        app
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_TOUCH_INTERVAL"
        ]
        == 30
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_IDLE_TIMEOUT"
        ]
        == 900
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_ABSOLUTE_TIMEOUT"
        ]
        == 28800
    )

    assert (
        app.config[
            (
                "MARKS_AUTH_REMEMBERED_"
                "SESSION_ABSOLUTE_TIMEOUT"
            )
        ]
        == 86400
    )


def test_high_alias_is_supported():
    app = make_app()

    app.config[
        "MARKS_AUTH_SECURITY_PROFILE"
    ] = "high"

    profile = (
        apply_security_profile(
            app
        )
    )

    assert (
        profile
        == "high-security"
    )

    assert (
        app.config[
            "MARKS_AUTH_SECURITY_PROFILE"
        ]
        == "high-security"
    )


def test_explicit_setting_overrides_profile():
    app = make_app()

    app.config[
        "MARKS_AUTH_SECURITY_PROFILE"
    ] = "high-security"

    app.config[
        "MARKS_AUTH_SESSION_IDLE_TIMEOUT"
    ] = 1800

    apply_security_profile(
        app
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_IDLE_TIMEOUT"
        ]
        == 1800
    )

    assert (
        app.config[
            "MARKS_AUTH_SESSION_ABSOLUTE_TIMEOUT"
        ]
        == 28800
    )


def test_custom_profile_requires_values():
    app = make_app()

    app.config[
        "MARKS_AUTH_SECURITY_PROFILE"
    ] = "custom"

    with pytest.raises(
        RuntimeError,
        match=(
            "custom.*requires explicit"
        ),
    ):
        apply_security_profile(
            app
        )


def test_custom_profile_accepts_complete_policy():
    app = make_app()

    app.config.update(
        MARKS_AUTH_SECURITY_PROFILE=(
            "custom"
        ),

        MARKS_AUTH_SESSION_TOUCH_INTERVAL=(
            20
        ),

        MARKS_AUTH_SESSION_IDLE_TIMEOUT=(
            600
        ),

        MARKS_AUTH_SESSION_ABSOLUTE_TIMEOUT=(
            7200
        ),

        MARKS_AUTH_REMEMBERED_SESSION_ABSOLUTE_TIMEOUT=(
            21600
        ),
    )

    profile = (
        apply_security_profile(
            app
        )
    )

    assert profile == "custom"

    assert (
        app.config[
            "MARKS_AUTH_SESSION_IDLE_TIMEOUT"
        ]
        == 600
    )


def test_invalid_profile_rejected():
    app = make_app()

    app.config[
        "MARKS_AUTH_SECURITY_PROFILE"
    ] = "maximum-ultra-secure"

    with pytest.raises(
        RuntimeError,
        match=(
            "MARKS_AUTH_SECURITY_PROFILE"
        ),
    ):
        apply_security_profile(
            app
        )


@pytest.mark.parametrize(
    "value",
    [
        -1,
        "600",
        1.5,
        True,
        None,
    ],
)
def test_invalid_policy_value_rejected(
    value,
):
    app = make_app()

    app.config[
        "MARKS_AUTH_SECURITY_PROFILE"
    ] = "standard"

    app.config[
        "MARKS_AUTH_SESSION_IDLE_TIMEOUT"
    ] = value

    with pytest.raises(
        RuntimeError,
        match=(
            "MARKS_AUTH_SESSION_IDLE_TIMEOUT"
        ),
    ):
        apply_security_profile(
            app
        )