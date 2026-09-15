from flask import Flask

from conftest import TestUserStore as UserStoreFixture

from marks_toolkit.auth.captcha import (
    TestCaptchaProvider,
)
from marks_toolkit.auth.extensions import AuthKit


def make_app(
    *,
    auth_cookie_secure=None,
    session_cookie_secure=None,
    remember_cookie_secure=None,
    session_cookie_samesite=None,
    remember_cookie_samesite=None,
):
    app = Flask(__name__)

    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = (
        "cookie-security-test-secret"
    )

    app.config[
        "MARKS_AUTH_ALLOW_CONSOLE_MAILER"
    ] = True

    app.config["MARKS_AUTH_RESET_URL"] = (
        "http://localhost/reset-password"
    )

    app.config[
        "MARKS_AUTH_ALLOW_INSECURE_RESET_URL"
    ] = True

    if auth_cookie_secure is not None:
        app.config[
            "MARKS_AUTH_COOKIE_SECURE"
        ] = auth_cookie_secure

    if session_cookie_secure is not None:
        app.config[
            "SESSION_COOKIE_SECURE"
        ] = session_cookie_secure

    if remember_cookie_secure is not None:
        app.config[
            "REMEMBER_COOKIE_SECURE"
        ] = remember_cookie_secure

    if session_cookie_samesite is not None:
        app.config[
            "SESSION_COOKIE_SAMESITE"
        ] = session_cookie_samesite

    if remember_cookie_samesite is not None:
        app.config[
            "REMEMBER_COOKIE_SAMESITE"
        ] = remember_cookie_samesite

    auth_kit = AuthKit()

    auth_kit.init_app(
        app,
        user_store=UserStoreFixture(),
        captcha_provider=TestCaptchaProvider(),
    )

    return app


def test_cookies_are_secure_by_default():
    app = make_app()

    assert (
        app.config[
            "SESSION_COOKIE_SECURE"
        ]
        is True
    )

    assert (
        app.config[
            "REMEMBER_COOKIE_SECURE"
        ]
        is True
    )

    assert (
        app.config[
            "SESSION_COOKIE_HTTPONLY"
        ]
        is True
    )

    assert (
        app.config[
            "REMEMBER_COOKIE_HTTPONLY"
        ]
        is True
    )


def test_local_development_can_disable_secure_cookies():
    app = make_app(
        auth_cookie_secure=False,
    )

    assert (
        app.config[
            "SESSION_COOKIE_SECURE"
        ]
        is False
    )

    assert (
        app.config[
            "REMEMBER_COOKIE_SECURE"
        ]
        is False
    )


def test_authkit_does_not_downgrade_host_secure_cookies():
    app = make_app(
        auth_cookie_secure=False,
        session_cookie_secure=True,
        remember_cookie_secure=True,
    )

    assert (
        app.config[
            "SESSION_COOKIE_SECURE"
        ]
        is True
    )

    assert (
        app.config[
            "REMEMBER_COOKIE_SECURE"
        ]
        is True
    )


def test_authkit_preserves_host_samesite_policy():
    app = make_app(
        session_cookie_samesite="Strict",
        remember_cookie_samesite="Strict",
    )

    assert (
        app.config[
            "SESSION_COOKIE_SAMESITE"
        ]
        == "Strict"
    )

    assert (
        app.config[
            "REMEMBER_COOKIE_SAMESITE"
        ]
        == "Strict"
    )