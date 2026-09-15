from flask import Flask

from conftest import TestUserStore as UserStoreFixture

from marks_toolkit.auth.captcha import (
    TestCaptchaProvider,
)
from marks_toolkit.auth.extensions import AuthKit
from marks_toolkit.auth.mailer import ConsoleMailer


def make_base_app():
    app = Flask(__name__)

    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = (
        "mailer-configuration-test-secret"
    )

    app.config["MARKS_AUTH_RESET_URL"] = (
        "http://localhost/reset-password"
    )

    app.config[
        "MARKS_AUTH_ALLOW_INSECURE_RESET_URL"
    ] = True

    app.config[
        "MARKS_AUTH_COOKIE_SECURE"
    ] = False

    return app


def test_missing_mailer_is_rejected_by_default():
    app = make_base_app()

    auth_kit = AuthKit()

    try:
        auth_kit.init_app(
            app,
            user_store=UserStoreFixture(),
            captcha_provider=TestCaptchaProvider(),
        )

    except RuntimeError as error:
        assert (
            "requires an explicit mailer"
            in str(error)
        )

    else:
        raise AssertionError(
            "AuthKit should reject a missing mailer."
        )


def test_console_mailer_can_be_explicitly_enabled():
    app = make_base_app()

    app.config[
        "MARKS_AUTH_ALLOW_CONSOLE_MAILER"
    ] = True

    auth_kit = AuthKit()

    auth_kit.init_app(
        app,
        user_store=UserStoreFixture(),
        captcha_provider=TestCaptchaProvider(),
    )

    state = app.extensions[
        "marks_auth"
    ]

    assert isinstance(
        state.mailer,
        ConsoleMailer,
    )