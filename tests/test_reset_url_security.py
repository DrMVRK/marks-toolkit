from flask import Flask

from conftest import TestUserStore as UserStoreFixture

from marks_toolkit.auth.captcha import TestCaptchaProvider
from marks_toolkit.auth.extensions import AuthKit


def make_app(reset_url):
    app = Flask(__name__)

    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = (
        "reset-url-security-test-secret"
    )

    app.config["MARKS_AUTH_RESET_URL"] = (
        reset_url
    )

    app.config[
        "MARKS_AUTH_ALLOW_CONSOLE_MAILER"
    ] = True

    app.config[
        "MARKS_AUTH_COOKIE_SECURE"
    ] = False

    return app


def init_auth(app):
    auth_kit = AuthKit()

    auth_kit.init_app(
        app,
        user_store=UserStoreFixture(),
        captcha_provider=TestCaptchaProvider(),
    )


def test_https_reset_url_is_allowed():
    app = make_app(
        "https://example.com/reset-password"
    )

    init_auth(app)

    assert (
        app.extensions["marks_auth"]
        is not None
    )


def test_http_reset_url_is_rejected_by_default():
    app = make_app(
        "http://example.com/reset-password"
    )

    try:
        init_auth(app)

    except RuntimeError as error:
        assert (
            "must use HTTPS"
            in str(error)
        )

    else:
        raise AssertionError(
            "Insecure reset URL should "
            "have been rejected."
        )


def test_http_reset_url_can_be_allowed_for_dev():
    app = make_app(
        "http://localhost/reset-password"
    )

    app.config[
        "MARKS_AUTH_ALLOW_INSECURE_RESET_URL"
    ] = True

    init_auth(app)

    assert (
        app.extensions["marks_auth"]
        is not None
    )


def test_reset_url_requires_absolute_host():
    app = make_app(
        "/reset-password"
    )

    try:
        init_auth(app)

    except RuntimeError as error:
        assert (
            "absolute HTTP or HTTPS URL"
            in str(error)
        )

    else:
        raise AssertionError(
            "Relative reset URL should "
            "have been rejected."
        )


def test_reset_url_rejects_embedded_credentials():
    app = make_app(
        "https://user:password@example.com/"
        "reset-password"
    )

    try:
        init_auth(app)

    except RuntimeError as error:
        assert (
            "must not contain embedded credentials"
            in str(error)
        )

    else:
        raise AssertionError(
            "Credential-bearing reset URL should "
            "have been rejected."
        )