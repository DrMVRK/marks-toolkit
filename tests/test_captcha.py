import httpx

from marks_toolkit.auth.captcha import (
    TurnstileCaptchaProvider,
)


class FakeResponse:
    def __init__(
        self,
        payload,
        status_code=200,
    ):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "Test HTTP error",
                request=httpx.Request(
                    "POST",
                    "https://example.test",
                ),
                response=httpx.Response(
                    self.status_code,
                ),
            )

    def json(self):
        return self.payload


def test_turnstile_accepts_successful_response(
    monkeypatch,
):
    def fake_post(*args, **kwargs):
        return FakeResponse({
            "success": True,
            "hostname": "example.com",
            "action": "login",
        })

    monkeypatch.setattr(
        httpx,
        "post",
        fake_post,
    )

    provider = TurnstileCaptchaProvider(
        secret_key="test-secret",
        allowed_hostnames=[
            "example.com",
        ],
        expected_action="login",
    )

    assert (
        provider.verify(
            "test-token",
            remote_ip="203.0.113.10",
        )
        is True
    )


def test_turnstile_rejects_wrong_hostname(
    monkeypatch,
):
    def fake_post(*args, **kwargs):
        return FakeResponse({
            "success": True,
            "hostname": "evil.example",
            "action": "login",
        })

    monkeypatch.setattr(
        httpx,
        "post",
        fake_post,
    )

    provider = TurnstileCaptchaProvider(
        secret_key="test-secret",
        allowed_hostnames=[
            "example.com",
        ],
        expected_action="login",
    )

    assert (
        provider.verify(
            "test-token"
        )
        is False
    )


def test_turnstile_rejects_wrong_action(
    monkeypatch,
):
    def fake_post(*args, **kwargs):
        return FakeResponse({
            "success": True,
            "hostname": "example.com",
            "action": "register",
        })

    monkeypatch.setattr(
        httpx,
        "post",
        fake_post,
    )

    provider = TurnstileCaptchaProvider(
        secret_key="test-secret",
        allowed_hostnames=[
            "example.com",
        ],
        expected_action="login",
    )

    assert (
        provider.verify(
            "test-token"
        )
        is False
    )


def test_turnstile_rejects_failed_response(
    monkeypatch,
):
    def fake_post(*args, **kwargs):
        return FakeResponse({
            "success": False,
        })

    monkeypatch.setattr(
        httpx,
        "post",
        fake_post,
    )

    provider = TurnstileCaptchaProvider(
        secret_key="test-secret",
    )

    assert (
        provider.verify(
            "test-token"
        )
        is False
    )


def test_turnstile_rejects_non_string_token():
    provider = TurnstileCaptchaProvider(
        secret_key="test-secret",
    )

    assert (
        provider.verify(
            {"bad": "type"}
        )
        is False
    )


def test_turnstile_rejects_oversized_token():
    provider = TurnstileCaptchaProvider(
        secret_key="test-secret",
    )

    token = "a" * 2049

    assert (
        provider.verify(token)
        is False
    )