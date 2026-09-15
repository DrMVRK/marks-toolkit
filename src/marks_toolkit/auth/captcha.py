from abc import ABC, abstractmethod

import httpx


class CaptchaProvider(ABC):

    @abstractmethod
    def verify(
        self,
        token,
        remote_ip=None,
    ):
        pass


class TestCaptchaProvider(CaptchaProvider):

    def verify(
        self,
        token,
        remote_ip=None,
    ):
        return token == "test-pass"


class TurnstileCaptchaProvider(CaptchaProvider):
    VERIFY_URL = (
        "https://challenges.cloudflare.com/"
        "turnstile/v0/siteverify"
    )

    def __init__(
        self,
        secret_key,
        timeout=5.0,
        allowed_hostnames=None,
        expected_action=None,
    ):
        if not secret_key:
            raise ValueError(
                "Turnstile secret key is required."
            )

        self.secret_key = secret_key
        self.timeout = timeout

        self.allowed_hostnames = {
            hostname.strip().casefold()
            for hostname in (
                allowed_hostnames or []
            )
            if (
                isinstance(hostname, str)
                and hostname.strip()
            )
        }

        self.expected_action = (
            expected_action.strip()
            if isinstance(
                expected_action,
                str,
            )
            and expected_action.strip()
            else None
        )

    def verify(
        self,
        token,
        remote_ip=None,
    ):
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 2048
        ):
            return False

        data = {
            "secret": self.secret_key,
            "response": token,
        }

        if remote_ip:
            data["remoteip"] = remote_ip

        try:
            response = httpx.post(
                self.VERIFY_URL,
                data=data,
                timeout=self.timeout,
            )

            response.raise_for_status()

            result = response.json()

        except (
            httpx.HTTPError,
            ValueError,
        ):
            return False

        if result.get("success") is not True:
            return False

        if self.allowed_hostnames:
            hostname = result.get(
                "hostname"
            )

            if not isinstance(
                hostname,
                str,
            ):
                return False

            if (
                hostname
                .strip()
                .casefold()
                not in self.allowed_hostnames
            ):
                return False

        if self.expected_action is not None:
            action = result.get(
                "action"
            )

            if (
                action
                != self.expected_action
            ):
                return False

        return True