from abc import ABC, abstractmethod
import httpx


class CaptchaProvider(ABC):

    @abstractmethod
    def verify(self, token, remote_ip=None):
        pass


class TestCaptchaProvider(CaptchaProvider):

    def verify(self, token, remote_ip=None):
        return token == "test-pass"


class TurnstileCaptchaProvider(CaptchaProvider):
    VERIFY_URL = (
        "https://challenges.cloudflare.com/"
        "turnstile/v0/siteverify"
    )

    def __init__(self, secret_key, timeout=5.0):
        self.secret_key = secret_key
        self.timeout = timeout

    def verify(self, token, remote_ip=None):
        if not token:
            return False

        data = {
            "secret": self.secret_key,
            "response": token
        }

        if remote_ip:
            data["remoteip"] = remote_ip

        try:
            response = httpx.post(
                self.VERIFY_URL,
                data=data,
                timeout=self.timeout
            )

            response.raise_for_status()

            result = response.json()

        except (httpx.HTTPError, ValueError):
            return False

        return result.get("success", False)