from abc import ABC, abstractmethod
import logging


class AuditLogger(ABC):

    @abstractmethod
    def log(self, event, **details):
        pass


class StandardAuditLogger(AuditLogger):

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(
            "marks_toolkit.auth"
        )

    def log(self, event, **details):
        safe_details = {
            key: value
            for key, value in details.items()
            if key not in {
                "password",
                "password_hash",
                "token",
                "captcha_token",
                "totp_secret"
            }
        }

        self.logger.info(
            "auth_event=%s details=%s",
            event,
            safe_details
        )