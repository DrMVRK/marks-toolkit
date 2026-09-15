from abc import ABC, abstractmethod
import logging


class AuditLogger(ABC):

    @abstractmethod
    def log(
        self,
        event,
        **details,
    ):
        pass


class StandardAuditLogger(AuditLogger):

    SENSITIVE_KEY_PARTS = {
        "password",
        "passwd",
        "password_hash",
        "current_password",
        "new_password",
        "token",
        "access_token",
        "refresh_token",
        "reset_token",
        "captcha_token",
        "secret",
        "totp_secret",
        "recovery_code",
        "recovery_codes",
        "provisioning_uri",
        "authorization",
        "cookie",
        "session",
    }

    REDACTED = "<redacted>"

    def __init__(
        self,
        logger=None,
    ):
        self.logger = (
            logger
            or logging.getLogger(
                "marks_toolkit.auth"
            )
        )

    def _is_sensitive_key(
        self,
        key,
    ):
        if not isinstance(
            key,
            str,
        ):
            return False

        normalized = (
            key
            .strip()
            .casefold()
        )

        if not normalized:
            return False

        for sensitive_part in (
            self.SENSITIVE_KEY_PARTS
        ):
            if (
                sensitive_part
                in normalized
            ):
                return True

        return False

    def _sanitize(
        self,
        value,
    ):
        if isinstance(
            value,
            dict,
        ):
            sanitized = {}

            for key, item in (
                value.items()
            ):
                if self._is_sensitive_key(
                    key
                ):
                    sanitized[
                        key
                    ] = self.REDACTED

                else:
                    sanitized[
                        key
                    ] = self._sanitize(
                        item
                    )

            return sanitized

        if isinstance(
            value,
            list,
        ):
            return [
                self._sanitize(
                    item
                )
                for item in value
            ]

        if isinstance(
            value,
            tuple,
        ):
            return tuple(
                self._sanitize(
                    item
                )
                for item in value
            )

        if isinstance(
            value,
            set,
        ):
            return {
                self._sanitize(
                    item
                )
                for item in value
            }

        return value

    def log(
        self,
        event,
        **details,
    ):
        safe_details = {}

        for key, value in (
            details.items()
        ):
            if self._is_sensitive_key(
                key
            ):
                safe_details[
                    key
                ] = self.REDACTED

            else:
                safe_details[
                    key
                ] = self._sanitize(
                    value
                )

        self.logger.info(
            "auth_event=%s details=%s",
            event,
            safe_details,
        )