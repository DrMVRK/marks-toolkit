import hashlib
import hmac
import secrets


class RecoveryCodeService:
    def __init__(
        self,
        key,
        code_count=10,
    ):
        if not key:
            raise ValueError(
                "Recovery-code key is required."
            )

        if isinstance(key, str):
            key = key.encode(
                "utf-8"
            )

        self.key = key
        self.code_count = code_count

    def normalize_code(
        self,
        code,
    ):
        if not isinstance(
            code,
            str,
        ):
            raise ValueError(
                "Recovery code must be a string."
            )

        normalized = (
            code.strip()
            .replace("-", "")
            .replace(" ", "")
            .upper()
        )

        if not normalized:
            raise ValueError(
                "Recovery code is required."
            )

        return normalized

    def generate_code(self):
        raw = secrets.token_hex(
            8
        ).upper()

        return "-".join(
            raw[index:index + 4]
            for index in range(
                0,
                len(raw),
                4,
            )
        )

    def generate_codes(
        self,
        count=None,
    ):
        if count is None:
            count = self.code_count

        return [
            self.generate_code()
            for _ in range(count)
        ]

    def hash_code(
        self,
        code,
    ):
        normalized = (
            self.normalize_code(
                code
            )
        )

        return hmac.new(
            self.key,
            normalized.encode(
                "utf-8"
            ),
            hashlib.sha256,
        ).hexdigest()

    def hash_codes(
        self,
        codes,
    ):
        return [
            self.hash_code(code)
            for code in codes
        ]

    def verify(
        self,
        code,
        stored_hash,
    ):
        try:
            candidate_hash = (
                self.hash_code(code)
            )

        except ValueError:
            return False

        if not isinstance(
            stored_hash,
            str,
        ):
            return False

        return hmac.compare_digest(
            candidate_hash,
            stored_hash,
        )