import hashlib
import hmac
import secrets


class RecoveryCodeService:

    def __init__(
        self,
        hashing_key,
        code_count=10,
    ):
        if not hashing_key:
            raise ValueError(
                "A recovery-code hashing key is required."
            )

        if isinstance(hashing_key, str):
            hashing_key = hashing_key.encode(
                "utf-8"
            )

        self.hashing_key = hashing_key
        self.code_count = code_count

    def generate_code(self):
        raw = secrets.token_hex(8).upper()

        return (
            f"{raw[:4]}-"
            f"{raw[4:8]}-"
            f"{raw[8:12]}-"
            f"{raw[12:16]}"
        )

    def generate_codes(self):
        return [
            self.generate_code()
            for _ in range(self.code_count)
        ]

    def normalize_code(self, code):
        if not isinstance(code, str):
            raise ValueError(
                "Recovery code must be a string."
            )

        return (
            code
            .strip()
            .replace("-", "")
            .upper()
        )

    def hash_code(self, code):
        normalized = self.normalize_code(code)

        if not normalized:
            raise ValueError(
                "Recovery code is required."
            )

        digest = hmac.new(
            self.hashing_key,
            normalized.encode("utf-8"),
            hashlib.sha256,
        )

        return digest.hexdigest()

    def hash_codes(self, codes):
        return [
            self.hash_code(code)
            for code in codes
        ]

    def verify_code(
        self,
        submitted_code,
        stored_hash,
    ):
        submitted_hash = self.hash_code(
            submitted_code
        )

        return hmac.compare_digest(
            submitted_hash,
            stored_hash,
        )