from itsdangerous import (
    BadSignature,
    SignatureExpired,
    URLSafeTimedSerializer
)

class ResetTokenService:
    def __init__(self, secret_key, max_age=1800):
        self.serializer = URLSafeTimedSerializer(secret_key)
        self.max_age = max_age
        self.salt = "marks_auth_password_reset"

    def generate(self, auth_id):
        return self.serializer.dumps(
            {"auth_id": auth_id},
            salt=self.salt
        )

    def verify(self, token):
        try:
            return self.serializer.loads(
                token,
                salt=self.salt,
                max_age=self.max_age
            )
        except (BadSignature, SignatureExpired):
            return None