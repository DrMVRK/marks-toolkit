import secrets
import hmac

from flask import session


class CSRFService:
    SESSION_KEY = "_marks_auth_csrf"

    def get_token(self):
        token = session.get(self.SESSION_KEY)

        if token is None:
            token = secrets.token_urlsafe(32)
            session[self.SESSION_KEY] = token

        return token

    def validate_token(self, token):
        expected =  session.get(self.SESSION_KEY)

        if expected is None:
            return False

        if not isinstance(token, str):
            return False

        return hmac.compare_digest(expected, token)

    def validate_request(self, request):
        token = request.headers.get("X-CSRF-Token")

        return self.validate_token(token)