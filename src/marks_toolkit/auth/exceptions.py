class AuthError(Exception):
    code = "AUTH_ERROR"
    status_code = 400

    def __init__(self, message):
        super().__init__(message)
        self.message = message
        
class InvalidIdentityError(AuthError):
    code = "INVALID_IDENTITY"
    status_code = 400


class WeakPasswordError(AuthError):
    code = "WEAK_PASSWORD"
    status_code = 400


class IdentityUnavailableError(AuthError):
    code = "IDENTITY_UNAVAILABLE"
    status_code = 409