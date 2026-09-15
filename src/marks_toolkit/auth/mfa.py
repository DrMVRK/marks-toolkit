from .exceptions import AuthError


class MFAError(AuthError):
    pass


class TotpAlreadyEnabledError(MFAError):
    code = "TOTP_ALREADY_ENABLED"
    status_code = 409


class TotpEnrollmentNotFoundError(MFAError):
    code = "TOTP_ENROLLMENT_NOT_FOUND"
    status_code = 400


class InvalidTotpCodeError(MFAError):
    code = "INVALID_TOTP_CODE"
    status_code = 400

class InvalidMFAPasswordError(MFAError):
    code = "INVALID_MFA_PASSWORD"
    status_code = 400

