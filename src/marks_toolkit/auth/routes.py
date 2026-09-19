import base64
import hashlib
import hmac

from flask import Blueprint, current_app, request
from flask_login import (
    current_user,
    login_required,
)

from .responses import (
    success_response,
    error_response,
    no_store_response,
)
from .exceptions import AuthError
from .decorators import (
    csrf_protected,
    throttle,
)
from .request_validation import (
    get_json_object,
    get_required_string,
    get_optional_string,
    get_optional_bool,
)
from webauthn.helpers.exceptions import (
    WebAuthnException,
)
from .session_runtime import (
    clear_authenticated_session,
    clear_persistent_session_cookie,
    establish_authenticated_session,
    get_current_session_id,
    revoke_current_session,
    set_persistent_session_cookie,
)

auth_bp = Blueprint("marks_auth", __name__)

def encode_passkey_credential_id(
    credential_id,
):
    if not isinstance(
        credential_id,
        bytes,
    ):
        raise TypeError(
            "credential_id must be bytes"
        )

    return (
        base64.urlsafe_b64encode(
            credential_id
        )
        .rstrip(b"=")
        .decode("ascii")
    )


def decode_passkey_credential_id(
    encoded_id,
):
    if (
        not isinstance(encoded_id, str)
        or not encoded_id
    ):
        raise ValueError(
            "Invalid passkey credential ID."
        )

    try:
        encoded_bytes = (
            encoded_id.encode("ascii")
        )

    except UnicodeEncodeError as error:
        raise ValueError(
            "Invalid passkey credential ID."
        ) from error

    padding = (
        b"="
        * (
            -len(encoded_bytes)
            % 4
        )
    )

    try:
        return (
            base64.urlsafe_b64decode(
                encoded_bytes
                + padding
            )
        )

    except Exception as error:
        raise ValueError(
            "Invalid passkey credential ID."
        ) from error

def encode_session_public_id(
    session_id,
):
    if (
        not isinstance(session_id, str)
        or not session_id
    ):
        raise ValueError(
            "Invalid session ID."
        )

    return hashlib.sha256(
        session_id.encode("utf-8")
    ).hexdigest()


def find_session_by_public_id(
    state,
    user_id,
    public_id,
):
    if (
        not isinstance(public_id, str)
        or len(public_id) != 64
    ):
        return None

    sessions = (
        state.session_store
        .list_for_user(
            user_id,
            include_revoked=False,
        )
    )

    for record in sessions:
        candidate = (
            encode_session_public_id(
                record.id
            )
        )

        if hmac.compare_digest(
            candidate,
            public_id,
        ):
            return record

    return None

def refresh_security_session(
    state,
    user,
):
    # Security-sensitive credential changes invalidate every
    # registered session for this account.
    state.session_service.revoke_all_sessions(
        user=user
    )

    state.user_store.rotate_auth_id(
        user
    )

    clear_authenticated_session()

    return establish_authenticated_session(
        state=state,
        user=user,
        authentication_method=(
            "security-refresh"
        ),
        remembered=False,
    )

@auth_bp.get("/test")
def test_route():
    return {
        "ok": True,
        "message": "MARKS AuthKit is working",
    }


@auth_bp.get("/me")
def me():
    if not current_user.is_authenticated:
        return success_response(
            data={
                "authenticated": False,
                "user": None,
            }
        )

    return success_response(
        data={
            "authenticated": True,
            "user": {
                "auth_id": current_user.auth_id,
                "username": current_user.username,
                "email": current_user.email,
            },
        }
    )


@auth_bp.post("/register")
@csrf_protected
@throttle(
    action="registration",
    identities=("ip",),
    limit_config="registration_limit",
    window_config="registration_window",
)
def register():
    state = current_app.extensions["marks_auth"]

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    email, field_error = get_required_string(
        data,
        "email",
    )

    if field_error is not None:
        return field_error

    username, field_error = get_required_string(
        data,
        "username",
    )

    if field_error is not None:
        return field_error

    password, field_error = get_required_string(
        data,
        "password",
    )

    if field_error is not None:
        return field_error

    try:
        state.registration_service.register(
            email=email,
            username=username,
            password=password,
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    return success_response(
        message="User registered successfully.",
        status_code=201,
    )


@auth_bp.post("/login")
@csrf_protected
def login():
    state = current_app.extensions["marks_auth"]

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    identity, field_error = (
        get_required_string(
            data,
            "identity",
        )
    )

    if field_error is not None:
        return field_error

    password, field_error = (
        get_required_string(
            data,
            "password",
        )
    )

    if field_error is not None:
        return field_error

    ip_address = request.remote_addr or "unknown"

    remember, field_error = (
        get_optional_bool(
            data,
            "remember",
            default=False,
        )
    )
    
    if field_error is not None:
        return field_error

    decision = state.risk_service.assess(
        action="login",
        identity=identity or "",
        ip_address=ip_address,
    )

    if decision.blocked:
        state.audit_logger.log(
            "login_rate_limited",
            identity=identity or "",
            ip_address=ip_address,
            risk_score=decision.score,
        )

        return error_response(
            code="RATE_LIMITED",
            message=(
                "Too many failed login attempts. "
                "Please try again later."
            ),
            status_code=429,
        )

    if decision.captcha_required:
        captcha_token = data.get("captcha_token")

        if not state.captcha_provider.verify(
            captcha_token,
            remote_ip=ip_address,
        ):
            state.audit_logger.log(
                "captcha_required",
                identity=identity or "",
                ip_address=ip_address,
                risk_score=decision.score,
            )

            return error_response(
                code="CAPTCHA_REQUIRED",
                message="Please complete the security check.",
                status_code=403,
            )

    try:
        user = state.login_service.authenticate(
            identity=identity,
            password=password,
        )

    except AuthError as error:
        state.risk_service.record_failure(
            action="login",
            identity=identity or "",
            ip_address=ip_address,
        )

        state.audit_logger.log(
            "login_failure",
            identity=identity or "",
            ip_address=ip_address,
            error_code=error.code,
        )

        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    state.risk_service.record_success(
        action="login",
        identity=identity or "",
        ip_address=ip_address,
    )

    if (
        state.config.mfa_enabled
        and state.mfa_store.has_enabled_mfa(
            user.id
        )
    ):
        challenge_id = (
            state.mfa_challenge_service.create(
                user=user,
                remember=remember,
            )
        )

        methods = []

        totp = state.mfa_store.get_totp(
            user.id
        )

        if (
            totp is not None
            and totp.enabled
        ):
            methods.append("totp")

        if (
            state.recovery_code_manager
            .count_unused_codes(user)
            > 0
        ):
            methods.append(
                "recovery_code"
            )

        state.audit_logger.log(
            "mfa_challenge_created",
            auth_id=user.auth_id,
            username=user.username,
            ip_address=ip_address,
            methods=methods,
        )

        return success_response(
            data={
                "mfa_required": True,
                "challenge_id": challenge_id,
                "methods": methods,
            },
            message="Additional authentication is required.",
            status_code=202,
        )

    session_record = (
        establish_authenticated_session(
            state=state,
            user=user,
            authentication_method=(
                "password"
            ),
            remembered=remember,
        )
    )

    state.audit_logger.log(
        "login_success",
        auth_id=user.auth_id,
        username=user.username,
        ip_address=ip_address,
        remember=remember,
        session_id=session_record.id,
        authentication_method=(
            "password"
        ),
    )

    response = success_response(
        data={
            "auth_id": user.auth_id,
            "username": user.username,
            "email": user.email,
        },
        message="Login successful.",
    )

    return set_persistent_session_cookie(
        response,
        state=state,
        session_record=session_record,
    )


@auth_bp.post("/logout")
@login_required
@csrf_protected
def logout():
    state = current_app.extensions[
        "marks_auth"
    ]

    session_id = (
        get_current_session_id()
    )

    if session_id:
        state.audit_logger.log(
            "session_logout",
            auth_id=current_user.auth_id,
            username=current_user.username,
            session_id=session_id,
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

    revoke_current_session(
        state
    )

    response = success_response(
        message="Logout successful."
    )

    return clear_persistent_session_cookie(
        response
    )


@auth_bp.get("/csrf")
def csrf():
    state = current_app.extensions["marks_auth"]

    token = state.csrf_service.get_token()

    return success_response(
        data={
            "csrf_token": token,
        }
    )


@auth_bp.post("/forgot-password")
@csrf_protected
@throttle(
    action="forgot-password",
    identities=("ip", "email"),
    limit_config="forgot_password_limit",
    window_config="forgot_password_window",
)
def forgot_password():
    state = current_app.extensions["marks_auth"]

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    email, field_error = get_required_string(
        data,
        "email",
    )

    if field_error is not None:
        return field_error

    state.password_reset_service.request_reset(
        email=email,
        reset_url=state.config.reset_url,
    )

    return success_response(
        message=(
            "If an account exists for that email address, "
            "a password reset link has been sent."
        )
    )


@auth_bp.post("/reset-password")
@csrf_protected
@throttle(
    action="reset-password",
    identities=("ip",),
    limit_config="reset_password_limit",
    window_config="reset_password_window",
)
def reset_password():
    state = current_app.extensions["marks_auth"]

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    token, field_error = get_required_string(
        data,
        "token",
    )

    if field_error is not None:
        return field_error

    new_password, field_error = get_required_string(
        data,
        "password",
    )

    if field_error is not None:
        return field_error

    try:
        state.password_reset_service.reset_password(
            token,
            new_password,
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    return success_response(
        message="Password reset successfully."
    )


@auth_bp.post("/change-password")
@login_required
@csrf_protected
@throttle(
    action="password-change",
    identities=("ip",),
    limit_config="password_change_limit",
    window_config="password_change_window",
)
def change_password():
    state = current_app.extensions["marks_auth"]

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    current_password, field_error = (
        get_required_string(
            data,
            "current_password",
        )
    )

    if field_error is not None:
        return field_error

    new_password, field_error = (
        get_required_string(
            data,
            "new_password",
        )
    )

    if field_error is not None:
        return field_error

    try:
        state.password_change_service.change_password(
            user=current_user,
            current_password=current_password,
            new_password=new_password,
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    state.audit_logger.log(
        "password_changed",
        auth_id=current_user.auth_id,
        username=current_user.username,
        ip_address=request.remote_addr or "unknown",
    )

    state.session_service.revoke_all_sessions(
        user=current_user
    )

    clear_authenticated_session()

    response = success_response(
        message=(
            "Password changed successfully. "
            "Please log in again."
        )
    )

    return clear_persistent_session_cookie(
        response
    )


@auth_bp.get("/mfa/status")
@login_required
def mfa_status():
    state = current_app.extensions[
        "marks_auth"
    ]

    totp_enabled = False

    if (
        state.config.mfa_enabled
        and state.mfa_store is not None
    ):
        totp = state.mfa_store.get_totp(
            current_user.id
        )

        totp_enabled = (
            totp is not None
            and totp.enabled
        )

    passkey_count = 0

    if (
        state.config.webauthn_enabled
        and state.passkey_store is not None
    ):
        passkey_count = len(
            state.passkey_store.list_for_user(
                current_user.id
            )
        )

    mfa_enabled = False

    if (
        state.config.mfa_enabled
        and state.mfa_store is not None
    ):
        mfa_enabled = (
            state.mfa_store.has_enabled_mfa(
                current_user.id
            )
        )

    return success_response(
        data={
            "mfa_enabled": mfa_enabled,
            "totp_enabled": totp_enabled,
            "passkey_count": passkey_count,
            "passkeys_available": (
                state.config.webauthn_enabled
            ),
        }
    )


@auth_bp.post(
    "/passkeys/register/options"
)
@login_required
@csrf_protected
@throttle(
    action="passkey-enrollment",
    identities=("ip",),
    limit_config="passkey_enrollment_limit",
    window_config="passkey_enrollment_window",
)
def begin_passkey_registration():
    state = current_app.extensions[
        "marks_auth"
    ]

    if not state.config.webauthn_enabled:
        return error_response(
            code="WEBAUTHN_DISABLED",
            message=(
                "Passkey authentication is not "
                "enabled for this application."
            ),
            status_code=404,
        )

    if state.passkey_service is None:
        return error_response(
            code="WEBAUTHN_UNAVAILABLE",
            message=(
                "Passkey authentication is "
                "currently unavailable."
            ),
            status_code=503,
        )

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    current_password, field_error = (
        get_required_string(
            data,
            "current_password",
        )
    )

    if field_error is not None:
        return field_error

    if not state.password_service.verify_password(
        current_user.password_hash,
        current_password,
    ):
        state.audit_logger.log(
            "passkey_enrollment_reauth_failed",
            auth_id=current_user.auth_id,
            username=current_user.username,
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        return error_response(
            code="INVALID_PASSWORD",
            message=(
                "Current password is incorrect."
            ),
            status_code=401,
        )

    try:
        registration = (
            state.passkey_service
            .begin_registration(
                current_user
            )
        )

    except (
        ValueError,
        RuntimeError,
    ):
        return error_response(
            code="PASSKEY_REGISTRATION_FAILED",
            message=(
                "Passkey registration could "
                "not be started."
            ),
            status_code=400,
        )

    state.audit_logger.log(
        "passkey_enrollment_started",
        auth_id=current_user.auth_id,
        username=current_user.username,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
    )

    return no_store_response(
        data={
            "challenge_id": (
                registration[
                    "challenge_id"
                ]
            ),
            "options": (
                registration[
                    "options"
                ]
            ),
        },
        message=(
            "Passkey registration started."
        ),
    )


@auth_bp.post(
    "/passkeys/register/verify"
)
@login_required
@csrf_protected
@throttle(
    action="passkey-enrollment",
    identities=("ip",),
    limit_config="passkey_enrollment_limit",
    window_config="passkey_enrollment_window",
)
def finish_passkey_registration():
    state = current_app.extensions[
        "marks_auth"
    ]

    if not state.config.webauthn_enabled:
        return error_response(
            code="WEBAUTHN_DISABLED",
            message=(
                "Passkey authentication is not "
                "enabled for this application."
            ),
            status_code=404,
        )

    if state.passkey_service is None:
        return error_response(
            code="WEBAUTHN_UNAVAILABLE",
            message=(
                "Passkey authentication is "
                "currently unavailable."
            ),
            status_code=503,
        )

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    challenge_id, field_error = (
        get_required_string(
            data,
            "challenge_id",
        )
    )

    if field_error is not None:
        return field_error

    credential = data.get(
        "credential"
    )

    if not isinstance(
        credential,
        dict,
    ):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "A WebAuthn credential "
                "response is required."
            ),
            status_code=400,
        )

    name, field_error = (
        get_optional_string(
            data,
            "name",
        )
    )

    if field_error is not None:
        return field_error

    try:
        passkey = (
            state.passkey_service
            .finish_registration(
                user=current_user,
                challenge_id=challenge_id,
                credential=credential,
                name=name,
            )
        )

    except (
        WebAuthnException,
        ValueError,
        TypeError,
        RuntimeError,
    ):
        state.audit_logger.log(
            "passkey_enrollment_failed",
            auth_id=current_user.auth_id,
            username=current_user.username,
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        return error_response(
            code="INVALID_PASSKEY_REGISTRATION",
            message=(
                "Passkey registration could "
                "not be verified."
            ),
            status_code=400,
        )

    user = (
        current_user
        ._get_current_object()
    )

    refresh_security_session(
        state,
        user,
    )

    state.audit_logger.log(
        "passkey_enabled",
        auth_id=user.auth_id,
        username=user.username,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
    )

    response = success_response(
        data={
            "passkey": {
                "id": passkey.id,
                "name": passkey.name,
                "created_at": (
                    passkey.created_at
                    .isoformat()
                ),
            },
        },
        message=(
            "Passkey registered successfully."
        ),
        status_code=201,
    )

    return clear_persistent_session_cookie(
        response
    )


@auth_bp.post(
    "/passkeys/login/options"
)
@csrf_protected
@throttle(
    action="passkey-login-options",
    identities=("ip",),
    limit_config="passkey_login_limit",
    window_config="passkey_login_window",
)
def begin_passkey_login():
    state = current_app.extensions[
        "marks_auth"
    ]

    if not state.config.webauthn_enabled:
        return error_response(
            code="WEBAUTHN_DISABLED",
            message=(
                "Passkey authentication is not "
                "enabled for this application."
            ),
            status_code=404,
        )

    if state.passkey_service is None:
        return error_response(
            code="WEBAUTHN_UNAVAILABLE",
            message=(
                "Passkey authentication is "
                "currently unavailable."
            ),
            status_code=503,
        )

    try:
        authentication = (
            state.passkey_service
            .begin_authentication()
        )

    except (
        WebAuthnException,
        ValueError,
        TypeError,
        RuntimeError,
    ):
        state.audit_logger.log(
            "passkey_login_options_failed",
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        return error_response(
            code="PASSKEY_LOGIN_FAILED",
            message=(
                "Passkey authentication could "
                "not be started."
            ),
            status_code=400,
        )

    return no_store_response(
        data={
            "challenge_id": (
                authentication[
                    "challenge_id"
                ]
            ),
            "options": (
                authentication[
                    "options"
                ]
            ),
        },
        message=(
            "Passkey authentication started."
        ),
    )


@auth_bp.post(
    "/passkeys/login/verify"
)
@csrf_protected
@throttle(
    action="passkey-login-verify",
    identities=(
        "ip",
        "challenge",
    ),
    limit_config="passkey_login_limit",
    window_config="passkey_login_window",
)
def finish_passkey_login():
    state = current_app.extensions[
        "marks_auth"
    ]

    if not state.config.webauthn_enabled:
        return error_response(
            code="WEBAUTHN_DISABLED",
            message=(
                "Passkey authentication is not "
                "enabled for this application."
            ),
            status_code=404,
        )

    if state.passkey_service is None:
        return error_response(
            code="WEBAUTHN_UNAVAILABLE",
            message=(
                "Passkey authentication is "
                "currently unavailable."
            ),
            status_code=503,
        )

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    challenge_id, field_error = (
        get_required_string(
            data,
            "challenge_id",
        )
    )

    if field_error is not None:
        return field_error

    credential = data.get(
        "credential"
    )

    if not isinstance(
        credential,
        dict,
    ):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "A WebAuthn credential "
                "response is required."
            ),
            status_code=400,
        )

    try:
        user_id = (
            state.passkey_service
            .finish_authentication(
                challenge_id=challenge_id,
                credential=credential,
            )
        )

    except (
        WebAuthnException,
        ValueError,
        TypeError,
        RuntimeError,
        KeyError,
    ):
        state.audit_logger.log(
            "passkey_login_failure",
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        return error_response(
            code="INVALID_PASSKEY",
            message=(
                "Passkey authentication failed."
            ),
            status_code=401,
        )

    user = state.user_store.find_by_id(
        user_id
    )

    if user is None:
        state.audit_logger.log(
            "passkey_login_failure",
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        return error_response(
            code="INVALID_PASSKEY",
            message=(
                "Passkey authentication failed."
            ),
            status_code=401,
        )

    if not getattr(
        user,
        "is_active",
        False,
    ):
        state.audit_logger.log(
            "passkey_login_failure",
            auth_id=getattr(
                user,
                "auth_id",
                None,
            ),
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        return error_response(
            code="ACCOUNT_UNAVAILABLE",
            message=(
                "This account is not available."
            ),
            status_code=403,
        )

    session_record = (
        establish_authenticated_session(
            state=state,
            user=user,
            authentication_method=(
                "passkey"
            ),
            remembered=False,
        )
    )

    state.audit_logger.log(
        "login_success",
        auth_id=user.auth_id,
        username=user.username,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
        remember=False,
        authentication_method="passkey",
        session_id=session_record.id,
    )

    return success_response(
        data={
            "auth_id": user.auth_id,
            "username": user.username,
            "email": user.email,
        },
        message="Login successful.",
    )


@auth_bp.get("/passkeys")
@login_required
def list_passkeys():
    state = current_app.extensions[
        "marks_auth"
    ]

    if not state.config.webauthn_enabled:
        return error_response(
            code="WEBAUTHN_DISABLED",
            message=(
                "Passkey authentication is not "
                "enabled for this application."
            ),
            status_code=404,
        )

    if state.passkey_store is None:
        return error_response(
            code="WEBAUTHN_UNAVAILABLE",
            message=(
                "Passkey authentication is "
                "currently unavailable."
            ),
            status_code=503,
        )

    credentials = (
        state.passkey_store.list_for_user(
            current_user.id
        )
    )

    passkeys = []

    for credential in credentials:
        passkeys.append(
            {
                "credential_id": (
                    encode_passkey_credential_id(
                        credential.credential_id
                    )
                ),

                "name": credential.name,

                "created_at": (
                    credential.created_at
                    .isoformat()
                    if credential.created_at
                    is not None
                    else None
                ),

                "last_used_at": (
                    credential.last_used_at
                    .isoformat()
                    if credential.last_used_at
                    is not None
                    else None
                ),

                "transports": list(
                    credential.transports
                ),
            }
        )

    return no_store_response(
        data={
            "passkeys": passkeys,
        }
    )


@auth_bp.patch(
    "/passkeys/<credential_id>"
)
@login_required
@csrf_protected
def rename_passkey(
    credential_id,
):
    state = current_app.extensions[
        "marks_auth"
    ]

    if not state.config.webauthn_enabled:
        return error_response(
            code="WEBAUTHN_DISABLED",
            message=(
                "Passkey authentication is not "
                "enabled for this application."
            ),
            status_code=404,
        )

    if state.passkey_store is None:
        return error_response(
            code="WEBAUTHN_UNAVAILABLE",
            message=(
                "Passkey authentication is "
                "currently unavailable."
            ),
            status_code=503,
        )

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    name = data.get("name")

    if name is not None:
        if not isinstance(name, str):
            return error_response(
                code="INVALID_REQUEST",
                message=(
                    "Passkey name must be "
                    "a string."
                ),
                status_code=400,
            )

        name = name.strip()

        if not name:
            name = None

        elif len(name) > 100:
            return error_response(
                code="INVALID_REQUEST",
                message=(
                    "Passkey name must be "
                    "100 characters or fewer."
                ),
                status_code=400,
            )

    try:
        credential_id_bytes = (
            decode_passkey_credential_id(
                credential_id
            )
        )

    except ValueError:
        return error_response(
            code="PASSKEY_NOT_FOUND",
            message=(
                "Passkey was not found."
            ),
            status_code=404,
        )

    updated = (
        state.passkey_store.update_name(
            current_user.id,
            credential_id_bytes,
            name=name,
        )
    )

    if not updated:
        return error_response(
            code="PASSKEY_NOT_FOUND",
            message=(
                "Passkey was not found."
            ),
            status_code=404,
        )

    state.audit_logger.log(
        "passkey_renamed",
        auth_id=current_user.auth_id,
        username=current_user.username,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
    )

    return success_response(
        data={
            "credential_id":
                credential_id,

            "name":
                name,
        },
        message=(
            "Passkey renamed successfully."
        ),
    )


@auth_bp.delete(
    "/passkeys/<credential_id>"
)
@login_required
@csrf_protected
def delete_passkey(
    credential_id,
):
    state = current_app.extensions[
        "marks_auth"
    ]

    if not state.config.webauthn_enabled:
        return error_response(
            code="WEBAUTHN_DISABLED",
            message=(
                "Passkey authentication is not "
                "enabled for this application."
            ),
            status_code=404,
        )

    if state.passkey_store is None:
        return error_response(
            code="WEBAUTHN_UNAVAILABLE",
            message=(
                "Passkey authentication is "
                "currently unavailable."
            ),
            status_code=503,
        )

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    current_password, field_error = (
        get_required_string(
            data,
            "current_password",
        )
    )

    if field_error is not None:
        return field_error

    if not (
        state.password_service
        .verify_password(
            current_user.password_hash,
            current_password,
        )
    ):
        state.audit_logger.log(
            "passkey_delete_reauth_failed",
            auth_id=current_user.auth_id,
            username=current_user.username,
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        return error_response(
            code="INVALID_PASSWORD",
            message=(
                "Current password is incorrect."
            ),
            status_code=401,
        )

    try:
        credential_id_bytes = (
            decode_passkey_credential_id(
                credential_id
            )
        )

    except ValueError:
        return error_response(
            code="PASSKEY_NOT_FOUND",
            message=(
                "Passkey was not found."
            ),
            status_code=404,
        )

    deleted = (
        state.passkey_store.delete(
            current_user.id,
            credential_id_bytes,
        )
    )

    if not deleted:
        return error_response(
            code="PASSKEY_NOT_FOUND",
            message=(
                "Passkey was not found."
            ),
            status_code=404,
        )

    user = (
        current_user
        ._get_current_object()
    )

    refresh_security_session(
        state,
        user,
    )

    state.audit_logger.log(
        "passkey_deleted",
        auth_id=user.auth_id,
        username=user.username,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
    )

    response = success_response(
        message=(
            "Passkey deleted successfully."
        )
    )

    return clear_persistent_session_cookie(
        response
    )


@auth_bp.post("/mfa/totp/enroll")
@login_required
@csrf_protected
def enroll_totp():
    state = current_app.extensions["marks_auth"]

    if not state.config.mfa_enabled:
        return error_response(
            code="MFA_DISABLED",
            message="MFA is not enabled for this application.",
            status_code=404,
        )

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    current_password, field_error = (
        get_required_string(
            data,
            "current_password",
        )
    )

    if field_error is not None:
        return field_error

    try:
        enrollment = (
            state.totp_service.begin_enrollment(
                user=current_user,
                current_password=current_password,
                password_service=(
                    state.password_service
                ),
            )
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    state.audit_logger.log(
        "totp_enrollment_started",
        auth_id=current_user.auth_id,
        username=current_user.username,
        ip_address=request.remote_addr or "unknown",
    )

    return no_store_response(
        data={
            "secret": enrollment["secret"],
            "provisioning_uri": (
                enrollment["provisioning_uri"]
            ),
        },
        message="TOTP enrollment started.",
    )


@auth_bp.post("/mfa/totp/verify-enrollment")
@login_required
@csrf_protected
@throttle(
    action="mfa-enrollment-verify",
    identities=("ip",),
    limit_config="mfa_enrollment_verify_limit",
    window_config="mfa_enrollment_verify_window",
)
def verify_totp_enrollment():
    state = current_app.extensions["marks_auth"]

    if not state.config.mfa_enabled:
        return error_response(
            code="MFA_DISABLED",
            message="MFA is not enabled for this application.",
            status_code=404,
        )

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    code, field_error = get_required_string(
        data,
        "code",
    )

    if field_error is not None:
        return field_error

    try:
        state.totp_service.verify_enrollment(
            current_user,
            code,
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    user = current_user._get_current_object()

    refresh_security_session(
        state,
        user,
    )

    state.audit_logger.log(
        "totp_enabled",
        auth_id=current_user.auth_id,
        username=current_user.username,
        ip_address=request.remote_addr or "unknown",
    )

    response = success_response(
        message="TOTP enabled successfully."
    )

    return clear_persistent_session_cookie(
        response
    )


@auth_bp.post("/mfa/totp/disable")
@login_required
@csrf_protected
@throttle(
    action="mfa-disable",
    identities=("ip",),
    limit_config="mfa_disable_limit",
    window_config="mfa_disable_window",
)
def disable_totp():
    state = current_app.extensions["marks_auth"]

    if not state.config.mfa_enabled:
        return error_response(
            code="MFA_DISABLED",
            message="MFA is not enabled for this application.",
            status_code=404,
        )

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    current_password, field_error = (
        get_required_string(
            data,
            "current_password",
        )
    )

    if field_error is not None:
        return field_error

    try:
        state.totp_service.disable_totp(
            user=current_user,
            current_password=current_password,
            password_service=state.password_service,
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    user = current_user._get_current_object()

    refresh_security_session(
        state,
        user,
    )

    state.audit_logger.log(
        "totp_disabled",
        auth_id=user.auth_id,
        username=user.username,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
    )

    response = success_response(
        message="TOTP disabled successfully."
    )

    return clear_persistent_session_cookie(
        response
    )


@auth_bp.post("/mfa/recovery-codes/generate")
@login_required
@csrf_protected
@throttle(
    action="recovery-code-generation",
    identities=("ip",),
    limit_config="recovery_code_generation_limit",
    window_config="recovery_code_generation_window",
)
def generate_recovery_codes():
    state = current_app.extensions[
        "marks_auth"
    ]

    if not state.config.mfa_enabled:
        return error_response(
            code="MFA_DISABLED",
            message=(
                "MFA is not enabled for "
                "this application."
            ),
            status_code=404,
        )

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    current_password, field_error = (
        get_required_string(
            data,
            "current_password",
        )
    )

    if field_error is not None:
        return field_error

    try:
        codes = (
            state.recovery_code_manager
            .generate_codes(
                user=current_user,
                current_password=(
                    current_password
                ),
            )
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    state.audit_logger.log(
        "recovery_codes_generated",
        auth_id=current_user.auth_id,
        username=current_user.username,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
    )

    return no_store_response(
        data={
            "codes": codes,
        },
        message=(
            "Recovery codes generated "
            "successfully."
        ),
    )


@auth_bp.get(
    "/mfa/recovery-codes/status"
)
@login_required
def recovery_code_status():
    state = current_app.extensions[
        "marks_auth"
    ]

    if not state.config.mfa_enabled:
        return error_response(
            code="MFA_DISABLED",
            message=(
                "MFA is not enabled for "
                "this application."
            ),
            status_code=404,
        )

    remaining = (
        state.recovery_code_manager
        .count_unused_codes(
            current_user
        )
    )

    return success_response(
        data={
            "remaining": remaining,
        }
    )


@auth_bp.get("/sessions")
@login_required
def list_sessions():
    state = current_app.extensions[
        "marks_auth"
    ]

    current_session_id = (
        get_current_session_id()
    )

    records = (
        state.session_store
        .list_for_user(
            current_user.id,
            include_revoked=False,
        )
    )

    sessions = []

    for record in records:
        sessions.append(
            {
                "id": (
                    encode_session_public_id(
                        record.id
                    )
                ),

                "current": (
                    record.id
                    == current_session_id
                ),

                "created_at": (
                    record.created_at
                    .isoformat()
                    if record.created_at
                    is not None
                    else None
                ),

                "last_seen_at": (
                    record.last_seen_at
                    .isoformat()
                    if record.last_seen_at
                    is not None
                    else None
                ),

                "ip_address": (
                    record.ip_address
                ),

                "user_agent": (
                    record.user_agent
                ),

                "authentication_method": (
                    record
                    .authentication_method
                ),

                "remembered": (
                    record.remembered
                ),
            }
        )

    return no_store_response(
        data={
            "sessions": sessions,
        }
    )


@auth_bp.delete(
    "/sessions/<session_public_id>"
)
@login_required
@csrf_protected
def revoke_session(
    session_public_id,
):
    state = current_app.extensions[
        "marks_auth"
    ]

    target = (
        find_session_by_public_id(
            state,
            current_user.id,
            session_public_id,
        )
    )

    if target is None:
        return error_response(
            code="SESSION_NOT_FOUND",
            message=(
                "Session was not found."
            ),
            status_code=404,
        )

    current_session_id = (
        get_current_session_id()
    )

    is_current = (
        target.id
        == current_session_id
    )

    if is_current:
        state.audit_logger.log(
            "session_revoked",
            auth_id=(
                current_user.auth_id
            ),
            username=(
                current_user.username
            ),
            session_id=(
                session_public_id
            ),
            current=True,
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        revoke_current_session(
            state
        )

        response = (
            success_response(
                message=(
                    "Session revoked "
                    "successfully."
                )
            )
        )

        return (
            clear_persistent_session_cookie(
                response
            )
        )

    revoked = (
        state.session_service
        .revoke_session(
            session_id=target.id,
            user=current_user,
        )
    )

    if not revoked:
        return error_response(
            code="SESSION_NOT_FOUND",
            message=(
                "Session was not found."
            ),
            status_code=404,
        )

    state.audit_logger.log(
        "session_revoked",
        auth_id=current_user.auth_id,
        username=(
            current_user.username
        ),
        session_id=(
            session_public_id
        ),
        current=False,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
    )

    return success_response(
        message=(
            "Session revoked successfully."
        )
    )


@auth_bp.post(
    "/sessions/revoke-others"
)
@login_required
@csrf_protected
def revoke_other_sessions():
    state = current_app.extensions[
        "marks_auth"
    ]

    current_session_id = (
        get_current_session_id()
    )

    if not current_session_id:
        return error_response(
            code="SESSION_UNAVAILABLE",
            message=(
                "Current session could "
                "not be identified."
            ),
            status_code=401,
        )

    count = (
        state.session_service
        .revoke_other_sessions(
            current_session_id=(
                current_session_id
            ),
            user=current_user,
        )
    )

    state.audit_logger.log(
        "other_sessions_revoked",
        auth_id=current_user.auth_id,
        username=current_user.username,
        revoked_count=count,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
    )

    return success_response(
        data={
            "revoked_count": count,
        },
        message=(
            "Other sessions revoked "
            "successfully."
        ),
    )


@auth_bp.get("/config")
def auth_config():
    state = current_app.extensions[
        "marks_auth"
    ]

    return success_response(
        data={
            "captcha_site_key": (
                state.config.captcha_site_key
            ),
            "passkeys_available": (
                state.config.webauthn_enabled
                and state.passkey_service
                is not None
            ),
        }
    )

@auth_bp.post("/mfa/challenge/totp")
@csrf_protected
@throttle(
    action="mfa-challenge",
    identities=(
        "ip",
        "challenge",
    ),
    limit_config="mfa_challenge_attempt_limit",
    window_config="mfa_challenge_attempt_window",
)
def complete_totp_challenge():
    state = current_app.extensions[
        "marks_auth"
    ]

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    challenge_id, field_error = (
        get_required_string(
            data,
            "challenge_id",
        )
    )

    if field_error is not None:
        return field_error

    code, field_error = get_required_string(
        data,
        "code",
    )

    if field_error is not None:
        return field_error

    try:
        challenge = (
            state.mfa_challenge_service.get(
                challenge_id
            )
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    user = state.user_store.find_by_auth_id(
        challenge["auth_id"]
    )

    if user is None:
        state.mfa_challenge_service.clear()

        return error_response(
            code="INVALID_MFA_CHALLENGE",
            message=(
                "MFA challenge is invalid "
                "or expired."
            ),
            status_code=401,
        )

    if not state.totp_service.verify_code(
        user,
        code,
    ):
        state.audit_logger.log(
            "mfa_totp_failure",
            auth_id=user.auth_id,
            username=user.username,
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        return error_response(
            code="INVALID_TOTP_CODE",
            message=(
                "Invalid authentication code."
            ),
            status_code=401,
        )

    try:
        consumed_challenge = (
            state.mfa_challenge_service.consume(
                challenge_id
            )
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    remember = consumed_challenge["remember"]

    session_record = (
        establish_authenticated_session(
            state=state,
            user=user,
            authentication_method=(
                "password+totp"
            ),
            remembered=remember,
        )
    )

    state.audit_logger.log(
        "login_success",
        auth_id=user.auth_id,
        username=user.username,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
        remember=remember,
        mfa_method="totp",
        session_id=session_record.id,
    )

    response = success_response(
        data={
            "auth_id": user.auth_id,
            "username": user.username,
            "email": user.email,
        },
        message="Login successful.",
    )

    return set_persistent_session_cookie(
        response,
        state=state,
        session_record=session_record,
    )

@auth_bp.post(
    "/mfa/challenge/recovery-code"
)
@csrf_protected
@throttle(
    action="mfa-challenge",
    identities=(
        "ip",
        "challenge",
    ),
    limit_config="mfa_challenge_attempt_limit",
    window_config="mfa_challenge_attempt_window",
)
def complete_recovery_code_challenge():
    state = current_app.extensions[
        "marks_auth"
    ]

    data, request_error = (
        get_json_object()
    )

    if request_error is not None:
        return request_error

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    challenge_id, field_error = (
        get_required_string(
            data,
            "challenge_id",
        )
    )

    if field_error is not None:
        return field_error

    recovery_code, field_error = (
        get_required_string(
            data,
            "recovery_code",
        )
    )

    if field_error is not None:
        return field_error

    try:
        challenge = (
            state.mfa_challenge_service.get(
                challenge_id
            )
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    user = state.user_store.find_by_auth_id(
        challenge["auth_id"]
    )

    if user is None:
        state.mfa_challenge_service.clear()

        return error_response(
            code="INVALID_MFA_CHALLENGE",
            message=(
                "MFA challenge is invalid "
                "or expired."
            ),
            status_code=401,
        )

    if not (
        state.recovery_code_manager
        .verify_and_consume(
            user,
            recovery_code,
        )
    ):
        state.audit_logger.log(
            "mfa_recovery_failure",
            auth_id=user.auth_id,
            username=user.username,
            ip_address=(
                request.remote_addr
                or "unknown"
            ),
        )

        return error_response(
            code="INVALID_RECOVERY_CODE",
            message=(
                "Invalid recovery code."
            ),
            status_code=401,
        )

    try:
        consumed_challenge = (
            state.mfa_challenge_service.consume(
                challenge_id
            )
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code,
        )

    remember = consumed_challenge["remember"]

    session_record = (
        establish_authenticated_session(
            state=state,
            user=user,
            authentication_method=(
                "password+recovery_code"
            ),
            remembered=remember,
        )
    )

    state.audit_logger.log(
        "login_success",
        auth_id=user.auth_id,
        username=user.username,
        ip_address=(
            request.remote_addr
            or "unknown"
        ),
        remember=remember,
        mfa_method="recovery_code",
        session_id=session_record.id,
    )

    response = success_response(
        data={
            "auth_id": user.auth_id,
            "username": user.username,
            "email": user.email,
        },
        message="Login successful.",
    )

    return set_persistent_session_cookie(
        response,
        state=state,
        session_record=session_record,
    )
