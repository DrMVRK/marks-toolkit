from flask import Blueprint, current_app, request
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)

from .responses import success_response, error_response
from .exceptions import AuthError
from .decorators import (
    csrf_protected,
    throttle,
)


auth_bp = Blueprint("marks_auth", __name__)


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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    identity = data.get("identity")
    password = data.get("password")

    ip_address = request.remote_addr or "unknown"

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

    remember = bool(
        data.get("remember", False)
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

    login_user(
        user,
        remember=remember,
    )

    state.audit_logger.log(
        "login_success",
        auth_id=user.auth_id,
        username=user.username,
        ip_address=ip_address,
        remember=remember,
    )

    return success_response(
        data={
            "auth_id": user.auth_id,
            "username": user.username,
            "email": user.email,
        },
        message="Login successful.",
    )


@auth_bp.post("/logout")
@login_required
@csrf_protected
def logout():
    logout_user()

    return success_response(
        message="Logout successful."
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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    email = data.get("email")

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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    token = data.get("token")
    new_password = data.get("password")

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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    current_password = data.get("current_password")
    new_password = data.get("new_password")

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

    logout_user()

    return success_response(
        message=(
            "Password changed successfully. "
            "Please log in again."
        )
    )


@auth_bp.get("/mfa/status")
@login_required
def mfa_status():
    state = current_app.extensions["marks_auth"]

    if not state.config.mfa_enabled:
        return success_response(
            data={
                "mfa_enabled": False,
                "totp_enabled": False,
                "passkey_count": 0,
            }
        )

    totp = state.mfa_store.get_totp(
        current_user.id
    )

    passkeys = state.mfa_store.list_passkeys(
        current_user.id
    )

    return success_response(
        data={
            "mfa_enabled": (
                state.mfa_store.has_enabled_mfa(
                    current_user.id
                )
            ),
            "totp_enabled": (
                totp is not None
                and totp.enabled
            ),
            "passkey_count": len(passkeys),
        }
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

    try:
        enrollment = (
            state.totp_service.begin_enrollment(
                current_user
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

    return success_response(
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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    code = data.get("code")

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

    state.audit_logger.log(
        "totp_enabled",
        auth_id=current_user.auth_id,
        username=current_user.username,
        ip_address=request.remote_addr or "unknown",
    )

    return success_response(
        message="TOTP enabled successfully."
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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400,
        )

    current_password = data.get(
        "current_password"
    )

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

    state.audit_logger.log(
        "totp_disabled",
        auth_id=current_user.auth_id,
        username=current_user.username,
        ip_address=request.remote_addr or "unknown",
    )

    return success_response(
        message="TOTP disabled successfully."
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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    current_password = data.get(
        "current_password"
    )

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

    return success_response(
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


@auth_bp.get("/config")
def auth_config():
    state = current_app.extensions["marks_auth"]

    return success_response(
        data={
            "captcha_site_key": (
                state.config.captcha_site_key
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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    challenge_id = data.get(
        "challenge_id"
    )

    code = data.get("code")

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

    login_user(
        user,
        remember=remember,
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
    )

    return success_response(
        data={
            "auth_id": user.auth_id,
            "username": user.username,
            "email": user.email,
        },
        message="Login successful.",
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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message=(
                "Request body must contain "
                "a JSON object."
            ),
            status_code=400,
        )

    challenge_id = data.get(
        "challenge_id"
    )

    recovery_code = data.get(
        "recovery_code"
    )

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

    login_user(
        user,
        remember=remember,
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
    )

    return success_response(
        data={
            "auth_id": user.auth_id,
            "username": user.username,
            "email": user.email,
        },
        message="Login successful.",
    )