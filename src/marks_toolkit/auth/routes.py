from flask import Blueprint, current_app, request
from flask_login import current_user, login_required, login_user, logout_user

from .responses import success_response, error_response
from .exceptions import AuthError
from .decorators import csrf_protected


auth_bp = Blueprint('marks_auth', __name__)


@auth_bp.get("/test")
def test_route():
    return {"ok": True, "message":"MARKS AuthKit is working"}


@auth_bp.get("/me")
def me():
    if not current_user.is_authenticated:
        return success_response(
            data={
                "authenticated": False,
                "user": None
            }
        )

    return success_response(
        data={
            "authenticated": True,
            "user": {
                "auth_id": current_user.auth_id,
                "username": current_user.username,
                "email": current_user.email
            }
        }
    )


@auth_bp.post("/register")
@csrf_protected
def register():
    state = current_app.extensions["marks_auth"]

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400
        )

    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    try:
        state.registration_service.register(
            email=email,
            username=username,
            password=password
        )
    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code
        )

    return success_response(
        message="User registered successfully.",
        status_code=201
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
            status_code=400
        )

    identity = data.get("identity")
    password = data.get("password")

    try:
        user = state.login_service.authenticate(
            identity=identity,
            password=password
        )
    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code
        )

    remember = bool(data.get("remember", False))

    login_user(
        user,
        remember=remember
    )

    return success_response(
        data={
            "auth_id": user.auth_id,
            "username": user.username,
            "email": user.email
        },
        message="Login successful."
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
            "csrf_token": token
        }
    )


@auth_bp.post("/forgot-password")
@csrf_protected
def forgot_password():
    state = current_app.extensions["marks_auth"]

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400
        )

    email = data.get("email")

    state.password_reset_service.request_reset(
        email=email,
        reset_url=state.config.reset_url
    )

    return success_response(
        message=(
            "If an account exists for that email address, "
            "a password reset link has been sent."
        )
    )


@auth_bp.post("/reset-password")
@csrf_protected
def reset_password():
    state = current_app.extensions["marks_auth"]

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            code="INVALID_REQUEST",
            message="Request body must contain a JSON object.",
            status_code=400
        )

    token = data.get("token")
    new_password = data.get("password")

    try:
        state.password_reset_service.reset_password(
            token,
            new_password
        )

    except AuthError as error:
        return error_response(
            code=error.code,
            message=error.message,
            status_code=error.status_code
        )

    return success_response(
        message="Password reset successfully."
    )