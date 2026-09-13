from flask import Blueprint, current_app, request

auth_bp = Blueprint('marks_auth', __name__)


@auth_bp.get("/test")
def test_route():
    return {"ok": True, "message":"MARKS AuthKit is working"}


@auth_bp.post("/register")
def register():
    state = current_app.extensions["marks_auth"]

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return {
            "ok": False,
            "error": "Request body must contain a JSON object."
        }, 400

    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    try:
        email = state.identity_service.normalize_email(email)
        username = state.identity_service.normalize_username(username)
    except ValueError as error:
        return {
            "ok": False,
            "error": str(error)
        }, 400
    
    if state.user_store.identity_exists(email, username):
        return {
            "ok": False,
            "error": "Email or username already exists."
        }, 409

    try:
        password_hash = state.password_service.hash_password(password)
    except ValueError as error:
        return {
            "ok": False,
            "error": str(error)
        }, 400

    user = state.user_store.create_user(
        email,
        username,
        password_hash
    )

    return {
        "ok": True,
        "message": "User registered successfully.",
    }