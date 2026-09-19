import pyotp

def get_csrf(client):
    response = client.get("/auth/csrf")
    return response.get_json()["data"]["csrf_token"]


def register_user(
    client,
    email="mark@example.com",
    username="Mark",
    password="TestingPassword123!"
):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "username": username,
            "password": password,
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 201


def login_user(
    client,
    identity="mark@example.com",
    password="TestingPassword123!",
    remember=False,
):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": identity,
            "password": password,
            "remember": remember,
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    return response

def enable_totp(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/totp/enroll",
        json={
            "current_password":
                "TestingPassword123!",
        },
        headers={
            "X-CSRF-Token":
                csrf_token,
        },
    )

    assert response.status_code == 200

    secret = (
        response.get_json()
        ["data"]
        ["secret"]
    )

    code = pyotp.TOTP(
        secret
    ).now()

    response = client.post(
        "/auth/mfa/totp/verify-enrollment",
        json={
            "code": code,
        },
        headers={
            "X-CSRF-Token":
                csrf_token,
        },
    )

    assert response.status_code == 200

    return secret


def generate_recovery_codes(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password":
                "TestingPassword123!",
        },
        headers={
            "X-CSRF-Token":
                csrf_token,
        },
    )

    assert response.status_code == 200

    return (
        response.get_json()
        ["data"]
        ["codes"]
    )


def logout_user(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token":
                csrf_token,
        },
    )

    assert response.status_code == 200

def test_me_reports_unauthenticated(client):
    response = client.get("/auth/me")

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True
    assert data["data"]["authenticated"] is False
    assert data["data"]["user"] is None


def test_me_reports_authenticated_user(client):
    register_user(client)
    login_user(client)

    response = client.get("/auth/me")

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True
    assert data["data"]["authenticated"] is True

    user = data["data"]["user"]

    assert user["username"] == "Mark"
    assert user["email"] == "mark@example.com"
    assert user["auth_id"]


def test_logout_clears_session(client):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    me_response = client.get("/auth/me")
    data = me_response.get_json()

    assert data["data"]["authenticated"] is False
    assert data["data"]["user"] is None


def test_logout_requires_authentication(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 401
    assert data["ok"] is False
    assert data["error"]["code"] == "AUTH_REQUIRED"


def test_logout_requires_csrf(client):
    register_user(client)
    login_user(client)

    response = client.post(
        "/auth/logout"
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["ok"] is False


def test_auth_id_rotation_invalidates_existing_session(client, app):
    register_user(client)
    login_user(client)

    user = app.test_user_store.users[0]

    app.test_user_store.rotate_auth_id(user)

    response = client.get("/auth/me")

    data = response.get_json()

    assert response.status_code == 200
    assert data["data"]["authenticated"] is False

def test_enabling_mfa_invalidates_existing_remember_cookie(
    client,
    app,
):
    register_user(client)

    login_user(
        client,
        remember=True,
    )

    remember_cookie = client.get_cookie(
        "marks_auth_device_session"
    )

    assert remember_cookie is not None

    old_cookie_value = (
        remember_cookie.value
    )

    enable_totp(client)

    restored_client = (
        app.test_client()
    )

    restored_client.set_cookie(
        "remember_token",
        old_cookie_value,
    )

    response = restored_client.get(
        "/auth/me"
    )

    data = response.get_json()

    assert response.status_code == 200
    assert (
        data["data"]
        ["authenticated"]
        is False
    )

    assert (
        data["data"]["user"]
        is None
    )

def test_remember_cookie_after_mfa_can_restore_session(
    client,
    app,
):
    register_user(client)

    login_user(client)

    enable_totp(client)

    recovery_codes = (
        generate_recovery_codes(
            client
        )
    )

    logout_user(client)

    csrf_token = get_csrf(client)

    login_response = client.post(
        "/auth/login",
        json={
            "identity":
                "mark@example.com",
            "password":
                "TestingPassword123!",
            "remember":
                True,
        },
        headers={
            "X-CSRF-Token":
                csrf_token,
        },
    )

    assert (
        login_response.status_code
        == 202
    )

    challenge_id = (
        login_response.get_json()
        ["data"]
        ["challenge_id"]
    )

    csrf_token = get_csrf(client)

    mfa_response = client.post(
        "/auth/mfa/challenge/recovery-code",
        json={
            "challenge_id":
                challenge_id,
            "recovery_code":
                recovery_codes[0],
        },
        headers={
            "X-CSRF-Token":
                csrf_token,
        },
    )

    assert (
        mfa_response.status_code
        == 200
    )

    remember_cookie = client.get_cookie(
        "marks_auth_device_session"
    )
    assert remember_cookie is not None

    remembered_value = (
        remember_cookie.value
    )

    restored_client = (
        app.test_client()
    )

    restored_client.set_cookie(
        "marks_auth_device_session",
        remembered_value,
    )

    response = restored_client.get(
        "/auth/me"
    )

    data = response.get_json()

    assert response.status_code == 200

    assert (
        data["data"]
        ["authenticated"]
        is True
    )

    assert (
        data["data"]
        ["user"]
        ["email"]
        == "mark@example.com"
    )