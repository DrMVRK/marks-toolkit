import pyotp


def get_csrf(client):
    response = client.get("/auth/csrf")
    return response.get_json()["data"]["csrf_token"]


def register_user(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/register",
        json={
            "email": "mark@example.com",
            "username": "Mark",
            "password": "TestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 201


def login_user(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "TestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200


def enable_totp(client):
    csrf_token = get_csrf(client)

    enroll = client.post(
        "/auth/mfa/totp/enroll",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    secret = enroll.get_json()["data"]["secret"]

    code = pyotp.TOTP(secret).now()

    verify = client.post(
        "/auth/mfa/totp/verify-enrollment",
        json={
            "code": code
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert verify.status_code == 200


def test_totp_disable_requires_authentication(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/totp/disable",
        json={
            "current_password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 401


def test_totp_disable_requires_csrf(client):
    register_user(client)
    login_user(client)
    enable_totp(client)

    response = client.post(
        "/auth/mfa/totp/disable",
        json={
            "current_password": "TestingPassword123!"
        },
    )

    assert response.status_code == 403


def test_totp_disable_requires_correct_password(client):
    register_user(client)
    login_user(client)
    enable_totp(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/totp/disable",
        json={
            "current_password": "WrongPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 400
    assert (
        data["error"]["code"]
        == "INVALID_MFA_PASSWORD"
    )


def test_totp_can_be_disabled(client):
    register_user(client)
    login_user(client)
    enable_totp(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/totp/disable",
        json={
            "current_password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    status = client.get(
        "/auth/mfa/status"
    ).get_json()["data"]

    assert status["totp_enabled"] is False
    assert status["mfa_enabled"] is False