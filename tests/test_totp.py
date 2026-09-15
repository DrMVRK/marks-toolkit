import pyotp


def get_csrf(client):
    response = client.get("/auth/csrf")

    return response.get_json()["data"]["csrf_token"]


def register_user(
    client,
    email="mark@example.com",
    username="Mark",
    password="TestingPassword123!",
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
):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": identity,
            "password": password,
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200


def test_mfa_status_requires_authentication(client):
    response = client.get(
        "/auth/mfa/status"
    )

    data = response.get_json()

    assert response.status_code == 401
    assert data["ok"] is False
    assert data["error"]["code"] == "AUTH_REQUIRED"


def test_mfa_status_initially_disabled_for_user(client):
    register_user(client)
    login_user(client)

    response = client.get(
        "/auth/mfa/status"
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True

    assert (
        data["data"]["mfa_enabled"]
        is False
    )

    assert (
        data["data"]["totp_enabled"]
        is False
    )

    assert (
        data["data"]["passkey_count"]
        == 0
    )


def test_totp_enrollment_requires_authentication(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/totp/enroll",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 401
    assert data["error"]["code"] == "AUTH_REQUIRED"


def test_totp_enrollment_requires_csrf(client):
    register_user(client)
    login_user(client)

    response = client.post(
        "/auth/mfa/totp/enroll"
    )

    assert response.status_code == 403


def test_totp_enrollment_returns_setup_data(
    client,
    app,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/totp/enroll",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True

    assert data["data"]["secret"]
    assert data["data"]["provisioning_uri"]

    assert (
        data["data"]["provisioning_uri"]
        .startswith("otpauth://totp/")
    )

    user = app.test_user_store.users[0]

    stored = app.test_mfa_store.get_totp(
        user.id
    )

    assert stored is not None
    assert stored.enabled is False

    assert (
        data["data"]["secret"].encode()
        not in stored.encrypted_secret
    )


def test_invalid_totp_enrollment_code_rejected(
    client,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    enroll = client.post(
        "/auth/mfa/totp/enroll",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert enroll.status_code == 200

    response = client.post(
        "/auth/mfa/totp/verify-enrollment",
        json={
            "code": "000000"
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 400
    assert (
        data["error"]["code"]
        == "INVALID_TOTP_CODE"
    )


def test_valid_totp_code_enables_totp(
    client,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    enroll = client.post(
        "/auth/mfa/totp/enroll",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    enrollment_data = (
        enroll.get_json()["data"]
    )

    secret = enrollment_data["secret"]

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

    data = verify.get_json()

    assert verify.status_code == 200
    assert data["ok"] is True

    status = client.get(
        "/auth/mfa/status"
    )

    status_data = (
        status.get_json()["data"]
    )

    assert (
        status_data["mfa_enabled"]
        is True
    )

    assert (
        status_data["totp_enabled"]
        is True
    )


def test_cannot_begin_second_totp_enrollment_when_enabled(
    client,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    first = client.post(
        "/auth/mfa/totp/enroll",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    secret = first.get_json()["data"]["secret"]

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

    second = client.post(
        "/auth/mfa/totp/enroll",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = second.get_json()

    assert second.status_code == 409
    assert (
        data["error"]["code"]
        == "TOTP_ALREADY_ENABLED"
    )