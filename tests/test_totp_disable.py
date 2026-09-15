import pyotp

PASSWORD = "TestingPassword123!"


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
        json={
            "current_password": PASSWORD,
        },
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

def test_totp_disable_is_rate_limited(
    client,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    for _ in range(5):
        response = client.post(
            "/auth/mfa/totp/disable",
            json={
                "current_password":
                    "WrongPassword123!",
            },
            headers={
                "X-CSRF-Token":
                    csrf_token
            },
        )

        assert response.status_code in (
            400,
            401,
        )

    response = client.post(
        "/auth/mfa/totp/disable",
        json={
            "current_password":
                "WrongPassword123!",
        },
        headers={
            "X-CSRF-Token":
                csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 429

    assert (
        data["error"]["code"]
        == "RATE_LIMITED"
    )


def test_disabling_totp_revokes_recovery_codes(
    client,
    app,
):
    register_user(client)
    login_user(client)

    enable_totp(client)

    state = app.extensions[
        "marks_auth"
    ]

    user = state.user_store.find_by_identity(
        "mark@example.com"
    )

    state.mfa_store.replace_recovery_codes(
        user.id,
        [
            "test-recovery-hash-1",
            "test-recovery-hash-2",
        ],
    )

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/totp/disable",
        json={
            "current_password":
                "TestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    assert (
        state.mfa_store.consume_recovery_code(
            user.id,
            "test-recovery-hash-1",
        )
        is False
    )

    assert (
        state.mfa_store.consume_recovery_code(
            user.id,
            "test-recovery-hash-2",
        )
        is False
    )