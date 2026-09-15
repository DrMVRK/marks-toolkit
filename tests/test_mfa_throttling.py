import pyotp


PASSWORD = "TestingPassword123!"


def get_csrf(client):
    response = client.get("/auth/csrf")

    return response.get_json()[
        "data"
    ]["csrf_token"]


def register_user(client):
    csrf = get_csrf(client)

    response = client.post(
        "/auth/register",
        json={
            "email": "mark@example.com",
            "username": "Mark",
            "password": PASSWORD,
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 201


def login(client):
    csrf = get_csrf(client)

    return client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": PASSWORD,
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )


def enable_totp(client):
    csrf = get_csrf(client)

    enrollment = client.post(
        "/auth/mfa/totp/enroll",
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert enrollment.status_code == 200

    secret = (
        enrollment.get_json()
        ["data"]["secret"]
    )

    code = pyotp.TOTP(secret).now()

    verify = client.post(
        "/auth/mfa/totp/verify-enrollment",
        json={
            "code": code
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert verify.status_code == 200

    return secret


def logout(client):
    csrf = get_csrf(client)

    response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200


def prepare_mfa_login(client):
    register_user(client)

    first_login = login(client)

    assert first_login.status_code == 200

    enable_totp(client)

    logout(client)

    login_response = login(client)

    assert login_response.status_code == 202

    return (
        login_response
        .get_json()["data"]["challenge_id"]
    )


def test_totp_challenge_is_rate_limited(client):
    challenge_id = prepare_mfa_login(
        client
    )

    csrf = get_csrf(client)

    # Default MFA attempt limit is 5.
    for _ in range(5):
        response = client.post(
            "/auth/mfa/challenge/totp",
            json={
                "challenge_id": challenge_id,
                "code": "000000",
            },
            headers={
                "X-CSRF-Token": csrf
            },
        )

        assert response.status_code == 401

    blocked = client.post(
        "/auth/mfa/challenge/totp",
        json={
            "challenge_id": challenge_id,
            "code": "000000",
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = blocked.get_json()

    assert blocked.status_code == 429
    assert data["ok"] is False

    assert (
        data["error"]["code"]
        == "RATE_LIMITED"
    )


def test_mfa_rate_limit_does_not_create_session(
    client,
):
    challenge_id = prepare_mfa_login(
        client
    )

    csrf = get_csrf(client)

    for _ in range(6):
        client.post(
            "/auth/mfa/challenge/totp",
            json={
                "challenge_id": challenge_id,
                "code": "000000",
            },
            headers={
                "X-CSRF-Token": csrf
            },
        )

    me = client.get(
        "/auth/me"
    ).get_json()

    assert (
        me["data"]["authenticated"]
        is False
    )