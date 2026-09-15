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


def login_normal(client):
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
        json={
            "current_password": PASSWORD,
        },
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


def generate_recovery_codes(client):
    csrf = get_csrf(client)

    response = client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password": PASSWORD
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200

    return response.get_json()[
        "data"
    ]["codes"]


def logout(client):
    csrf = get_csrf(client)

    response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200


def prepare_totp_account(client):
    register_user(client)

    first_login = login_normal(client)
    assert first_login.status_code == 200

    secret = enable_totp(client)

    logout(client)

    return secret


def test_mfa_user_not_logged_in_after_password(
    client,
):
    prepare_totp_account(client)

    response = login_normal(client)

    data = response.get_json()

    assert response.status_code == 202
    assert data["ok"] is True
    assert (
        data["data"]["mfa_required"]
        is True
    )

    assert data["data"]["challenge_id"]

    assert "totp" in (
        data["data"]["methods"]
    )

    me = client.get("/auth/me").get_json()

    assert (
        me["data"]["authenticated"]
        is False
    )


def test_valid_totp_completes_login(
    client,
):
    secret = prepare_totp_account(
        client
    )

    login_response = login_normal(client)

    challenge_id = (
        login_response.get_json()
        ["data"]["challenge_id"]
    )

    code = pyotp.TOTP(secret).now()

    csrf = get_csrf(client)

    response = client.post(
        "/auth/mfa/challenge/totp",
        json={
            "challenge_id": challenge_id,
            "code": code,
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200

    me = client.get("/auth/me").get_json()

    assert (
        me["data"]["authenticated"]
        is True
    )


def test_invalid_totp_does_not_login(
    client,
):
    prepare_totp_account(client)

    login_response = login_normal(client)

    challenge_id = (
        login_response.get_json()
        ["data"]["challenge_id"]
    )

    csrf = get_csrf(client)

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

    data = response.get_json()

    assert (
        data["error"]["code"]
        == "INVALID_TOTP_CODE"
    )

    me = client.get("/auth/me").get_json()

    assert (
        me["data"]["authenticated"]
        is False
    )


def test_recovery_code_completes_login(
    client,
):
    register_user(client)

    assert (
        login_normal(client).status_code
        == 200
    )

    enable_totp(client)

    codes = generate_recovery_codes(
        client
    )

    logout(client)

    login_response = login_normal(client)

    data = login_response.get_json()

    assert "recovery_code" in (
        data["data"]["methods"]
    )

    challenge_id = (
        data["data"]["challenge_id"]
    )

    csrf = get_csrf(client)

    response = client.post(
        "/auth/mfa/challenge/recovery-code",
        json={
            "challenge_id": challenge_id,
            "recovery_code": codes[0],
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200

    me = client.get("/auth/me").get_json()

    assert (
        me["data"]["authenticated"]
        is True
    )


def test_invalid_challenge_id_rejected(
    client,
):
    secret = prepare_totp_account(
        client
    )

    login_normal(client)

    csrf = get_csrf(client)

    response = client.post(
        "/auth/mfa/challenge/totp",
        json={
            "challenge_id": "not-the-real-challenge",
            "code": pyotp.TOTP(
                secret
            ).now(),
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 401

    assert (
        data["error"]["code"]
        == "INVALID_MFA_CHALLENGE"
    )


def test_completed_challenge_cannot_be_reused(
    client,
):
    secret = prepare_totp_account(
        client
    )

    login_response = login_normal(client)

    challenge_id = (
        login_response.get_json()
        ["data"]["challenge_id"]
    )

    csrf = get_csrf(client)

    first = client.post(
        "/auth/mfa/challenge/totp",
        json={
            "challenge_id": challenge_id,
            "code": pyotp.TOTP(
                secret
            ).now(),
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert first.status_code == 200

    second = client.post(
        "/auth/mfa/challenge/totp",
        json={
            "challenge_id": challenge_id,
            "code": pyotp.TOTP(
                secret
            ).now(),
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert second.status_code == 401

def test_totp_code_cannot_be_reused_across_challenges(
    client,
):
    secret = prepare_totp_account(
        client
    )

    # First password login creates MFA challenge #1.
    first_login = login_normal(
        client
    )

    assert first_login.status_code == 202

    first_challenge_id = (
        first_login.get_json()
        ["data"]["challenge_id"]
    )

    # Generate ONE TOTP code that we will deliberately
    # attempt to use twice.
    code = pyotp.TOTP(
        secret
    ).now()

    csrf = get_csrf(
        client
    )

    first_mfa = client.post(
        "/auth/mfa/challenge/totp",
        json={
            "challenge_id":
                first_challenge_id,
            "code": code,
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert first_mfa.status_code == 200

    # End the authenticated session normally.
    csrf = get_csrf(
        client
    )

    logout_response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert logout_response.status_code == 200

    # Password login again creates an entirely NEW
    # MFA challenge.
    second_login = login_normal(
        client
    )

    assert second_login.status_code == 202

    second_challenge_id = (
        second_login.get_json()
        ["data"]["challenge_id"]
    )

    csrf = get_csrf(
        client
    )

    # Replay the exact same authenticator code.
    replay = client.post(
        "/auth/mfa/challenge/totp",
        json={
            "challenge_id":
                second_challenge_id,
            "code": code,
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert replay.status_code == 401

    body = replay.get_json()

    assert (
        body["error"]["code"]
        == "INVALID_TOTP_CODE"
    )

def test_totp_challenge_rejects_non_string_code(
    client,
):
    csrf = get_csrf(client)

    response = client.post(
        "/auth/mfa/challenge/totp",
        json={
            "challenge_id": "test-challenge",
            "code": [
                "bad"
            ],
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 400
    assert (
        response.get_json()["error"]["code"]
        == "INVALID_REQUEST"
    )

def test_recovery_challenge_rejects_non_string_code(
    client,
):
    csrf = get_csrf(client)

    response = client.post(
        "/auth/mfa/challenge/recovery-code",
        json={
            "challenge_id": "test-challenge",
            "recovery_code": {
                "bad": "type"
            },
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 400
    assert (
        response.get_json()["error"]["code"]
        == "INVALID_REQUEST"
    )