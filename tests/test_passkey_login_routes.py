# ============================================================
# HELPERS
# ============================================================


def get_csrf(
    client,
):
    response = client.get(
        "/auth/csrf"
    )

    assert response.status_code == 200

    return (
        response.get_json()
        ["data"]
        ["csrf_token"]
    )


def create_test_user(
    app,
):
    state = app.extensions[
        "marks_auth"
    ]

    password_hash = (
        state.password_service
        .hash_password(
            "TestingPassword123!"
        )
    )

    return (
        app.test_user_store
        .create_user(
            email="mark@example.com",
            username="Mark",
            password_hash=password_hash,
        )
    )


# ============================================================
# OPTIONS
# ============================================================


def test_passkey_login_options_requires_csrf(
    client,
):
    response = client.post(
        "/auth/passkeys/login/options"
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["ok"] is False


def test_passkey_login_options_returns_challenge(
    client,
):
    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/options",
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True

    assert (
        data["data"]["challenge_id"]
    )

    assert isinstance(
        data["data"]["options"],
        dict,
    )


def test_passkey_login_options_is_not_cached(
    client,
):
    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/options",
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200

    assert (
        response.headers["Cache-Control"]
        == "no-store"
    )


def test_passkey_login_options_rejected_when_disabled(
    client,
    app,
):
    state = app.extensions[
        "marks_auth"
    ]

    state.config.webauthn_enabled = False

    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/options",
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 404

    assert (
        data["error"]["code"]
        == "WEBAUTHN_DISABLED"
    )


# ============================================================
# VERIFY — REQUEST VALIDATION
# ============================================================


def test_passkey_login_verify_requires_csrf(
    client,
):
    response = client.post(
        "/auth/passkeys/login/verify",
        json={
            "challenge_id":
                "test-challenge",

            "credential": {},
        },
    )

    assert response.status_code == 403


def test_passkey_login_verify_requires_challenge_id(
    client,
):
    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/verify",
        json={
            "credential": {},
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 400

    assert (
        data["error"]["code"]
        == "INVALID_REQUEST"
    )


def test_passkey_login_verify_requires_credential_object(
    client,
):
    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/verify",
        json={
            "challenge_id":
                "test-challenge",

            "credential":
                "not-an-object",
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 400

    assert (
        data["error"]["code"]
        == "INVALID_REQUEST"
    )


# ============================================================
# SUCCESSFUL LOGIN
# ============================================================


def test_valid_passkey_login_creates_session(
    client,
    app,
    monkeypatch,
):
    user = create_test_user(
        app
    )

    state = app.extensions[
        "marks_auth"
    ]

    monkeypatch.setattr(
        state.passkey_service,
        "finish_authentication",
        lambda **kwargs: user.id,
    )

    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/verify",
        json={
            "challenge_id":
                "test-challenge",

            "credential": {
                "id": "test-passkey"
            },
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True

    assert (
        data["data"]["username"]
        == "Mark"
    )

    assert (
        data["data"]["email"]
        == "mark@example.com"
    )

    me = client.get(
        "/auth/me"
    )

    me_data = (
        me.get_json()["data"]
    )

    assert (
        me_data["authenticated"]
        is True
    )

    assert (
        me_data["user"]["username"]
        == "Mark"
    )


# ============================================================
# REMEMBER COOKIE
# ============================================================


def test_passkey_login_does_not_create_remember_cookie(
    client,
    app,
    monkeypatch,
):
    user = create_test_user(
        app
    )

    state = app.extensions[
        "marks_auth"
    ]

    monkeypatch.setattr(
        state.passkey_service,
        "finish_authentication",
        lambda **kwargs: user.id,
    )

    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/verify",
        json={
            "challenge_id":
                "test-challenge",

            "credential": {
                "id": "test-passkey"
            },
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200

    cookies = (
        response.headers.getlist(
            "Set-Cookie"
        )
    )

    assert not any(
        cookie.startswith(
            "remember_token="
        )
        for cookie in cookies
    )


# ============================================================
# UNKNOWN / DELETED USER
# ============================================================


def test_passkey_login_rejects_missing_user(
    client,
    app,
    monkeypatch,
):
    state = app.extensions[
        "marks_auth"
    ]

    monkeypatch.setattr(
        state.passkey_service,
        "finish_authentication",
        lambda **kwargs: 999999,
    )

    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/verify",
        json={
            "challenge_id":
                "test-challenge",

            "credential": {
                "id": "test-passkey"
            },
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 401

    assert (
        data["error"]["code"]
        == "INVALID_PASSKEY"
    )


# ============================================================
# INVALID PASSKEY
# ============================================================


def test_invalid_passkey_returns_generic_failure(
    client,
    app,
    monkeypatch,
):
    state = app.extensions[
        "marks_auth"
    ]

    def fail_authentication(
        **kwargs,
    ):
        raise ValueError(
            "credential does not exist"
        )

    monkeypatch.setattr(
        state.passkey_service,
        "finish_authentication",
        fail_authentication,
    )

    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/verify",
        json={
            "challenge_id":
                "test-challenge",

            "credential": {
                "id": "bad-passkey"
            },
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 401

    assert (
        data["error"]["code"]
        == "INVALID_PASSKEY"
    )

    assert (
        data["error"]["message"]
        == "Passkey authentication failed."
    )


# ============================================================
# CHALLENGE REPLAY
# ============================================================


def test_passkey_login_challenge_cannot_be_reused(
    client,
    app,
    monkeypatch,
):
    user = create_test_user(
        app
    )

    state = app.extensions[
        "marks_auth"
    ]

    calls = 0

    def finish_authentication(
        **kwargs,
    ):
        nonlocal calls

        calls += 1

        if calls == 1:
            return user.id

        raise ValueError(
            "WebAuthn challenge is invalid "
            "or expired."
        )

    monkeypatch.setattr(
        state.passkey_service,
        "finish_authentication",
        finish_authentication,
    )

    csrf = get_csrf(
        client
    )

    payload = {
        "challenge_id":
            "single-use-challenge",

        "credential": {
            "id": "test-passkey"
        },
    }

    first = client.post(
        "/auth/passkeys/login/verify",
        json=payload,
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert first.status_code == 200

    second = client.post(
        "/auth/passkeys/login/verify",
        json=payload,
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = second.get_json()

    assert second.status_code == 401

    assert (
        data["error"]["code"]
        == "INVALID_PASSKEY"
    )


# ============================================================
# INACTIVE USER
# ============================================================


def test_passkey_login_rejects_inactive_user(
    client,
    app,
    monkeypatch,
):
    user = create_test_user(
        app
    )

    user.active = False

    state = app.extensions[
        "marks_auth"
    ]

    monkeypatch.setattr(
        state.passkey_service,
        "finish_authentication",
        lambda **kwargs: user.id,
    )

    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/passkeys/login/verify",
        json={
            "challenge_id":
                "test-challenge",

            "credential": {
                "id": "test-passkey"
            },
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 403

    assert (
        data["error"]["code"]
        == "ACCOUNT_UNAVAILABLE"
    )

    me = client.get(
        "/auth/me"
    )

    assert (
        me.get_json()
        ["data"]
        ["authenticated"]
        is False
    )