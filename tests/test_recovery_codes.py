def get_csrf(client):
    response = client.get("/auth/csrf")

    return response.get_json()[
        "data"
    ]["csrf_token"]


def register_user(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/register",
        json={
            "email": "mark@example.com",
            "username": "Mark",
            "password": (
                "TestingPassword123!"
            ),
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
            "identity": (
                "mark@example.com"
            ),
            "password": (
                "TestingPassword123!"
            ),
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200


def test_recovery_code_generation_requires_auth(
    client,
):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password": (
                "TestingPassword123!"
            )
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 401


def test_recovery_code_generation_requires_csrf(
    client,
):
    register_user(client)
    login_user(client)

    response = client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password": (
                "TestingPassword123!"
            )
        },
    )

    assert response.status_code == 403


def test_recovery_code_generation_requires_password(
    client,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password": (
                "WrongPassword123!"
            )
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


def test_recovery_codes_generated_and_hashed(
    client,
    app,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password": (
                "TestingPassword123!"
            )
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 200

    codes = data["data"]["codes"]

    assert len(codes) == 10

    user = app.test_user_store.users[0]

    stored_codes = (
        app.test_mfa_store
        .list_unused_recovery_codes(
            user.id
        )
    )

    assert len(stored_codes) == 10

    for stored in stored_codes:
        assert (
            stored.code_hash
            not in codes
        )


def test_recovery_code_status(
    client,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password": (
                "TestingPassword123!"
            )
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    response = client.get(
        "/auth/mfa/recovery-codes/status"
    )

    data = response.get_json()

    assert response.status_code == 200

    assert (
        data["data"]["remaining"]
        == 10
    )


def test_recovery_code_can_be_consumed_once(
    client,
    app,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password": (
                "TestingPassword123!"
            )
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    code = (
        response.get_json()
        ["data"]["codes"][0]
    )

    user = app.test_user_store.users[0]

    state = app.extensions["marks_auth"]

    first = (
        state.recovery_code_manager
        .verify_and_consume(
            user,
            code,
        )
    )

    second = (
        state.recovery_code_manager
        .verify_and_consume(
            user,
            code,
        )
    )

    assert first is True
    assert second is False

    remaining = (
        state.recovery_code_manager
        .count_unused_codes(user)
    )

    assert remaining == 9


def test_regenerating_codes_invalidates_old_codes(
    client,
    app,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    first_response = client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password": (
                "TestingPassword123!"
            )
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    old_code = (
        first_response.get_json()
        ["data"]["codes"][0]
    )

    second_response = client.post(
        "/auth/mfa/recovery-codes/generate",
        json={
            "current_password": (
                "TestingPassword123!"
            )
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert second_response.status_code == 200

    user = app.test_user_store.users[0]

    state = app.extensions["marks_auth"]

    assert (
        state.recovery_code_manager
        .verify_and_consume(
            user,
            old_code,
        )
        is False
    )