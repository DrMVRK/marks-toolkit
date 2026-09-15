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


def get_registered_user(app):
    assert len(app.test_user_store.users) == 1
    return app.test_user_store.users[0]


def test_forgot_password_returns_generic_success(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/forgot-password",
        json={
            "email": "does-not-exist@example.com"
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True


def test_forgot_password_requires_csrf(client):
    response = client.post(
        "/auth/forgot-password",
        json={
            "email": "mark@example.com"
        },
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["ok"] is False


def test_reset_password_changes_password(client, app):
    register_user(client)

    user = get_registered_user(app)

    state = app.extensions["marks_auth"]

    token = state.reset_token_service.generate(
        user.auth_id
    )

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/reset-password",
        json={
            "token": token,
            "password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True

    login_response = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert login_response.status_code == 200


def test_old_password_rejected_after_reset(client, app):
    register_user(client)

    user = get_registered_user(app)

    state = app.extensions["marks_auth"]

    token = state.reset_token_service.generate(
        user.auth_id
    )

    csrf_token = get_csrf(client)

    reset_response = client.post(
        "/auth/reset-password",
        json={
            "token": token,
            "password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert reset_response.status_code == 200

    login_response = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "TestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert login_response.status_code == 401


def test_reset_token_is_single_use(client, app):
    register_user(client)

    user = get_registered_user(app)

    state = app.extensions["marks_auth"]

    token = state.reset_token_service.generate(
        user.auth_id
    )

    csrf_token = get_csrf(client)

    first = client.post(
        "/auth/reset-password",
        json={
            "token": token,
            "password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert first.status_code == 200

    second = client.post(
        "/auth/reset-password",
        json={
            "token": token,
            "password": "AnotherPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = second.get_json()

    assert second.status_code == 400
    assert data["ok"] is False
    assert data["error"]["code"] == "INVALID_RESET_TOKEN"


def test_reset_rotates_auth_id(client, app):
    register_user(client)

    user = get_registered_user(app)

    original_auth_id = user.auth_id

    state = app.extensions["marks_auth"]

    token = state.reset_token_service.generate(
        original_auth_id
    )

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/reset-password",
        json={
            "token": token,
            "password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200
    assert user.auth_id != original_auth_id


def test_invalid_reset_token_rejected(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/reset-password",
        json={
            "token": "definitely-not-a-valid-token",
            "password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 400
    assert data["ok"] is False
    assert data["error"]["code"] == "INVALID_RESET_TOKEN"

def test_reset_rotates_auth_id_exactly_once(
    client,
    app,
    monkeypatch,
):
    register_user(client)

    state = app.extensions[
        "marks_auth"
    ]

    user = state.user_store.find_by_identity(
        "mark@example.com"
    )

    original_update = (
        state.user_store
        .update_password_and_rotate_auth_id
    )

    update_calls = 0
    rotate_calls = 0

    def tracked_update(
        user,
        password_hash,
    ):
        nonlocal update_calls

        update_calls += 1

        return original_update(
            user,
            password_hash,
        )

    def tracked_rotate(user):
        nonlocal rotate_calls

        rotate_calls += 1

    monkeypatch.setattr(
        state.user_store,
        "update_password_and_rotate_auth_id",
        tracked_update,
    )

    monkeypatch.setattr(
        state.user_store,
        "rotate_auth_id",
        tracked_rotate,
    )

    token = (
        state.reset_token_service
        .generate(user.auth_id)
    )

    csrf = get_csrf(client)

    response = client.post(
        "/auth/reset-password",
        json={
            "token": token,
            "password":
                "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200

    assert update_calls == 1
    assert rotate_calls == 0