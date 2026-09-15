import logging


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


def test_authenticated_user_can_change_password(client):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "TestingPassword123!",
            "new_password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True


def test_wrong_current_password_rejected(client):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "WrongPassword123!",
            "new_password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 400
    assert data["ok"] is False
    assert (
        data["error"]["code"]
        == "INCORRECT_CURRENT_PASSWORD"
    )


def test_new_password_policy_is_enforced(client):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "TestingPassword123!",
            "new_password": "short",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 400
    assert data["ok"] is False
    assert data["error"]["code"] == "WEAK_PASSWORD"


def test_old_password_stops_working_after_change(client):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "TestingPassword123!",
            "new_password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    csrf_token = get_csrf(client)

    old_login = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "TestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert old_login.status_code == 401


def test_new_password_works_after_change(client):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "TestingPassword123!",
            "new_password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    csrf_token = get_csrf(client)

    new_login = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert new_login.status_code == 200


def test_password_change_rotates_auth_id(client, app):
    register_user(client)
    login_user(client)

    user = app.test_user_store.users[0]
    original_auth_id = user.auth_id

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "TestingPassword123!",
            "new_password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200
    assert user.auth_id != original_auth_id


def test_password_change_logs_current_session_out(
    client,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "TestingPassword123!",
            "new_password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    me_response = client.get("/auth/me")
    data = me_response.get_json()

    assert data["data"]["authenticated"] is False
    assert data["data"]["user"] is None


def test_password_change_requires_authentication(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "TestingPassword123!",
            "new_password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 401
    assert data["ok"] is False
    assert data["error"]["code"] == "AUTH_REQUIRED"


def test_password_change_requires_csrf(client):
    register_user(client)
    login_user(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "TestingPassword123!",
            "new_password": "NewTestingPassword123!",
        },
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["ok"] is False


def test_password_change_is_audited(
    client,
    caplog,
):
    caplog.set_level(
        logging.INFO,
        logger="marks_toolkit.auth",
    )

    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/change-password",
        json={
            "current_password": "TestingPassword123!",
            "new_password": "NewTestingPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    assert (
        "auth_event=password_changed"
        in caplog.text
    )

def test_password_change_is_rate_limited(
    client,
):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(
        client
    )

    for _ in range(5):
        response = client.post(
            "/auth/change-password",
            json={
                "current_password":
                    "WrongPassword123!",
                "new_password":
                    "AnotherTestingPassword123!",
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
        "/auth/change-password",
        json={
            "current_password":
                "WrongPassword123!",
            "new_password":
                "AnotherTestingPassword123!",
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