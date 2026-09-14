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
            "password": password
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    assert response.status_code == 201


def test_login_with_email(client):
    register_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True
    assert data["data"]["username"] == "Mark"


def test_login_with_username(client):
    register_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": "Mark",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True


def test_login_is_case_insensitive(client):
    register_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": "mArK",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    assert response.status_code == 200


def test_wrong_password_rejected(client):
    register_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "DefinitelyWrongPassword!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = response.get_json()

    assert response.status_code == 401
    assert data["ok"] is False
    assert data["error"]["code"] == "INVALID_CREDENTIALS"


def test_unknown_user_uses_generic_error(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": "does-not-exist@example.com",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = response.get_json()

    assert response.status_code == 401
    assert data["error"]["code"] == "INVALID_CREDENTIALS"


def test_login_requires_csrf(client):
    response = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "TestingPassword123!"
        }
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["ok"] is False