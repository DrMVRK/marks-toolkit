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


def test_forgot_password_throttles_after_limit(client):
    csrf_token = get_csrf(client)

    for _ in range(3):
        response = client.post(
            "/auth/forgot-password",
            json={
                "email": "mark@example.com"
            },
            headers={
                "X-CSRF-Token": csrf_token
            },
        )

        assert response.status_code == 200

    blocked = client.post(
        "/auth/forgot-password",
        json={
            "email": "mark@example.com"
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = blocked.get_json()

    assert blocked.status_code == 429
    assert data["ok"] is False
    assert data["error"]["code"] == "RATE_LIMITED"


def test_forgot_password_throttles_unknown_email_too(client):
    csrf_token = get_csrf(client)

    for _ in range(3):
        response = client.post(
            "/auth/forgot-password",
            json={
                "email": "does-not-exist@example.com"
            },
            headers={
                "X-CSRF-Token": csrf_token
            },
        )

        assert response.status_code == 200

    blocked = client.post(
        "/auth/forgot-password",
        json={
            "email": "does-not-exist@example.com"
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert blocked.status_code == 429


def test_reset_password_throttles_after_limit(client):
    csrf_token = get_csrf(client)

    for _ in range(3):
        response = client.post(
            "/auth/reset-password",
            json={
                "token": "invalid-token",
                "password": "NewTestingPassword123!"
            },
            headers={
                "X-CSRF-Token": csrf_token
            },
        )

        assert response.status_code == 400

    blocked = client.post(
        "/auth/reset-password",
        json={
            "token": "invalid-token",
            "password": "NewTestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = blocked.get_json()

    assert blocked.status_code == 429
    assert data["ok"] is False
    assert data["error"]["code"] == "RATE_LIMITED"


def test_throttle_runs_after_csrf(client):
    for _ in range(5):
        response = client.post(
            "/auth/forgot-password",
            json={
                "email": "mark@example.com"
            },
        )

        assert response.status_code == 403

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/forgot-password",
        json={
            "email": "mark@example.com"
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200