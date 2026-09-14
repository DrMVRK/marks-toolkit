def get_csrf(client):
    response = client.get("/auth/csrf")

    return response.get_json()["data"]["csrf_token"]


def test_registration_success(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/register",
        json={
            "email": "mark@example.com",
            "username": "Mark",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = response.get_json()

    assert response.status_code == 201
    assert data["ok"] is True

def test_duplicate_email_rejected(client):
    csrf_token = get_csrf(client)

    first = client.post(
        "/auth/register",
        json={
            "email": "mark@example.com",
            "username": "Mark",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    assert first.status_code == 201

    second = client.post(
        "/auth/register",
        json={
            "email": "MARK@example.com",
            "username": "DifferentUser",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = second.get_json()

    assert second.status_code == 409
    assert data["ok"] is False
    assert data["error"]["code"] == "IDENTITY_UNAVAILABLE"


def test_duplicate_username_rejected(client):
    csrf_token = get_csrf(client)

    first = client.post(
        "/auth/register",
        json={
            "email": "first@example.com",
            "username": "Mark",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    assert first.status_code == 201

    second = client.post(
        "/auth/register",
        json={
            "email": "second@example.com",
            "username": "mArK",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = second.get_json()

    assert second.status_code == 409
    assert data["ok"] is False
    assert data["error"]["code"] == "IDENTITY_UNAVAILABLE"


def test_registration_requires_csrf(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "mark@example.com",
            "username": "Mark",
            "password": "TestingPassword123!"
        }
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["ok"] is False


def test_invalid_email_rejected(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/register",
        json={
            "email": "not-an-email",
            "username": "Mark",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = response.get_json()

    assert response.status_code == 400
    assert data["ok"] is False