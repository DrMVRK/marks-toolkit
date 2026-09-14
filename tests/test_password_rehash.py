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


def test_login_rehashes_outdated_password(client, app, monkeypatch):
    register_user(client)

    user = app.test_user_store.users[0]

    state = app.extensions["marks_auth"]

    original_hash = user.password_hash

    monkeypatch.setattr(
        state.password_service,
        "needs_rehash",
        lambda stored_hash: True
    )

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

    assert user.password_hash != original_hash

    assert state.password_service.verify_password(
        user.password_hash,
        "TestingPassword123!"
    )