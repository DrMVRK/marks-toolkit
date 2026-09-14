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


def login_user(
    client,
    identity="mark@example.com",
    password="TestingPassword123!",
    remember=False,
):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": identity,
            "password": password,
            "remember": remember,
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    return response


def test_me_reports_unauthenticated(client):
    response = client.get("/auth/me")

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True
    assert data["data"]["authenticated"] is False
    assert data["data"]["user"] is None


def test_me_reports_authenticated_user(client):
    register_user(client)
    login_user(client)

    response = client.get("/auth/me")

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True
    assert data["data"]["authenticated"] is True

    user = data["data"]["user"]

    assert user["username"] == "Mark"
    assert user["email"] == "mark@example.com"
    assert user["auth_id"]


def test_logout_clears_session(client):
    register_user(client)
    login_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 200

    me_response = client.get("/auth/me")
    data = me_response.get_json()

    assert data["data"]["authenticated"] is False
    assert data["data"]["user"] is None


def test_logout_requires_authentication(client):
    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 401
    assert data["ok"] is False
    assert data["error"]["code"] == "AUTH_REQUIRED"


def test_logout_requires_csrf(client):
    register_user(client)
    login_user(client)

    response = client.post(
        "/auth/logout"
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["ok"] is False


def test_auth_id_rotation_invalidates_existing_session(client, app):
    register_user(client)
    login_user(client)

    user = app.test_user_store.users[0]

    app.test_user_store.rotate_auth_id(user)

    response = client.get("/auth/me")

    data = response.get_json()

    assert response.status_code == 200
    assert data["data"]["authenticated"] is False