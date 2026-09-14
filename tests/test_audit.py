import logging


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


def test_failed_login_is_audited(
    client,
    caplog
):
    caplog.set_level(
        logging.INFO,
        logger="marks_toolkit.auth"
    )

    register_user(client)

    csrf_token = get_csrf(client)

    response = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "WrongPassword123!",
        },
        headers={
            "X-CSRF-Token": csrf_token
        },
    )

    assert response.status_code == 401

    assert (
        "auth_event=login_failure"
        in caplog.text
    )


def test_successful_login_is_audited(
    client,
    caplog
):
    caplog.set_level(
        logging.INFO,
        logger="marks_toolkit.auth"
    )

    register_user(client)

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

    assert (
        "auth_event=login_success"
        in caplog.text
    )