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


def failed_login(client, csrf_token):
    return client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "WrongPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )


def test_captcha_required_after_failed_logins(client):
    register_user(client)

    csrf_token = get_csrf(client)

    first = failed_login(client, csrf_token)
    second = failed_login(client, csrf_token)

    assert first.status_code == 401
    assert second.status_code == 401

    third = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = third.get_json()

    assert third.status_code == 403
    assert data["ok"] is False
    assert data["error"]["code"] == "CAPTCHA_REQUIRED"


def test_valid_captcha_allows_login(client):
    register_user(client)

    csrf_token = get_csrf(client)

    failed_login(client, csrf_token)
    failed_login(client, csrf_token)

    response = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "TestingPassword123!",
            "captcha_token": "test-pass"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True


def test_invalid_captcha_rejected(client):
    register_user(client)

    csrf_token = get_csrf(client)

    failed_login(client, csrf_token)
    failed_login(client, csrf_token)

    response = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "TestingPassword123!",
            "captcha_token": "wrong-token"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["error"]["code"] == "CAPTCHA_REQUIRED"


def test_login_blocked_after_failure_threshold(client):
    register_user(client)

    csrf_token = get_csrf(client)

    # First two failures happen normally.
    failed_login(client, csrf_token)
    failed_login(client, csrf_token)

    # CAPTCHA is now required. Supplying the valid test CAPTCHA
    # allows the password attempt to reach LoginService and count
    # as another authentication failure.
    third = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "WrongPassword123!",
            "captcha_token": "test-pass"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    fourth = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "WrongPassword123!",
            "captcha_token": "test-pass"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    assert third.status_code == 401
    assert fourth.status_code == 401

    blocked = client.post(
        "/auth/login",
        json={
            "identity": "mark@example.com",
            "password": "TestingPassword123!",
            "captcha_token": "test-pass"
        },
        headers={
            "X-CSRF-Token": csrf_token
        }
    )

    data = blocked.get_json()

    assert blocked.status_code == 429
    assert data["ok"] is False
    assert data["error"]["code"] == "RATE_LIMITED"

def test_login_identity_limit_applies_across_ips(
    client,
):
    register_user(client)

    csrf_token = get_csrf(client)

    for index in range(4):
        response = client.post(
            "/auth/login",
            json={
                "identity":
                    "mark@example.com",
                "password":
                    "WrongPassword123!",
            },
            headers={
                "X-CSRF-Token":
                    csrf_token,
                "X-Forwarded-For":
                    f"203.0.113.{index + 1}",
            },
        )

        assert response.status_code in (
            401,
            403,
        )

    response = client.post(
        "/auth/login",
        json={
            "identity":
                "mark@example.com",
            "password":
                "WrongPassword123!",
        },
        headers={
            "X-CSRF-Token":
                csrf_token,
            "X-Forwarded-For":
                "203.0.113.99",
        },
    )

    data = response.get_json()

    assert response.status_code == 403

    assert (
        data["error"]["code"]
        == "CAPTCHA_REQUIRED"
    )

def test_login_ip_limit_applies_across_identities(
    client,
):
    csrf_token = get_csrf(client)

    identities = [
        "user1@example.com",
        "user2@example.com",
        "user3@example.com",
        "user4@example.com",
    ]

    for identity in identities:
        response = client.post(
            "/auth/login",
            json={
                "identity": identity,
                "password":
                    "WrongPassword123!",
            },
            headers={
                "X-CSRF-Token":
                    csrf_token
            },
        )

        assert response.status_code in (
            401,
            403,
        )

    response = client.post(
        "/auth/login",
        json={
            "identity":
                "user5@example.com",
            "password":
                "WrongPassword123!",
        },
        headers={
            "X-CSRF-Token":
                csrf_token
        },
    )

    data = response.get_json()

    assert response.status_code == 403

    assert (
        data["error"]["code"]
        == "CAPTCHA_REQUIRED"
    )