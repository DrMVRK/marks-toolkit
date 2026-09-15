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

def test_audit_logger_redacts_nested_sensitive_values(
    caplog,
):
    from marks_toolkit.auth.audit import (
        StandardAuditLogger,
    )

    logger = StandardAuditLogger()

    with caplog.at_level(
        "INFO",
        logger="marks_toolkit.auth",
    ):
        logger.log(
            "test_event",
            username="Mark",
            current_password="secret-1",
            metadata={
                "reset_token":
                    "secret-2",
                "nested": {
                    "recovery_codes": [
                        "code-1",
                        "code-2",
                    ],
                    "safe_value":
                        "hello",
                },
            },
        )

    output = caplog.text

    assert "Mark" in output
    assert "hello" in output

    assert "secret-1" not in output
    assert "secret-2" not in output
    assert "code-1" not in output
    assert "code-2" not in output

    assert "<redacted>" in output

def test_audit_logger_redacts_sensitive_key_variants(
    caplog,
):
    from marks_toolkit.auth.audit import (
        StandardAuditLogger,
    )

    logger = StandardAuditLogger()

    with caplog.at_level(
        "INFO",
        logger="marks_toolkit.auth",
    ):
        logger.log(
            "test_event",
            password_confirmation="alpha",
            session_cookie="beta",
            provisioning_uri="gamma",
            access_token="delta",
            safe_field="visible",
        )

    output = caplog.text

    assert "visible" in output

    assert "alpha" not in output
    assert "beta" not in output
    assert "gamma" not in output
    assert "delta" not in output