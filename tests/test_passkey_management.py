from marks_toolkit.auth.passkey_store import (
    PasskeyCredential,
)


def get_csrf(
    client,
):
    response = client.get(
        "/auth/csrf"
    )

    assert response.status_code == 200

    return (
        response.get_json()
        ["data"]
        ["csrf_token"]
    )


def register_user(
    client,
    *,
    email="mark@example.com",
    username="Mark",
    password="TestingPassword123!",
):
    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "username": username,
            "password": password,
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 201


def login_user(
    client,
    *,
    identity="mark@example.com",
    password="TestingPassword123!",
):
    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/login",
        json={
            "identity": identity,
            "password": password,
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200


def add_passkey(
    app,
    *,
    user_id,
    credential_id=b"credential-one",
    name="Windows Laptop",
):
    return (
        app.test_passkey_store
        .create(
            PasskeyCredential(
                id=None,
                user_id=user_id,
                user_handle=b"user-handle",
                credential_id=credential_id,
                public_key=b"public-key",
                sign_count=0,
                name=name,
                transports=(
                    "internal",
                ),
            )
        )
    )


def test_passkey_list_requires_authentication(
    client,
):
    response = client.get(
        "/auth/passkeys"
    )

    data = response.get_json()

    assert response.status_code == 401
    assert data["ok"] is False
    assert (
        data["error"]["code"]
        == "AUTH_REQUIRED"
    )


def test_passkey_list_returns_metadata(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    user = (
        app.test_user_store
        .find_by_identity(
            "mark@example.com"
        )
    )

    add_passkey(
        app,
        user_id=user.id,
    )

    response = client.get(
        "/auth/passkeys"
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True

    passkeys = (
        data["data"]["passkeys"]
    )

    assert len(passkeys) == 1

    passkey = passkeys[0]

    assert (
        passkey["name"]
        == "Windows Laptop"
    )

    assert (
        passkey["credential_id"]
    )

    assert (
        passkey["created_at"]
    )

    assert (
        passkey["last_used_at"]
        is None
    )

    assert (
        passkey["transports"]
        == ["internal"]
    )

    assert "public_key" not in passkey
    assert "user_handle" not in passkey
    assert "sign_count" not in passkey
    assert "user_id" not in passkey


def test_passkey_list_is_not_cached(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    response = client.get(
        "/auth/passkeys"
    )

    assert response.status_code == 200

    assert (
        response.headers[
            "Cache-Control"
        ]
        == "no-store"
    )


def test_rename_passkey_requires_csrf(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    user = (
        app.test_user_store
        .find_by_identity(
            "mark@example.com"
        )
    )

    add_passkey(
        app,
        user_id=user.id,
    )

    response = client.patch(
        "/auth/passkeys/"
        "Y3JlZGVudGlhbC1vbmU",
        json={
            "name": "Laptop"
        },
    )

    assert response.status_code == 403


def test_passkey_can_be_renamed(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    user = (
        app.test_user_store
        .find_by_identity(
            "mark@example.com"
        )
    )

    credential = add_passkey(
        app,
        user_id=user.id,
    )

    from marks_toolkit.auth.routes import (
        encode_passkey_credential_id,
    )

    encoded_id = (
        encode_passkey_credential_id(
            credential.credential_id
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.patch(
        f"/auth/passkeys/{encoded_id}",
        json={
            "name":
                "Gaming PC"
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True

    stored = (
        app.test_passkey_store
        .get_by_credential_id(
            credential.credential_id
        )
    )

    assert (
        stored.name
        == "Gaming PC"
    )


def test_passkey_name_can_be_cleared(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    user = (
        app.test_user_store
        .find_by_identity(
            "mark@example.com"
        )
    )

    credential = add_passkey(
        app,
        user_id=user.id,
    )

    from marks_toolkit.auth.routes import (
        encode_passkey_credential_id,
    )

    encoded_id = (
        encode_passkey_credential_id(
            credential.credential_id
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.patch(
        f"/auth/passkeys/{encoded_id}",
        json={
            "name": "   "
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200

    stored = (
        app.test_passkey_store
        .get_by_credential_id(
            credential.credential_id
        )
    )

    assert stored.name is None


def test_passkey_name_length_is_enforced(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    user = (
        app.test_user_store
        .find_by_identity(
            "mark@example.com"
        )
    )

    credential = add_passkey(
        app,
        user_id=user.id,
    )

    from marks_toolkit.auth.routes import (
        encode_passkey_credential_id,
    )

    encoded_id = (
        encode_passkey_credential_id(
            credential.credential_id
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.patch(
        f"/auth/passkeys/{encoded_id}",
        json={
            "name": "x" * 101
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 400
    assert (
        data["error"]["code"]
        == "INVALID_REQUEST"
    )


def test_user_cannot_rename_another_users_passkey(
    client,
    app,
):
    register_user(
        client,
        email="mark@example.com",
        username="Mark",
    )

    second_user = (
        app.test_user_store
        .create_user(
            email="other@example.com",
            username="Other",
            password_hash=(
                app.extensions[
                    "marks_auth"
                ]
                .password_service
                .hash_password(
                    "OtherPassword123!"
                )
            ),
        )
    )

    credential = add_passkey(
        app,
        user_id=second_user.id,
        credential_id=(
            b"other-user-credential"
        ),
    )

    login_user(
        client
    )

    from marks_toolkit.auth.routes import (
        encode_passkey_credential_id,
    )

    encoded_id = (
        encode_passkey_credential_id(
            credential.credential_id
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.patch(
        f"/auth/passkeys/{encoded_id}",
        json={
            "name":
                "Should Not Work"
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 404


def test_delete_passkey_requires_csrf(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    user = (
        app.test_user_store
        .find_by_identity(
            "mark@example.com"
        )
    )

    credential = add_passkey(
        app,
        user_id=user.id,
    )

    from marks_toolkit.auth.routes import (
        encode_passkey_credential_id,
    )

    encoded_id = (
        encode_passkey_credential_id(
            credential.credential_id
        )
    )

    response = client.delete(
        f"/auth/passkeys/{encoded_id}",
        json={
            "current_password":
                "TestingPassword123!"
        },
    )

    assert response.status_code == 403


def test_delete_passkey_requires_correct_password(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    user = (
        app.test_user_store
        .find_by_identity(
            "mark@example.com"
        )
    )

    credential = add_passkey(
        app,
        user_id=user.id,
    )

    from marks_toolkit.auth.routes import (
        encode_passkey_credential_id,
    )

    encoded_id = (
        encode_passkey_credential_id(
            credential.credential_id
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.delete(
        f"/auth/passkeys/{encoded_id}",
        json={
            "current_password":
                "WrongPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    data = response.get_json()

    assert response.status_code == 401

    assert (
        data["error"]["code"]
        == "INVALID_PASSWORD"
    )

    assert (
        app.test_passkey_store
        .get_by_credential_id(
            credential.credential_id
        )
        is not None
    )


def test_passkey_can_be_deleted(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    user = (
        app.test_user_store
        .find_by_identity(
            "mark@example.com"
        )
    )

    credential = add_passkey(
        app,
        user_id=user.id,
    )

    from marks_toolkit.auth.routes import (
        encode_passkey_credential_id,
    )

    encoded_id = (
        encode_passkey_credential_id(
            credential.credential_id
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.delete(
        f"/auth/passkeys/{encoded_id}",
        json={
            "current_password":
                "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200

    assert (
        app.test_passkey_store
        .get_by_credential_id(
            credential.credential_id
        )
        is None
    )


def test_deleting_passkey_rotates_auth_id_and_keeps_session(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    user = (
        app.test_user_store
        .find_by_identity(
            "mark@example.com"
        )
    )

    old_auth_id = (
        user.auth_id
    )

    credential = add_passkey(
        app,
        user_id=user.id,
    )

    from marks_toolkit.auth.routes import (
        encode_passkey_credential_id,
    )

    encoded_id = (
        encode_passkey_credential_id(
            credential.credential_id
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.delete(
        f"/auth/passkeys/{encoded_id}",
        json={
            "current_password":
                "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 200

    assert (
        user.auth_id
        != old_auth_id
    )

    me = client.get(
        "/auth/me"
    )

    assert me.status_code == 200

    assert (
        me.get_json()
        ["data"]
        ["authenticated"]
        is True
    )


def test_user_cannot_delete_another_users_passkey(
    client,
    app,
):
    register_user(
        client,
        email="mark@example.com",
        username="Mark",
    )

    state = app.extensions[
        "marks_auth"
    ]

    second_user = (
        app.test_user_store
        .create_user(
            email="other@example.com",
            username="Other",
            password_hash=(
                state.password_service
                .hash_password(
                    "OtherPassword123!"
                )
            ),
        )
    )

    credential = add_passkey(
        app,
        user_id=second_user.id,
        credential_id=(
            b"other-user-credential"
        ),
    )

    login_user(
        client
    )

    from marks_toolkit.auth.routes import (
        encode_passkey_credential_id,
    )

    encoded_id = (
        encode_passkey_credential_id(
            credential.credential_id
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.delete(
        f"/auth/passkeys/{encoded_id}",
        json={
            "current_password":
                "TestingPassword123!"
        },
        headers={
            "X-CSRF-Token": csrf
        },
    )

    assert response.status_code == 404

    assert (
        app.test_passkey_store
        .get_by_credential_id(
            credential.credential_id
        )
        is not None
    )