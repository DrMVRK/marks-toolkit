import hashlib


TEST_EMAIL = "mark@example.com"
TEST_USERNAME = "Mark"
TEST_PASSWORD = (
    "TestingPassword123!"
)


def get_csrf(client):
    response = client.get(
        "/auth/csrf"
    )

    assert response.status_code == 200

    return (
        response.get_json()
        ["data"]
        ["csrf_token"]
    )


def register_user(client):
    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/register",
        json={
            "email": TEST_EMAIL,
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
        headers={
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code in (
        200,
        201,
    )


def login_user(
    client,
    *,
    remember=False,
):
    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/login",
        json={
            "identity": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "remember": remember,
        },
        headers={
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code == 200

    return response


def public_session_id(
    session_id,
):
    return hashlib.sha256(
        session_id.encode(
            "utf-8"
        )
    ).hexdigest()


def test_list_sessions_contains_current_session(
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
        "/auth/sessions"
    )

    assert response.status_code == 200

    data = (
        response.get_json()
        ["data"]
        ["sessions"]
    )

    assert len(data) == 1

    current = data[0]

    assert (
        current["current"]
        is True
    )

    assert (
        current[
            "authentication_method"
        ]
        == "password"
    )

    assert (
        current["remembered"]
        is False
    )

    assert current["id"]

    # The management API must never expose
    # the real server-side session ID.
    state = app.extensions[
        "marks_auth"
    ]

    raw_session = (
        state.session_store
        .list_for_user(1)[0]
    )

    assert (
        current["id"]
        != raw_session.id
    )


def test_list_sessions_does_not_expose_auth_id(
    client,
):
    register_user(
        client
    )

    login_user(
        client
    )

    response = client.get(
        "/auth/sessions"
    )

    session = (
        response.get_json()
        ["data"]
        ["sessions"]
        [0]
    )

    assert (
        "auth_id"
        not in session
    )

    assert (
        "user_id"
        not in session
    )


def test_remembered_session_is_marked(
    client,
):
    register_user(
        client
    )

    login_user(
        client,
        remember=True,
    )

    response = client.get(
        "/auth/sessions"
    )

    session = (
        response.get_json()
        ["data"]
        ["sessions"]
        [0]
    )

    assert (
        session["remembered"]
        is True
    )


def test_can_revoke_another_session(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    state = app.extensions[
        "marks_auth"
    ]

    user = (
        state.user_store
        .find_by_identity(
            TEST_EMAIL
        )
    )

    other = (
        state.session_service
        .create_session(
            user=user,
            ip_address="10.0.0.2",
            user_agent=(
                "Other Browser"
            ),
            authentication_method=(
                "password"
            ),
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.delete(
        (
            "/auth/sessions/"
            + public_session_id(
                other.id
            )
        ),
        headers={
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code == 200

    stored = (
        state.session_store.get(
            other.id
        )
    )

    assert stored is not None

    assert (
        stored.revoked_at
        is not None
    )


def test_revoking_other_session_keeps_current_logged_in(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    state = app.extensions[
        "marks_auth"
    ]

    user = (
        state.user_store
        .find_by_identity(
            TEST_EMAIL
        )
    )

    other = (
        state.session_service
        .create_session(
            user=user
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.delete(
        (
            "/auth/sessions/"
            + public_session_id(
                other.id
            )
        ),
        headers={
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code == 200

    me = client.get(
        "/auth/me"
    )

    assert (
        me.get_json()
        ["data"]
        ["authenticated"]
        is True
    )


def test_cannot_revoke_unknown_session(
    client,
):
    register_user(
        client
    )

    login_user(
        client
    )

    csrf = get_csrf(
        client
    )

    response = client.delete(
        (
            "/auth/sessions/"
            + ("a" * 64)
        ),
        headers={
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code == 404

    assert (
        response.get_json()
        ["error"]
        ["code"]
        == "SESSION_NOT_FOUND"
    )


def test_session_revoke_requires_csrf(
    client,
):
    register_user(
        client
    )

    login_user(
        client
    )

    sessions = (
        client.get(
            "/auth/sessions"
        )
        .get_json()
        ["data"]
        ["sessions"]
    )

    response = client.delete(
        (
            "/auth/sessions/"
            + sessions[0]["id"]
        )
    )

    assert response.status_code == 403


def test_current_session_can_revoke_itself(
    client,
):
    register_user(
        client
    )

    login_user(
        client,
        remember=True,
    )

    session = (
        client.get(
            "/auth/sessions"
        )
        .get_json()
        ["data"]
        ["sessions"]
        [0]
    )

    csrf = get_csrf(
        client
    )

    response = client.delete(
        (
            "/auth/sessions/"
            + session["id"]
        ),
        headers={
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code == 200

    me = client.get(
        "/auth/me"
    )

    assert (
        me.get_json()
        ["data"]
        ["authenticated"]
        is False
    )

    assert (
        client.get_cookie(
            "marks_auth_device_session"
        )
        is None
    )


def test_revoke_other_sessions(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    state = app.extensions[
        "marks_auth"
    ]

    user = (
        state.user_store
        .find_by_identity(
            TEST_EMAIL
        )
    )

    first = (
        state.session_service
        .create_session(
            user=user
        )
    )

    second = (
        state.session_service
        .create_session(
            user=user
        )
    )

    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/sessions/revoke-others",
        headers={
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code == 200

    assert (
        response.get_json()
        ["data"]
        ["revoked_count"]
        == 2
    )

    assert (
        state.session_store
        .get(first.id)
        .revoked_at
        is not None
    )

    assert (
        state.session_store
        .get(second.id)
        .revoked_at
        is not None
    )


def test_revoke_others_keeps_current_session(
    client,
    app,
):
    register_user(
        client
    )

    login_user(
        client
    )

    state = app.extensions[
        "marks_auth"
    ]

    user = (
        state.user_store
        .find_by_identity(
            TEST_EMAIL
        )
    )

    state.session_service.create_session(
        user=user
    )

    csrf = get_csrf(
        client
    )

    response = client.post(
        "/auth/sessions/revoke-others",
        headers={
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code == 200

    me = client.get(
        "/auth/me"
    )

    assert (
        me.get_json()
        ["data"]
        ["authenticated"]
        is True
    )

    active = (
        state.session_store
        .list_for_user(
            user.id
        )
    )

    assert len(active) == 1