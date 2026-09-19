from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from marks_toolkit.auth.memory_session_store import (
    MemorySessionStore,
)

from marks_toolkit.auth.session_store import (
    SessionRecord,
)


def utcnow():
    return datetime.now(
        timezone.utc
    )


def make_session(
    *,
    session_id="session-1",
    user_id=1,
    auth_id="auth-1",
    created_at=None,
    last_seen_at=None,
):
    now = utcnow()

    return SessionRecord(
        id=session_id,

        user_id=user_id,

        auth_id=auth_id,

        created_at=(
            created_at
            or now
        ),

        last_seen_at=(
            last_seen_at
            or now
        ),

        ip_address=(
            "127.0.0.1"
        ),

        user_agent=(
            "Test Browser"
        ),

        authentication_method=(
            "password"
        ),

        remembered=False,
    )


def test_create_and_get_session():
    store = (
        MemorySessionStore()
    )

    session = make_session()

    created = store.create(
        session
    )

    stored = store.get(
        session.id
    )

    assert created.id == (
        "session-1"
    )

    assert stored is not None

    assert stored.id == (
        session.id
    )

    assert stored.user_id == 1

    assert stored.auth_id == (
        "auth-1"
    )

    assert stored.revoked_at is None


def test_duplicate_session_id_rejected():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session()
    )

    with pytest.raises(
        ValueError,
        match=(
            "Session ID already exists"
        ),
    ):
        store.create(
            make_session()
        )


def test_empty_session_id_rejected():
    store = (
        MemorySessionStore()
    )

    with pytest.raises(
        ValueError,
        match=(
            "Session ID is required"
        ),
    ):
        store.create(
            make_session(
                session_id=""
            )
        )


def test_get_missing_session_returns_none():
    store = (
        MemorySessionStore()
    )

    assert (
        store.get(
            "missing"
        )
        is None
    )


def test_get_returns_copy():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session()
    )

    first = store.get(
        "session-1"
    )

    assert first is not None

    first.revoked_at = (
        utcnow()
    )

    second = store.get(
        "session-1"
    )

    assert second is not None

    assert (
        second.revoked_at
        is None
    )


def test_list_for_user_returns_only_users_sessions():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session(
            session_id="user-1-a",
            user_id=1,
        )
    )

    store.create(
        make_session(
            session_id="user-1-b",
            user_id=1,
        )
    )

    store.create(
        make_session(
            session_id="user-2",
            user_id=2,
        )
    )

    sessions = (
        store.list_for_user(
            1
        )
    )

    assert len(
        sessions
    ) == 2

    assert {
        record.id
        for record in sessions
    } == {
        "user-1-a",
        "user-1-b",
    }


def test_list_excludes_revoked_by_default():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session(
            session_id="active"
        )
    )

    store.create(
        make_session(
            session_id="revoked"
        )
    )

    assert store.revoke(
        "revoked",
        user_id=1,
        revoked_at=utcnow(),
    )

    sessions = (
        store.list_for_user(
            1
        )
    )

    assert [
        session.id
        for session in sessions
    ] == [
        "active"
    ]


def test_list_can_include_revoked_sessions():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session(
            session_id="active"
        )
    )

    store.create(
        make_session(
            session_id="revoked"
        )
    )

    store.revoke(
        "revoked",
        user_id=1,
        revoked_at=utcnow(),
    )

    sessions = (
        store.list_for_user(
            1,
            include_revoked=True,
        )
    )

    assert {
        session.id
        for session in sessions
    } == {
        "active",
        "revoked",
    }


def test_sessions_sorted_newest_first():
    store = (
        MemorySessionStore()
    )

    now = utcnow()

    store.create(
        make_session(
            session_id="older",
            created_at=(
                now
                - timedelta(
                    hours=1
                )
            ),
        )
    )

    store.create(
        make_session(
            session_id="newer",
            created_at=now,
        )
    )

    sessions = (
        store.list_for_user(
            1
        )
    )

    assert [
        session.id
        for session in sessions
    ] == [
        "newer",
        "older",
    ]


def test_touch_updates_last_seen():
    store = (
        MemorySessionStore()
    )

    original = (
        utcnow()
        - timedelta(
            minutes=10
        )
    )

    updated = utcnow()

    store.create(
        make_session(
            last_seen_at=original
        )
    )

    result = store.touch(
        "session-1",
        user_id=1,
        last_seen_at=updated,
    )

    assert result is True

    stored = store.get(
        "session-1"
    )

    assert stored is not None

    assert (
        stored.last_seen_at
        == updated
    )


def test_touch_rejects_wrong_user():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session(
            user_id=1
        )
    )

    result = store.touch(
        "session-1",
        user_id=2,
        last_seen_at=utcnow(),
    )

    assert result is False


def test_touch_rejects_revoked_session():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session()
    )

    store.revoke(
        "session-1",
        user_id=1,
        revoked_at=utcnow(),
    )

    result = store.touch(
        "session-1",
        user_id=1,
        last_seen_at=utcnow(),
    )

    assert result is False


def test_revoke_session():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session()
    )

    revoked_at = utcnow()

    result = store.revoke(
        "session-1",
        user_id=1,
        revoked_at=revoked_at,
    )

    assert result is True

    stored = store.get(
        "session-1"
    )

    assert stored is not None

    assert (
        stored.revoked_at
        == revoked_at
    )


def test_user_cannot_revoke_another_users_session():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session(
            user_id=1
        )
    )

    result = store.revoke(
        "session-1",
        user_id=2,
        revoked_at=utcnow(),
    )

    assert result is False

    stored = store.get(
        "session-1"
    )

    assert stored is not None

    assert (
        stored.revoked_at
        is None
    )


def test_revoke_is_single_transition():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session()
    )

    first = store.revoke(
        "session-1",
        user_id=1,
        revoked_at=utcnow(),
    )

    second = store.revoke(
        "session-1",
        user_id=1,
        revoked_at=utcnow(),
    )

    assert first is True
    assert second is False


def test_revoke_others_preserves_current_session():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session(
            session_id="current"
        )
    )

    store.create(
        make_session(
            session_id="other-1"
        )
    )

    store.create(
        make_session(
            session_id="other-2"
        )
    )

    revoked_at = utcnow()

    count = store.revoke_others(
        1,

        current_session_id=(
            "current"
        ),

        revoked_at=(
            revoked_at
        ),
    )

    assert count == 2

    current = store.get(
        "current"
    )

    other_1 = store.get(
        "other-1"
    )

    other_2 = store.get(
        "other-2"
    )

    assert current is not None
    assert other_1 is not None
    assert other_2 is not None

    assert (
        current.revoked_at
        is None
    )

    assert (
        other_1.revoked_at
        == revoked_at
    )

    assert (
        other_2.revoked_at
        == revoked_at
    )


def test_revoke_others_does_not_touch_another_user():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session(
            session_id="current",
            user_id=1,
        )
    )

    store.create(
        make_session(
            session_id="other-user",
            user_id=2,
        )
    )

    count = store.revoke_others(
        1,

        current_session_id=(
            "current"
        ),

        revoked_at=utcnow(),
    )

    assert count == 0

    other = store.get(
        "other-user"
    )

    assert other is not None

    assert (
        other.revoked_at
        is None
    )


def test_revoke_all_sessions_for_user():
    store = (
        MemorySessionStore()
    )

    store.create(
        make_session(
            session_id="one",
            user_id=1,
        )
    )

    store.create(
        make_session(
            session_id="two",
            user_id=1,
        )
    )

    store.create(
        make_session(
            session_id="other-user",
            user_id=2,
        )
    )

    revoked_at = utcnow()

    count = store.revoke_all(
        1,
        revoked_at=revoked_at,
    )

    assert count == 2

    one = store.get("one")
    two = store.get("two")

    other = store.get(
        "other-user"
    )

    assert one is not None
    assert two is not None
    assert other is not None

    assert (
        one.revoked_at
        == revoked_at
    )

    assert (
        two.revoked_at
        == revoked_at
    )

    assert (
        other.revoked_at
        is None
    )