from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from sqlalchemy import (
    create_engine,
)
from sqlalchemy.orm import (
    sessionmaker,
)

from marks_toolkit.auth.session_store import (
    SessionRecord,
)
from marks_toolkit.auth.sqlalchemy_models import (
    AuthBase,
    AuthUserModel,
)
from marks_toolkit.auth.sqlalchemy_session_store import (
    SQLAlchemySessionStore,
)


def utcnow():
    return datetime.now(
        timezone.utc
    )


@pytest.fixture
def session_factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
    )

    AuthBase.metadata.create_all(
        engine
    )

    factory = sessionmaker(
        bind=engine,
        expire_on_commit=False,
    )

    with factory() as db:
        db.add_all([
            AuthUserModel(
                id=1,
                auth_id="auth-1",
                email="one@example.com",
                email_key="one@example.com",
                username="One",
                username_key="one",
                password_hash="hash",
                active=True,
            ),
            AuthUserModel(
                id=2,
                auth_id="auth-2",
                email="two@example.com",
                email_key="two@example.com",
                username="Two",
                username_key="two",
                password_hash="hash",
                active=True,
            ),
        ])

        db.commit()

    yield factory

    engine.dispose()


@pytest.fixture
def store(
    session_factory,
):
    return SQLAlchemySessionStore(
        session_factory
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
            created_at or now
        ),
        last_seen_at=(
            last_seen_at or now
        ),
        ip_address="127.0.0.1",
        user_agent="Test Browser",
        authentication_method=(
            "password"
        ),
        remembered=False,
    )


def normalize_sqlite_datetime(
    value,
):
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value


def test_create_and_get_session(
    store,
):
    created = store.create(
        make_session()
    )

    stored = store.get(
        created.id
    )

    assert stored is not None
    assert stored.id == "session-1"
    assert stored.user_id == 1
    assert stored.auth_id == "auth-1"

    assert stored.ip_address == (
        "127.0.0.1"
    )

    assert stored.user_agent == (
        "Test Browser"
    )

    assert (
        stored.authentication_method
        == "password"
    )

    assert stored.remembered is False
    assert stored.revoked_at is None


def test_duplicate_session_id_rejected(
    store,
):
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


def test_empty_session_id_rejected(
    store,
):
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


def test_get_missing_session_returns_none(
    store,
):
    assert (
        store.get(
            "missing"
        )
        is None
    )


def test_list_for_user(
    store,
):
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
            session_id="other",
            user_id=2,
            auth_id="auth-2",
        )
    )

    sessions = (
        store.list_for_user(
            1
        )
    )

    assert {
        session.id
        for session in sessions
    } == {
        "one",
        "two",
    }


def test_list_excludes_revoked_by_default(
    store,
):
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
            1
        )
    )

    assert [
        session.id
        for session in sessions
    ] == [
        "active"
    ]


def test_list_can_include_revoked(
    store,
):
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


def test_sessions_sorted_newest_first(
    store,
):
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


def test_touch_updates_last_seen(
    store,
):
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

    assert store.touch(
        "session-1",
        user_id=1,
        last_seen_at=updated,
    )

    stored = store.get(
        "session-1"
    )

    assert stored is not None

    assert (
        normalize_sqlite_datetime(
            stored.last_seen_at
        )
        == updated
    )


def test_touch_wrong_user_fails(
    store,
):
    store.create(
        make_session()
    )

    assert (
        store.touch(
            "session-1",
            user_id=2,
            last_seen_at=utcnow(),
        )
        is False
    )


def test_touch_revoked_session_fails(
    store,
):
    store.create(
        make_session()
    )

    store.revoke(
        "session-1",
        user_id=1,
        revoked_at=utcnow(),
    )

    assert (
        store.touch(
            "session-1",
            user_id=1,
            last_seen_at=utcnow(),
        )
        is False
    )


def test_revoke_session(
    store,
):
    store.create(
        make_session()
    )

    revoked_at = utcnow()

    assert store.revoke(
        "session-1",
        user_id=1,
        revoked_at=revoked_at,
    )

    stored = store.get(
        "session-1"
    )

    assert stored is not None

    assert (
        normalize_sqlite_datetime(
            stored.revoked_at
        )
        == revoked_at
    )


def test_wrong_user_cannot_revoke_session(
    store,
):
    store.create(
        make_session()
    )

    assert (
        store.revoke(
            "session-1",
            user_id=2,
            revoked_at=utcnow(),
        )
        is False
    )

    stored = store.get(
        "session-1"
    )

    assert stored is not None
    assert stored.revoked_at is None


def test_revoke_is_single_transition(
    store,
):
    store.create(
        make_session()
    )

    assert store.revoke(
        "session-1",
        user_id=1,
        revoked_at=utcnow(),
    )

    assert (
        store.revoke(
            "session-1",
            user_id=1,
            revoked_at=utcnow(),
        )
        is False
    )


def test_revoke_others_preserves_current(
    store,
):
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
        revoked_at=revoked_at,
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

    assert current.revoked_at is None

    assert (
        normalize_sqlite_datetime(
            other_1.revoked_at
        )
        == revoked_at
    )

    assert (
        normalize_sqlite_datetime(
            other_2.revoked_at
        )
        == revoked_at
    )


def test_revoke_others_does_not_touch_other_users(
    store,
):
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
            auth_id="auth-2",
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
    assert other.revoked_at is None


def test_revoke_all(
    store,
):
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
            auth_id="auth-2",
        )
    )

    revoked_at = utcnow()

    count = store.revoke_all(
        1,
        revoked_at=revoked_at,
    )

    assert count == 2

    one = store.get(
        "one"
    )

    two = store.get(
        "two"
    )

    other = store.get(
        "other-user"
    )

    assert one is not None
    assert two is not None
    assert other is not None

    assert (
        normalize_sqlite_datetime(
            one.revoked_at
        )
        == revoked_at
    )

    assert (
        normalize_sqlite_datetime(
            two.revoked_at
        )
        == revoked_at
    )

    assert other.revoked_at is None