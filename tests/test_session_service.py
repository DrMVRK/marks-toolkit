from dataclasses import dataclass
from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from marks_toolkit.auth.memory_session_store import (
    MemorySessionStore,
)

from marks_toolkit.auth.session_service import (
    SessionService,
)


@dataclass
class DummyUser:
    id: int
    auth_id: str


def utcnow():
    return datetime.now(
        timezone.utc
    )


@pytest.fixture
def store():
    return MemorySessionStore()


@pytest.fixture
def service(
    store,
):
    return SessionService(
        session_store=store,
        touch_interval_seconds=60,
    )


@pytest.fixture
def user():
    return DummyUser(
        id=1,
        auth_id="auth-1",
    )


def test_create_session(
    service,
    store,
    user,
):
    now = utcnow()

    session = (
        service.create_session(
            user=user,
            ip_address="127.0.0.1",
            user_agent="Test Browser",
            authentication_method=(
                "password"
            ),
            remembered=True,
            now=now,
        )
    )

    assert session.id
    assert len(session.id) >= 32

    assert session.user_id == 1
    assert session.auth_id == "auth-1"

    assert (
        session.created_at
        == now
    )

    assert (
        session.last_seen_at
        == now
    )

    assert (
        session.ip_address
        == "127.0.0.1"
    )

    assert (
        session.user_agent
        == "Test Browser"
    )

    assert (
        session.authentication_method
        == "password"
    )

    assert session.remembered is True
    assert session.revoked_at is None

    stored = store.get(
        session.id
    )

    assert stored is not None


def test_session_ids_are_random(
    service,
    user,
):
    first = (
        service.create_session(
            user=user
        )
    )

    second = (
        service.create_session(
            user=user
        )
    )

    assert (
        first.id
        != second.id
    )


def test_create_requires_user(
    service,
):
    with pytest.raises(
        ValueError,
        match="user is required",
    ):
        service.create_session(
            user=None
        )


def test_validate_active_session(
    service,
    user,
):
    session = (
        service.create_session(
            user=user
        )
    )

    assert (
        service.validate_session(
            session_id=session.id,
            user=user,
        )
        is True
    )


def test_validate_missing_session_fails(
    service,
    user,
):
    assert (
        service.validate_session(
            session_id="missing",
            user=user,
        )
        is False
    )


def test_validate_wrong_user_fails(
    service,
    user,
):
    session = (
        service.create_session(
            user=user
        )
    )

    other = DummyUser(
        id=2,
        auth_id="auth-2",
    )

    assert (
        service.validate_session(
            session_id=session.id,
            user=other,
        )
        is False
    )


def test_validate_stale_auth_id_fails(
    service,
    user,
):
    session = (
        service.create_session(
            user=user
        )
    )

    rotated_user = DummyUser(
        id=1,
        auth_id="new-auth-id",
    )

    assert (
        service.validate_session(
            session_id=session.id,
            user=rotated_user,
        )
        is False
    )


def test_validate_revoked_session_fails(
    service,
    user,
):
    session = (
        service.create_session(
            user=user
        )
    )

    assert service.revoke_session(
        session_id=session.id,
        user=user,
    )

    assert (
        service.validate_session(
            session_id=session.id,
            user=user,
        )
        is False
    )


def test_validation_does_not_touch_too_early(
    service,
    store,
    user,
):
    now = utcnow()

    session = (
        service.create_session(
            user=user,
            now=now,
        )
    )

    checked_at = (
        now
        + timedelta(
            seconds=30
        )
    )

    assert service.validate_session(
        session_id=session.id,
        user=user,
        now=checked_at,
    )

    stored = store.get(
        session.id
    )

    assert stored is not None

    assert (
        stored.last_seen_at
        == now
    )


def test_validation_touches_after_interval(
    service,
    store,
    user,
):
    now = utcnow()

    session = (
        service.create_session(
            user=user,
            now=now,
        )
    )

    checked_at = (
        now
        + timedelta(
            seconds=60
        )
    )

    assert service.validate_session(
        session_id=session.id,
        user=user,
        now=checked_at,
    )

    stored = store.get(
        session.id
    )

    assert stored is not None

    assert (
        stored.last_seen_at
        == checked_at
    )


def test_revoke_session(
    service,
    store,
    user,
):
    session = (
        service.create_session(
            user=user
        )
    )

    assert service.revoke_session(
        session_id=session.id,
        user=user,
    )

    stored = store.get(
        session.id
    )

    assert stored is not None

    assert (
        stored.revoked_at
        is not None
    )


def test_wrong_user_cannot_revoke(
    service,
    store,
    user,
):
    session = (
        service.create_session(
            user=user
        )
    )

    other = DummyUser(
        id=2,
        auth_id="auth-2",
    )

    assert (
        service.revoke_session(
            session_id=session.id,
            user=other,
        )
        is False
    )

    stored = store.get(
        session.id
    )

    assert stored is not None

    assert (
        stored.revoked_at
        is None
    )


def test_revoke_other_sessions(
    service,
    store,
    user,
):
    current = (
        service.create_session(
            user=user
        )
    )

    other_one = (
        service.create_session(
            user=user
        )
    )

    other_two = (
        service.create_session(
            user=user
        )
    )

    count = (
        service
        .revoke_other_sessions(
            current_session_id=(
                current.id
            ),
            user=user,
        )
    )

    assert count == 2

    current_stored = (
        store.get(
            current.id
        )
    )

    other_one_stored = (
        store.get(
            other_one.id
        )
    )

    other_two_stored = (
        store.get(
            other_two.id
        )
    )

    assert (
        current_stored
        is not None
    )

    assert (
        other_one_stored
        is not None
    )

    assert (
        other_two_stored
        is not None
    )

    assert (
        current_stored
        .revoked_at
        is None
    )

    assert (
        other_one_stored
        .revoked_at
        is not None
    )

    assert (
        other_two_stored
        .revoked_at
        is not None
    )


def test_revoke_all_sessions(
    service,
    store,
    user,
):
    first = (
        service.create_session(
            user=user
        )
    )

    second = (
        service.create_session(
            user=user
        )
    )

    count = (
        service.revoke_all_sessions(
            user=user
        )
    )

    assert count == 2

    first_stored = (
        store.get(
            first.id
        )
    )

    second_stored = (
        store.get(
            second.id
        )
    )

    assert first_stored is not None
    assert second_stored is not None

    assert (
        first_stored.revoked_at
        is not None
    )

    assert (
        second_stored.revoked_at
        is not None
    )


def test_invalid_touch_interval_rejected(
    store,
):
    with pytest.raises(
        ValueError,
        match=(
            "touch_interval_seconds"
        ),
    ):
        SessionService(
            session_store=store,
            touch_interval_seconds=-1,
        )