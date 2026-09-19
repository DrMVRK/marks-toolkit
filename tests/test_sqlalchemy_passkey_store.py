from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from marks_toolkit.auth.passkey_store import PasskeyCredential
from marks_toolkit.auth.sqlalchemy_models import AuthBase, AuthUserModel
from marks_toolkit.auth.sqlalchemy_passkey_store import (
    SQLAlchemyPasskeyStore,
)


@pytest.fixture
def session_factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
    )

    AuthBase.metadata.create_all(engine)

    return sessionmaker(
        bind=engine,
        expire_on_commit=False,
    )


@pytest.fixture
def user_id(session_factory):
    with session_factory() as session:
        user = AuthUserModel(
            auth_id="auth-1",
            email="mark@example.com",
            email_key="mark@example.com",
            username="Mark",
            username_key="mark",
            password_hash="hash",
            active=True,
        )

        session.add(user)
        session.commit()
        session.refresh(user)

        return user.id


def make_credential(
    *,
    credential_id=b"credential-1",
    user_id=1,
    user_handle=b"user-handle-1",
):
    return PasskeyCredential(
        id=None,
        user_id=user_id,
        user_handle=user_handle,
        credential_id=credential_id,
        public_key=b"public-key",
        sign_count=0,
        name="MacBook Air",
        transports=("internal",),
    )


def test_create_and_get_passkey(
    session_factory,
    user_id,
):
    store = SQLAlchemyPasskeyStore(
        session_factory
    )

    created = store.create(
        make_credential(
            user_id=user_id
        )
    )

    assert created.id is not None
    assert created.user_id == user_id
    assert created.name == "MacBook Air"
    assert created.transports == (
        "internal",
    )

    stored = store.get_by_credential_id(
        b"credential-1"
    )

    assert stored is not None
    assert stored.id == created.id
    assert stored.user_handle == b"user-handle-1"
    assert stored.public_key == b"public-key"


def test_duplicate_credential_is_rejected(
    session_factory,
    user_id,
):
    store = SQLAlchemyPasskeyStore(
        session_factory
    )

    store.create(
        make_credential(
            user_id=user_id
        )
    )

    with pytest.raises(ValueError):
        store.create(
            make_credential(
                user_id=user_id
            )
        )


def test_list_for_user_only_returns_users_credentials(
    session_factory,
):
    with session_factory() as session:
        first_user = AuthUserModel(
            auth_id="auth-1",
            email="one@example.com",
            email_key="one@example.com",
            username="One",
            username_key="one",
            password_hash="hash",
            active=True,
        )

        second_user = AuthUserModel(
            auth_id="auth-2",
            email="two@example.com",
            email_key="two@example.com",
            username="Two",
            username_key="two",
            password_hash="hash",
            active=True,
        )

        session.add_all([
            first_user,
            second_user,
        ])

        session.commit()

        first_user_id = first_user.id
        second_user_id = second_user.id

    store = SQLAlchemyPasskeyStore(
        session_factory
    )

    store.create(
        make_credential(
            credential_id=b"credential-1",
            user_id=first_user_id,
        )
    )

    store.create(
        make_credential(
            credential_id=b"credential-2",
            user_id=first_user_id,
        )
    )

    store.create(
        make_credential(
            credential_id=b"credential-3",
            user_id=second_user_id,
        )
    )

    credentials = store.list_for_user(
        first_user_id
    )

    assert len(credentials) == 2

    credential_ids = {
        credential.credential_id
        for credential in credentials
    }

    assert credential_ids == {
        b"credential-1",
        b"credential-2",
    }


def test_update_usage(
    session_factory,
    user_id,
):
    store = SQLAlchemyPasskeyStore(
        session_factory
    )

    store.create(
        make_credential(
            user_id=user_id
        )
    )

    last_used_at = datetime.now(
        timezone.utc
    )

    store.update_usage(
        b"credential-1",
        sign_count=7,
        last_used_at=last_used_at,
    )

    stored = store.get_by_credential_id(
        b"credential-1"
    )

    assert stored is not None
    assert stored.sign_count == 7
    assert stored.last_used_at is not None


def test_update_missing_passkey_fails(
    session_factory,
):
    store = SQLAlchemyPasskeyStore(
        session_factory
    )

    with pytest.raises(KeyError):
        store.update_usage(
            b"missing",
            sign_count=1,
            last_used_at=datetime.now(
                timezone.utc
            ),
        )


def test_delete_passkey(
    session_factory,
    user_id,
):
    store = SQLAlchemyPasskeyStore(
        session_factory
    )

    store.create(
        make_credential(
            user_id=user_id
        )
    )

    deleted = store.delete(
        user_id,
        b"credential-1",
    )

    assert deleted is True

    assert (
        store.get_by_credential_id(
            b"credential-1"
        )
        is None
    )


def test_user_cannot_delete_another_users_passkey(
    session_factory,
):
    with session_factory() as session:
        first_user = AuthUserModel(
            auth_id="auth-1",
            email="one@example.com",
            email_key="one@example.com",
            username="One",
            username_key="one",
            password_hash="hash",
            active=True,
        )

        second_user = AuthUserModel(
            auth_id="auth-2",
            email="two@example.com",
            email_key="two@example.com",
            username="Two",
            username_key="two",
            password_hash="hash",
            active=True,
        )

        session.add_all([
            first_user,
            second_user,
        ])

        session.commit()

        first_user_id = first_user.id
        second_user_id = second_user.id

    store = SQLAlchemyPasskeyStore(
        session_factory
    )

    store.create(
        make_credential(
            user_id=first_user_id
        )
    )

    deleted = store.delete(
        second_user_id,
        b"credential-1",
    )

    assert deleted is False

    assert (
        store.get_by_credential_id(
            b"credential-1"
        )
        is not None
    )