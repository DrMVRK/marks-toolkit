from datetime import datetime, timezone

import pytest

from marks_toolkit.auth.memory_passkey_store import (
    MemoryPasskeyStore,
)
from marks_toolkit.auth.passkey_store import (
    PasskeyCredential,
)


def make_credential(
    *,
    credential_id=b"credential-1",
    user_id="user-1",
    user_handle=b"user-handle-1",
):
    return PasskeyCredential(
        id="passkey-1",
        user_id=user_id,
        user_handle=user_handle,
        credential_id=credential_id,
        public_key=b"public-key",
        sign_count=0,
        name="Test Passkey",
    )

def test_create_and_get_passkey():
    store = MemoryPasskeyStore()

    credential = make_credential()

    store.create(credential)

    stored = store.get_by_credential_id(
        b"credential-1"
    )

    assert stored is credential


def test_duplicate_credential_is_rejected():
    store = MemoryPasskeyStore()

    store.create(
        make_credential()
    )

    with pytest.raises(ValueError):
        store.create(
            make_credential()
        )


def test_list_for_user_only_returns_users_credentials():
    store = MemoryPasskeyStore()

    first = make_credential(
        credential_id=b"credential-1",
        user_id="user-1",
    )

    second = make_credential(
        credential_id=b"credential-2",
        user_id="user-1",
    )

    other = make_credential(
        credential_id=b"credential-3",
        user_id="user-2",
    )

    store.create(first)
    store.create(second)
    store.create(other)

    credentials = store.list_for_user(
        "user-1"
    )

    assert len(credentials) == 2
    assert first in credentials
    assert second in credentials
    assert other not in credentials


def test_update_usage():
    store = MemoryPasskeyStore()

    credential = make_credential()

    store.create(credential)

    last_used_at = datetime.now(
        timezone.utc
    )

    store.update_usage(
        b"credential-1",
        sign_count=8,
        last_used_at=last_used_at,
    )

    stored = store.get_by_credential_id(
        b"credential-1"
    )

    assert stored.sign_count == 8
    assert stored.last_used_at == last_used_at


def test_update_missing_passkey_fails():
    store = MemoryPasskeyStore()

    with pytest.raises(KeyError):
        store.update_usage(
            b"missing",
            sign_count=1,
            last_used_at=datetime.now(
                timezone.utc
            ),
        )


def test_delete_passkey():
    store = MemoryPasskeyStore()

    store.create(
        make_credential()
    )

    deleted = store.delete(
        "user-1",
        b"credential-1",
    )

    assert deleted is True

    assert (
        store.get_by_credential_id(
            b"credential-1"
        )
        is None
    )


def test_user_cannot_delete_another_users_passkey():
    store = MemoryPasskeyStore()

    store.create(
        make_credential(
            user_id="user-1"
        )
    )

    deleted = store.delete(
        "user-2",
        b"credential-1",
    )

    assert deleted is False

    assert (
        store.get_by_credential_id(
            b"credential-1"
        )
        is not None
    )