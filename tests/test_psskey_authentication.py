from types import SimpleNamespace

import pytest

from marks_toolkit.auth.memory_passkey_store import (
    MemoryPasskeyStore,
)
from marks_toolkit.auth.passkey_store import (
    PasskeyCredential,
)
from marks_toolkit.auth.passkeys import (
    PasskeyService,
)
from marks_toolkit.auth.webauthn_challenge_store import (
    MemoryWebAuthnChallengeStore,
)


# ============================================================
# HELPERS
# ============================================================

CREDENTIAL_ID = b"credential-id-123"
USER_HANDLE = b"user-handle-123"
PUBLIC_KEY = b"public-key-123"


def make_service():
    passkey_store = MemoryPasskeyStore()

    challenge_store = (
        MemoryWebAuthnChallengeStore()
    )

    service = PasskeyService(
        passkey_store=passkey_store,
        challenge_store=challenge_store,
        rp_id="localhost",
        rp_name="MARKS Toolkit Test",
        origin="http://localhost:5173",
        challenge_ttl=300,
    )

    return (
        service,
        passkey_store,
        challenge_store,
    )


def add_passkey(
    passkey_store,
    *,
    user_id=1,
    sign_count=0,
):
    credential = PasskeyCredential(
        id=None,
        user_id=user_id,
        user_handle=USER_HANDLE,
        credential_id=CREDENTIAL_ID,
        public_key=PUBLIC_KEY,
        sign_count=sign_count,
        name="Test Passkey",
        transports=("internal",),
    )

    return passkey_store.create(
        credential
    )


def make_parsed_credential(
    *,
    credential_id=CREDENTIAL_ID,
    user_handle=USER_HANDLE,
):
    return SimpleNamespace(
        raw_id=credential_id,
        response=SimpleNamespace(
            user_handle=user_handle,
        ),
    )


def make_verification(
    *,
    credential_id=CREDENTIAL_ID,
    new_sign_count=0,
    user_verified=True,
):
    return SimpleNamespace(
        credential_id=credential_id,
        new_sign_count=new_sign_count,
        user_verified=user_verified,
    )


# ============================================================
# BEGIN AUTHENTICATION
# ============================================================

def test_begin_authentication_returns_options():
    service, _, challenge_store = (
        make_service()
    )

    result = service.begin_authentication()

    assert isinstance(
        result["challenge_id"],
        str,
    )

    assert result["challenge_id"]

    assert isinstance(
        result["options"],
        dict,
    )

    stored_challenge = (
        challenge_store.consume(
            result["challenge_id"]
        )
    )

    assert stored_challenge is not None

    assert (
        stored_challenge.ceremony
        == "authentication"
    )

    assert stored_challenge.user_id is None
    assert stored_challenge.user_handle is None


# ============================================================
# SUCCESSFUL AUTHENTICATION
# ============================================================

def test_successful_authentication_returns_user_id(
    monkeypatch,
):
    service, passkey_store, _ = (
        make_service()
    )

    add_passkey(
        passkey_store,
        user_id=42,
    )

    result = service.begin_authentication()

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "parse_authentication_credential_json",
        lambda credential:
            make_parsed_credential(),
    )

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "verify_authentication_response",
        lambda **kwargs:
            make_verification(
                new_sign_count=0,
            ),
    )

    user_id = (
        service.finish_authentication(
            challenge_id=(
                result["challenge_id"]
            ),
            credential={},
        )
    )

    assert user_id == 42


# ============================================================
# SINGLE-USE CHALLENGE
# ============================================================

def test_authentication_challenge_is_single_use(
    monkeypatch,
):
    service, passkey_store, _ = (
        make_service()
    )

    add_passkey(
        passkey_store
    )

    result = service.begin_authentication()

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "parse_authentication_credential_json",
        lambda credential:
            make_parsed_credential(),
    )

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "verify_authentication_response",
        lambda **kwargs:
            make_verification(),
    )

    service.finish_authentication(
        challenge_id=result["challenge_id"],
        credential={},
    )

    with pytest.raises(
        ValueError,
        match="invalid or expired",
    ):
        service.finish_authentication(
            challenge_id=(
                result["challenge_id"]
            ),
            credential={},
        )


# ============================================================
# UNKNOWN CREDENTIAL
# ============================================================

def test_unknown_passkey_is_rejected(
    monkeypatch,
):
    service, _, _ = make_service()

    result = service.begin_authentication()

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "parse_authentication_credential_json",
        lambda credential:
            make_parsed_credential(
                credential_id=(
                    b"unknown-credential"
                )
            ),
    )

    with pytest.raises(
        ValueError,
        match="not recognized",
    ):
        service.finish_authentication(
            challenge_id=(
                result["challenge_id"]
            ),
            credential={},
        )


# ============================================================
# USER HANDLE
# ============================================================

def test_mismatched_user_handle_is_rejected(
    monkeypatch,
):
    service, passkey_store, _ = (
        make_service()
    )

    add_passkey(
        passkey_store
    )

    result = service.begin_authentication()

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "parse_authentication_credential_json",
        lambda credential:
            make_parsed_credential(
                user_handle=(
                    b"wrong-user-handle"
                )
            ),
    )

    with pytest.raises(
        ValueError,
        match="user handle",
    ):
        service.finish_authentication(
            challenge_id=(
                result["challenge_id"]
            ),
            credential={},
        )


# ============================================================
# FAILED VERIFICATION BURNS CHALLENGE
# ============================================================

def test_failed_verification_burns_challenge(
    monkeypatch,
):
    service, passkey_store, _ = (
        make_service()
    )

    add_passkey(
        passkey_store
    )

    result = service.begin_authentication()

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "parse_authentication_credential_json",
        lambda credential:
            make_parsed_credential(),
    )

    def fail_verification(**kwargs):
        raise ValueError(
            "verification failed"
        )

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "verify_authentication_response",
        fail_verification,
    )

    with pytest.raises(
        ValueError,
        match="verification failed",
    ):
        service.finish_authentication(
            challenge_id=(
                result["challenge_id"]
            ),
            credential={},
        )

    with pytest.raises(
        ValueError,
        match="invalid or expired",
    ):
        service.finish_authentication(
            challenge_id=(
                result["challenge_id"]
            ),
            credential={},
        )


# ============================================================
# USAGE UPDATE
# ============================================================

def test_successful_authentication_updates_usage(
    monkeypatch,
):
    service, passkey_store, _ = (
        make_service()
    )

    add_passkey(
        passkey_store,
        sign_count=3,
    )

    result = service.begin_authentication()

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "parse_authentication_credential_json",
        lambda credential:
            make_parsed_credential(),
    )

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "verify_authentication_response",
        lambda **kwargs:
            make_verification(
                new_sign_count=4,
            ),
    )

    service.finish_authentication(
        challenge_id=result["challenge_id"],
        credential={},
    )

    stored = (
        passkey_store
        .get_by_credential_id(
            CREDENTIAL_ID
        )
    )

    assert stored is not None
    assert stored.sign_count == 4
    assert stored.last_used_at is not None


# ============================================================
# SYNCED / ZERO COUNTER PASSKEYS
# ============================================================

def test_zero_counter_passkey_is_allowed(
    monkeypatch,
):
    service, passkey_store, _ = (
        make_service()
    )

    add_passkey(
        passkey_store,
        sign_count=0,
    )

    result = service.begin_authentication()

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "parse_authentication_credential_json",
        lambda credential:
            make_parsed_credential(),
    )

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "verify_authentication_response",
        lambda **kwargs:
            make_verification(
                new_sign_count=0,
            ),
    )

    user_id = (
        service.finish_authentication(
            challenge_id=(
                result["challenge_id"]
            ),
            credential={},
        )
    )

    assert user_id == 1


# ============================================================
# COUNTER REGRESSION
# ============================================================

def test_nonzero_counter_must_advance(
    monkeypatch,
):
    service, passkey_store, _ = (
        make_service()
    )

    add_passkey(
        passkey_store,
        sign_count=5,
    )

    result = service.begin_authentication()

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "parse_authentication_credential_json",
        lambda credential:
            make_parsed_credential(),
    )

    monkeypatch.setattr(
        "marks_toolkit.auth.passkeys."
        "verify_authentication_response",
        lambda **kwargs:
            make_verification(
                new_sign_count=5,
            ),
    )

    with pytest.raises(
        ValueError,
        match="counter did not advance",
    ):
        service.finish_authentication(
            challenge_id=(
                result["challenge_id"]
            ),
            credential={},
        )