from dataclasses import dataclass

from marks_toolkit.auth.memory_passkey_store import (
    MemoryPasskeyStore,
)
from marks_toolkit.auth.passkeys import (
    PasskeyService,
)
from marks_toolkit.auth.passkey_store import (
    PasskeyCredential,
)
from marks_toolkit.auth.webauthn_challenge_store import (
    MemoryWebAuthnChallengeStore,
)

from types import SimpleNamespace

import pytest

import marks_toolkit.auth.passkeys as passkeys_module

from webauthn.helpers.structs import (
    AuthenticatorAttestationResponse,
    AuthenticatorTransport,
    PublicKeyCredentialType,
    RegistrationCredential,
)


@dataclass
class DummyUser:
    id: int
    username: str


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


def test_begin_registration_returns_options():
    (
        service,
        _,
        challenge_store,
    ) = make_service()

    user = DummyUser(
        id=1,
        username="Mark",
    )

    result = service.begin_registration(
        user
    )

    assert "challenge_id" in result
    assert "options" in result

    options = result["options"]

    assert options["rp"]["id"] == "localhost"
    assert options["rp"]["name"] == (
        "MARKS Toolkit Test"
    )

    assert options["user"]["name"] == "Mark"

    challenge = challenge_store.consume(
        result["challenge_id"]
    )

    assert challenge is not None
    assert challenge.ceremony == (
        "registration"
    )
    assert challenge.user_id == 1
    assert challenge.user_handle is not None


def test_first_registration_generates_user_handle():
    (
        service,
        _,
        challenge_store,
    ) = make_service()

    user = DummyUser(
        id=1,
        username="Mark",
    )

    result = service.begin_registration(
        user
    )

    challenge = challenge_store.consume(
        result["challenge_id"]
    )

    assert challenge is not None

    assert isinstance(
        challenge.user_handle,
        bytes,
    )

    assert len(
        challenge.user_handle
    ) > 0


def test_existing_passkey_reuses_user_handle():
    (
        service,
        passkey_store,
        challenge_store,
    ) = make_service()

    existing_handle = (
        b"existing-user-handle"
    )

    passkey_store.create(
        PasskeyCredential(
            id="passkey-1",
            user_id=1,
            user_handle=existing_handle,
            credential_id=b"credential-1",
            public_key=b"public-key",
            sign_count=0,
            name="Existing passkey",
            transports=("internal",),
        )
    )

    user = DummyUser(
        id=1,
        username="Mark",
    )

    result = service.begin_registration(
        user
    )

    challenge = challenge_store.consume(
        result["challenge_id"]
    )

    assert challenge is not None

    assert (
        challenge.user_handle
        == existing_handle
    )


def test_existing_passkey_is_excluded():
    (
        service,
        passkey_store,
        _,
    ) = make_service()

    passkey_store.create(
        PasskeyCredential(
            id="passkey-1",
            user_id=1,
            user_handle=(
                b"existing-user-handle"
            ),
            credential_id=(
                b"credential-1"
            ),
            public_key=b"public-key",
            sign_count=0,
            name="Existing passkey",
            transports=("internal",),
        )
    )

    user = DummyUser(
        id=1,
        username="Mark",
    )

    result = service.begin_registration(
        user
    )

    exclude_credentials = (
        result["options"]
        ["excludeCredentials"]
    )

    assert len(
        exclude_credentials
    ) == 1


def test_inconsistent_user_handles_fail_closed():
    (
        service,
        passkey_store,
        _,
    ) = make_service()

    passkey_store.create(
        PasskeyCredential(
            id="passkey-1",
            user_id=1,
            user_handle=b"handle-1",
            credential_id=b"credential-1",
            public_key=b"public-key-1",
            sign_count=0,
        )
    )

    passkey_store.create(
        PasskeyCredential(
            id="passkey-2",
            user_id=1,
            user_handle=b"handle-2",
            credential_id=b"credential-2",
            public_key=b"public-key-2",
            sign_count=0,
        )
    )

    user = DummyUser(
        id=1,
        username="Mark",
    )

    try:
        service.begin_registration(
            user
        )

    except RuntimeError:
        pass

    else:
        raise AssertionError(
            "Expected inconsistent user handles "
            "to be rejected."
        )

def make_registration_credential():
    return RegistrationCredential(
        id="credential-id",
        raw_id=b"credential-id",
        response=(
            AuthenticatorAttestationResponse(
                client_data_json=b"client-data",
                attestation_object=b"attestation",
                transports=[
                    AuthenticatorTransport.INTERNAL
                ],
            )
        ),
        authenticator_attachment=None,
        type=PublicKeyCredentialType.PUBLIC_KEY,
    )

def test_finish_registration_stores_passkey(
    monkeypatch,
):
    (
        service,
        passkey_store,
        _,
    ) = make_service()

    user = DummyUser(
        id=1,
        username="Mark",
    )

    registration = (
        service.begin_registration(
            user
        )
    )

    credential = (
        make_registration_credential()
    )

    monkeypatch.setattr(
        passkeys_module,
        "parse_registration_credential_json",
        lambda value: credential,
    )

    monkeypatch.setattr(
        passkeys_module,
        "verify_registration_response",
        lambda **kwargs: SimpleNamespace(
            credential_id=b"credential-id",
            credential_public_key=(
                b"public-key"
            ),
            sign_count=5,
            user_verified=True,
        ),
    )

    stored = service.finish_registration(
        user=user,
        challenge_id=(
            registration["challenge_id"]
        ),
        credential={},
        name="MacBook Air",
    )

    assert stored.user_id == 1
    assert (
        stored.credential_id
        == b"credential-id"
    )
    assert stored.public_key == (
        b"public-key"
    )
    assert stored.sign_count == 5
    assert stored.name == "MacBook Air"
    assert stored.transports == (
        "internal",
    )

    persisted = (
        passkey_store
        .get_by_credential_id(
            b"credential-id"
        )
    )

    assert persisted is not None

def test_registration_challenge_is_single_use(
    monkeypatch,
):
    (
        service,
        _,
        _,
    ) = make_service()

    user = DummyUser(
        id=1,
        username="Mark",
    )

    registration = (
        service.begin_registration(
            user
        )
    )

    credential = (
        make_registration_credential()
    )

    monkeypatch.setattr(
        passkeys_module,
        "parse_registration_credential_json",
        lambda value: credential,
    )

    monkeypatch.setattr(
        passkeys_module,
        "verify_registration_response",
        lambda **kwargs: SimpleNamespace(
            credential_id=b"credential-id",
            credential_public_key=(
                b"public-key"
            ),
            sign_count=0,
            user_verified=True,
        ),
    )

    service.finish_registration(
        user=user,
        challenge_id=(
            registration["challenge_id"]
        ),
        credential={},
    )

    with pytest.raises(
        ValueError,
        match="invalid or expired",
    ):
        service.finish_registration(
            user=user,
            challenge_id=(
                registration["challenge_id"]
            ),
            credential={},
        )

def test_registration_challenge_is_bound_to_user():
    (
        service,
        _,
        _,
    ) = make_service()

    first_user = DummyUser(
        id=1,
        username="Mark",
    )

    second_user = DummyUser(
        id=2,
        username="Other",
    )

    registration = (
        service.begin_registration(
            first_user
        )
    )

    with pytest.raises(
        ValueError,
        match="does not belong",
    ):
        service.finish_registration(
            user=second_user,
            challenge_id=(
                registration["challenge_id"]
            ),
            credential={},
        )

def test_failed_registration_burns_challenge(
    monkeypatch,
):
    (
        service,
        _,
        _,
    ) = make_service()

    user = DummyUser(
        id=1,
        username="Mark",
    )

    registration = (
        service.begin_registration(
            user
        )
    )

    credential = (
        make_registration_credential()
    )

    monkeypatch.setattr(
        passkeys_module,
        "parse_registration_credential_json",
        lambda value: credential,
    )

    def fail_verification(**kwargs):
        raise ValueError(
            "Invalid WebAuthn response"
        )

    monkeypatch.setattr(
        passkeys_module,
        "verify_registration_response",
        fail_verification,
    )

    with pytest.raises(ValueError):
        service.finish_registration(
            user=user,
            challenge_id=(
                registration["challenge_id"]
            ),
            credential={},
        )

    with pytest.raises(
        ValueError,
        match="invalid or expired",
    ):
        service.finish_registration(
            user=user,
            challenge_id=(
                registration["challenge_id"]
            ),
            credential={},
        )