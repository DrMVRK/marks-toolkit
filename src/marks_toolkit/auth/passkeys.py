import secrets
from time import time

from webauthn import (
    generate_registration_options,
    verify_registration_response,
)
from webauthn.helpers import (
    generate_challenge,
    generate_user_handle,
    options_to_json_dict,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .passkey_store import PasskeyCredential
from .webauthn_challenge_store import (
    WebAuthnChallenge,
)


class PasskeyService:
    def __init__(
        self,
        *,
        passkey_store,
        challenge_store,
        rp_id,
        rp_name,
        origin,
        challenge_ttl=300,
    ):
        self.passkey_store = passkey_store
        self.challenge_store = challenge_store

        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin

        self.challenge_ttl = challenge_ttl

    # ============================================================
    # REGISTRATION — BEGIN
    # ============================================================

    def begin_registration(
        self,
        user,
    ):
        if user is None:
            raise ValueError(
                "A user is required for passkey registration."
            )

        user_id = user.id

        existing_credentials = (
            self.passkey_store.list_for_user(
                user_id
            )
        )

        # --------------------------------------------------------
        # WebAuthn user handle
        # --------------------------------------------------------

        if existing_credentials:
            user_handle = (
                existing_credentials[0]
                .user_handle
            )

            for credential in existing_credentials:
                if (
                    credential.user_handle
                    != user_handle
                ):
                    raise RuntimeError(
                        "Passkey credentials for this user "
                        "do not share the same user handle."
                    )

        else:
            user_handle = (
                generate_user_handle()
            )

        # --------------------------------------------------------
        # Existing credential exclusion
        # --------------------------------------------------------

        exclude_credentials = []

        for credential in existing_credentials:
            transports = []

            for transport in credential.transports:
                try:
                    transports.append(
                        AuthenticatorTransport(
                            transport
                        )
                    )

                except ValueError:
                    # Transport values are browser hints only.
                    # Unknown future values should not prevent
                    # registration.
                    continue

            exclude_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=credential.credential_id,
                    transports=(
                        transports
                        if transports
                        else None
                    ),
                )
            )

        # --------------------------------------------------------
        # Challenge
        # --------------------------------------------------------

        challenge = generate_challenge()

        challenge_id = (
            secrets.token_urlsafe(32)
        )

        self.challenge_store.create(
            WebAuthnChallenge(
                id=challenge_id,
                challenge=challenge,
                ceremony="registration",
                user_id=user_id,
                user_handle=user_handle,
                expires_at=(
                    time()
                    + self.challenge_ttl
                ),
            )
        )

        # --------------------------------------------------------
        # Registration options
        # --------------------------------------------------------

        username = getattr(
            user,
            "username",
            None,
        )

        if not username:
            username = str(user_id)

        display_name = getattr(
            user,
            "username",
            None,
        )

        if not display_name:
            display_name = username

        options = (
            generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_name=username,
                user_id=user_handle,
                user_display_name=display_name,
                challenge=challenge,
                exclude_credentials=(
                    exclude_credentials
                    if exclude_credentials
                    else None
                ),
                authenticator_selection=(
                    AuthenticatorSelectionCriteria(
                        resident_key=(
                            ResidentKeyRequirement.REQUIRED
                        ),
                        require_resident_key=True,
                        user_verification=(
                            UserVerificationRequirement.REQUIRED
                        ),
                    )
                ),
            )
        )

        return {
            "challenge_id": challenge_id,
            "options": options_to_json_dict(
                options
            ),
        }

    # ============================================================
    # REGISTRATION — FINISH
    # ============================================================

    def finish_registration(
        self,
        *,
        user,
        challenge_id,
        credential,
        name=None,
    ):
        if user is None:
            raise ValueError(
                "A user is required for passkey registration."
            )

        if (
            not isinstance(challenge_id, str)
            or not challenge_id
        ):
            raise ValueError(
                "A valid WebAuthn challenge ID is required."
            )

        # --------------------------------------------------------
        # Consume challenge atomically
        # --------------------------------------------------------

        challenge = (
            self.challenge_store.consume(
                challenge_id
            )
        )

        if challenge is None:
            raise ValueError(
                "WebAuthn challenge is invalid or expired."
            )

        # From this point forward the challenge is gone,
        # even if verification fails. This prevents replay.

        if challenge.ceremony != "registration":
            raise ValueError(
                "WebAuthn challenge has the wrong ceremony type."
            )

        if challenge.user_id != user.id:
            raise ValueError(
                "WebAuthn challenge does not belong to this user."
            )

        if challenge.user_handle is None:
            raise RuntimeError(
                "WebAuthn registration challenge "
                "has no user handle."
            )

        # --------------------------------------------------------
        # Parse browser credential
        # --------------------------------------------------------

        parsed_credential = (
            parse_registration_credential_json(
                credential
            )
        )

        # --------------------------------------------------------
        # Cryptographic WebAuthn verification
        # --------------------------------------------------------

        verification = (
            verify_registration_response(
                credential=parsed_credential,
                expected_challenge=(
                    challenge.challenge
                ),
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                require_user_presence=True,
                require_user_verification=True,
            )
        )

        # --------------------------------------------------------
        # Defensive credential consistency check
        # --------------------------------------------------------

        if (
            parsed_credential.raw_id
            != verification.credential_id
        ):
            raise ValueError(
                "Verified WebAuthn credential ID "
                "does not match the submitted credential."
            )

        if not verification.user_verified:
            raise ValueError(
                "WebAuthn user verification was not completed."
            )

        # --------------------------------------------------------
        # Transport metadata
        # --------------------------------------------------------

        transports = ()

        if (
            parsed_credential.response.transports
            is not None
        ):
            transports = tuple(
                transport.value
                for transport
                in parsed_credential.response.transports
            )

        # --------------------------------------------------------
        # Persist credential
        # --------------------------------------------------------

        passkey = PasskeyCredential(
            id=None,
            user_id=user.id,
            user_handle=(
                challenge.user_handle
            ),
            credential_id=(
                verification.credential_id
            ),
            public_key=(
                verification.credential_public_key
            ),
            sign_count=(
                verification.sign_count
            ),
            name=name,
            transports=transports,
        )

        return self.passkey_store.create(
            passkey
        )