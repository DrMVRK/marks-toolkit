import secrets
from datetime import datetime, timezone
from time import time

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    generate_challenge,
    generate_user_handle,
    options_to_json_dict,
    parse_authentication_credential_json,
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

        challenge = (
            self.challenge_store.consume(
                challenge_id
            )
        )

        if challenge is None:
            raise ValueError(
                "WebAuthn challenge is invalid or expired."
            )

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

        parsed_credential = (
            parse_registration_credential_json(
                credential
            )
        )

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

    # ============================================================
    # AUTHENTICATION — BEGIN
    # ============================================================

    def begin_authentication(
        self,
    ):
        challenge = generate_challenge()

        challenge_id = (
            secrets.token_urlsafe(32)
        )

        self.challenge_store.create(
            WebAuthnChallenge(
                id=challenge_id,
                challenge=challenge,
                ceremony="authentication",
                user_id=None,
                user_handle=None,
                expires_at=(
                    time()
                    + self.challenge_ttl
                ),
            )
        )

        options = (
            generate_authentication_options(
                rp_id=self.rp_id,
                challenge=challenge,

                # Intentionally omit allow_credentials.
                # This enables discoverable credentials
                # and conditional/passkey-first login.
                allow_credentials=None,

                user_verification=(
                    UserVerificationRequirement.REQUIRED
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
    # AUTHENTICATION — FINISH
    # ============================================================

    def finish_authentication(
        self,
        *,
        challenge_id,
        credential,
    ):
        if (
            not isinstance(challenge_id, str)
            or not challenge_id
        ):
            raise ValueError(
                "A valid WebAuthn challenge ID is required."
            )

        challenge = (
            self.challenge_store.consume(
                challenge_id
            )
        )

        if challenge is None:
            raise ValueError(
                "WebAuthn challenge is invalid or expired."
            )

        if (
            challenge.ceremony
            != "authentication"
        ):
            raise ValueError(
                "WebAuthn challenge has the wrong ceremony type."
            )

        parsed_credential = (
            parse_authentication_credential_json(
                credential
            )
        )

        stored_credential = (
            self.passkey_store
            .get_by_credential_id(
                parsed_credential.raw_id
            )
        )

        if stored_credential is None:
            raise ValueError(
                "Passkey credential is not recognized."
            )

        if (
            parsed_credential.response.user_handle
            is not None
            and parsed_credential.response.user_handle
            != stored_credential.user_handle
        ):
            raise ValueError(
                "WebAuthn user handle does not "
                "match the stored credential."
            )

        verification = (
            verify_authentication_response(
                credential=parsed_credential,
                expected_challenge=(
                    challenge.challenge
                ),
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=(
                    stored_credential.public_key
                ),
                credential_current_sign_count=(
                    stored_credential.sign_count
                ),
                require_user_verification=True,
            )
        )

        if (
            verification.credential_id
            != stored_credential.credential_id
        ):
            raise ValueError(
                "Verified WebAuthn credential ID "
                "does not match the stored credential."
            )

        if not verification.user_verified:
            raise ValueError(
                "WebAuthn user verification was not completed."
            )

        new_sign_count = (
            verification.new_sign_count
        )

        current_sign_count = (
            stored_credential.sign_count
        )

        # A sign count of zero is valid for many synced
        # multi-device passkeys. Do not reject zero-counter
        # authenticators purely because they remain zero.
        #
        # If both counters are non-zero and the new value
        # regresses, fail closed because that can indicate
        # cloned credential state.
        if (
            current_sign_count > 0
            and new_sign_count > 0
            and new_sign_count
            <= current_sign_count
        ):
            raise ValueError(
                "Passkey signature counter did not advance."
            )

        self.passkey_store.update_usage(
            stored_credential.credential_id,
            sign_count=new_sign_count,
            last_used_at=(
                datetime.now(
                    timezone.utc
                )
            ),
        )

        return stored_credential.user_id