from datetime import datetime, timezone

from sqlalchemy import delete, select

from .mfa_store import MFAStore
from .sqlalchemy_models import (
    AuthPasskeyModel,
    AuthRecoveryCodeModel,
    AuthTotpModel,
)


class SQLAlchemyMFAStore(MFAStore):

    def __init__(self, session_factory):
        self.session_factory = session_factory

    # -------------------------
    # TOTP
    # -------------------------

    def get_totp(self, user_id):
        with self.session_factory() as session:
            statement = select(
                AuthTotpModel
            ).where(
                AuthTotpModel.user_id == user_id
            )

            return session.scalar(statement)

    def create_totp(
        self,
        user_id,
        encrypted_secret,
    ):
        totp = AuthTotpModel(
            user_id=user_id,
            encrypted_secret=encrypted_secret,
            enabled=False,
        )

        with self.session_factory() as session:
            session.add(totp)
            session.commit()
            session.refresh(totp)

            return totp

    def enable_totp(self, user_id):
        with self.session_factory() as session:
            statement = select(
                AuthTotpModel
            ).where(
                AuthTotpModel.user_id == user_id
            )

            totp = session.scalar(statement)

            if totp is None:
                raise RuntimeError(
                    "TOTP configuration does not exist."
                )

            totp.enabled = True
            totp.verified_at = datetime.now(
                timezone.utc
            )

            session.commit()

            return True

    def delete_totp(self, user_id):
        with self.session_factory() as session:
            statement = delete(
                AuthTotpModel
            ).where(
                AuthTotpModel.user_id == user_id
            )

            session.execute(statement)
            session.commit()

    # -------------------------
    # Passkeys
    # -------------------------

    def list_passkeys(self, user_id):
        with self.session_factory() as session:
            statement = select(
                AuthPasskeyModel
            ).where(
                AuthPasskeyModel.user_id == user_id
            )

            return list(
                session.scalars(statement)
            )

    def find_passkey_by_credential_id(
        self,
        credential_id,
    ):
        with self.session_factory() as session:
            statement = select(
                AuthPasskeyModel
            ).where(
                AuthPasskeyModel.credential_id
                == credential_id
            )

            return session.scalar(statement)

    def create_passkey(
        self,
        user_id,
        credential_id,
        public_key,
        sign_count,
        name=None,
    ):
        passkey = AuthPasskeyModel(
            user_id=user_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            name=name,
        )

        with self.session_factory() as session:
            session.add(passkey)
            session.commit()
            session.refresh(passkey)

            return passkey

    def update_passkey_sign_count(
        self,
        passkey,
        sign_count,
    ):
        with self.session_factory() as session:
            stored_passkey = session.get(
                AuthPasskeyModel,
                passkey.id,
            )

            if stored_passkey is None:
                raise RuntimeError(
                    "Passkey no longer exists."
                )

            stored_passkey.sign_count = sign_count
            stored_passkey.last_used_at = (
                datetime.now(timezone.utc)
            )

            session.commit()

            passkey.sign_count = sign_count
            passkey.last_used_at = (
                stored_passkey.last_used_at
            )

    def delete_passkey(
        self,
        user_id,
        passkey_id,
    ):
        with self.session_factory() as session:
            statement = delete(
                AuthPasskeyModel
            ).where(
                AuthPasskeyModel.id == passkey_id,
                AuthPasskeyModel.user_id == user_id,
            )

            session.execute(statement)
            session.commit()

    # -------------------------
    # Recovery codes
    # -------------------------

    def replace_recovery_codes(
        self,
        user_id,
        code_hashes,
    ):
        with self.session_factory() as session:
            delete_statement = delete(
                AuthRecoveryCodeModel
            ).where(
                AuthRecoveryCodeModel.user_id
                == user_id
            )

            session.execute(delete_statement)

            for code_hash in code_hashes:
                session.add(
                    AuthRecoveryCodeModel(
                        user_id=user_id,
                        code_hash=code_hash,
                        used=False,
                    )
                )

            session.commit()

    def list_unused_recovery_codes(
        self,
        user_id,
    ):
        with self.session_factory() as session:
            statement = select(
                AuthRecoveryCodeModel
            ).where(
                AuthRecoveryCodeModel.user_id
                == user_id,
                AuthRecoveryCodeModel.used
                == False,
            )

            return list(
                session.scalars(statement)
            )

    def mark_recovery_code_used(
        self,
        recovery_code,
    ):
        with self.session_factory() as session:
            stored_code = session.get(
                AuthRecoveryCodeModel,
                recovery_code.id,
            )

            if stored_code is None:
                raise RuntimeError(
                    "Recovery code no longer exists."
                )

            stored_code.used = True
            stored_code.used_at = datetime.now(
                timezone.utc
            )

            session.commit()

            recovery_code.used = True
            recovery_code.used_at = (
                stored_code.used_at
            )

    # -------------------------
    # Account MFA status
    # -------------------------

    def has_enabled_mfa(self, user_id):
        with self.session_factory() as session:
            totp_statement = select(
                AuthTotpModel.id
            ).where(
                AuthTotpModel.user_id == user_id,
                AuthTotpModel.enabled == True,
            )

            if session.scalar(
                totp_statement
            ) is not None:
                return True

            passkey_statement = select(
                AuthPasskeyModel.id
            ).where(
                AuthPasskeyModel.user_id == user_id
            ).limit(1)

            return (
                session.scalar(
                    passkey_statement
                )
                is not None
            )