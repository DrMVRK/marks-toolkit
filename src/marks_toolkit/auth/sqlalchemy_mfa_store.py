from datetime import datetime, timezone

from sqlalchemy import (
    delete,
    or_,
    select,
    update,
)

from .mfa_store import MFAStore
from .sqlalchemy_models import (
    AuthRecoveryCodeModel,
    AuthTotpModel,
)


def _utcnow():
    return datetime.now(
        timezone.utc
    )


class SQLAlchemyMFAStore(MFAStore):
    def __init__(
        self,
        session_factory,
    ):
        self.session_factory = (
            session_factory
        )

    # ============================================================
    # TOTP
    # ============================================================

    def get_totp(
        self,
        user_id,
    ):
        with self.session_factory() as session:
            return session.scalar(
                select(
                    AuthTotpModel
                )
                .where(
                    AuthTotpModel
                        .user_id
                    == user_id
                )
            )

    def create_totp(
        self,
        user_id,
        encrypted_secret,
    ):
        with self.session_factory() as session:
            record = AuthTotpModel(
                user_id=user_id,

                encrypted_secret=(
                    encrypted_secret
                ),

                enabled=False,

                created_at=(
                    _utcnow()
                ),

                last_used_step=None,
            )

            session.add(
                record
            )

            session.commit()

            session.refresh(
                record
            )

            return record

    def enable_totp(
        self,
        user_id,
    ):
        with self.session_factory() as session:
            result = session.execute(
                update(
                    AuthTotpModel
                )
                .where(
                    AuthTotpModel
                        .user_id
                    == user_id
                )
                .values(
                    enabled=True,
                    verified_at=(
                        _utcnow()
                    ),
                )
            )

            session.commit()

            return (
                result.rowcount
                == 1
            )

    def delete_totp(
        self,
        user_id,
    ):
        with self.session_factory() as session:
            session.execute(
                delete(
                    AuthTotpModel
                )
                .where(
                    AuthTotpModel
                        .user_id
                    == user_id
                )
            )

            session.commit()

    def claim_totp_step(
        self,
        user_id,
        step,
    ):
        with self.session_factory() as session:
            result = session.execute(
                update(
                    AuthTotpModel
                )
                .where(
                    AuthTotpModel
                        .user_id
                    == user_id,

                    AuthTotpModel
                        .enabled
                        .is_(True),

                    or_(
                        AuthTotpModel
                            .last_used_step
                            .is_(None),

                        AuthTotpModel
                            .last_used_step
                        < step,
                    ),
                )
                .values(
                    last_used_step=(
                        step
                    )
                )
            )

            session.commit()

            return (
                result.rowcount
                == 1
            )

    # ============================================================
    # RECOVERY CODES
    # ============================================================

    def replace_recovery_codes(
        self,
        user_id,
        code_hashes,
    ):
        with self.session_factory() as session:
            session.execute(
                delete(
                    AuthRecoveryCodeModel
                )
                .where(
                    AuthRecoveryCodeModel
                        .user_id
                    == user_id
                )
            )

            records = []

            for code_hash in code_hashes:
                record = (
                    AuthRecoveryCodeModel(
                        user_id=user_id,

                        code_hash=(
                            code_hash
                        ),

                        used=False,

                        created_at=(
                            _utcnow()
                        ),
                    )
                )

                session.add(
                    record
                )

                records.append(
                    record
                )

            session.commit()

            for record in records:
                session.refresh(
                    record
                )

            return records

    def list_unused_recovery_codes(
        self,
        user_id,
    ):
        with self.session_factory() as session:
            return list(
                session.scalars(
                    select(
                        AuthRecoveryCodeModel
                    )
                    .where(
                        AuthRecoveryCodeModel
                            .user_id
                        == user_id,

                        AuthRecoveryCodeModel
                            .used
                            .is_(False),
                    )
                )
            )

    def mark_recovery_code_used(
        self,
        record,
    ):
        with self.session_factory() as session:
            result = session.execute(
                update(
                    AuthRecoveryCodeModel
                )
                .where(
                    AuthRecoveryCodeModel.id
                    == record.id,

                    AuthRecoveryCodeModel
                        .used
                        .is_(False),
                )
                .values(
                    used=True,

                    used_at=(
                        _utcnow()
                    ),
                )
            )

            session.commit()

            return (
                result.rowcount
                == 1
            )

    def consume_recovery_code(
        self,
        user_id,
        code_hash,
    ):
        with self.session_factory() as session:
            result = session.execute(
                update(
                    AuthRecoveryCodeModel
                )
                .where(
                    AuthRecoveryCodeModel
                        .user_id
                    == user_id,

                    AuthRecoveryCodeModel
                        .code_hash
                    == code_hash,

                    AuthRecoveryCodeModel
                        .used
                        .is_(False),
                )
                .values(
                    used=True,

                    used_at=(
                        _utcnow()
                    ),
                )
            )

            session.commit()

            return (
                result.rowcount
                == 1
            )

    # ============================================================
    # GENERAL MFA
    # ============================================================

    def has_enabled_mfa(
        self,
        user_id,
    ):
        with self.session_factory() as session:
            return (
                session.scalar(
                    select(
                        AuthTotpModel.id
                    )
                    .where(
                        AuthTotpModel
                            .user_id
                        == user_id,

                        AuthTotpModel
                            .enabled
                            .is_(True),
                    )
                    .limit(1)
                )
                is not None
            )