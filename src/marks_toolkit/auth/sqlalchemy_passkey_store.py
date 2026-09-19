from datetime import datetime

from sqlalchemy import (
    delete,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError

from .passkey_store import (
    PasskeyCredential,
    PasskeyStore,
)
from .sqlalchemy_models import (
    AuthPasskeyModel,
)


class SQLAlchemyPasskeyStore(PasskeyStore):
    def __init__(
        self,
        session_factory,
    ):
        self.session_factory = (
            session_factory
        )

    # ============================================================
    # CONVERSION
    # ============================================================

    def _to_credential(
        self,
        model: AuthPasskeyModel,
    ) -> PasskeyCredential:
        return PasskeyCredential(
            id=model.id,
            user_id=model.user_id,
            user_handle=model.user_handle,
            credential_id=(
                model.credential_id
            ),
            public_key=model.public_key,
            sign_count=model.sign_count,
            name=model.name,
            transports=tuple(
                model.transports or []
            ),
            created_at=model.created_at,
            last_used_at=(
                model.last_used_at
            ),
        )

    # ============================================================
    # CREATE
    # ============================================================

    def create(
        self,
        credential: PasskeyCredential,
    ) -> PasskeyCredential:
        if not isinstance(
            credential,
            PasskeyCredential,
        ):
            raise TypeError(
                "credential must be a "
                "PasskeyCredential"
            )

        if not isinstance(
            credential.credential_id,
            bytes,
        ):
            raise TypeError(
                "credential_id must be bytes"
            )

        model = AuthPasskeyModel(
            user_id=credential.user_id,
            user_handle=(
                credential.user_handle
            ),
            credential_id=(
                credential.credential_id
            ),
            public_key=(
                credential.public_key
            ),
            sign_count=(
                credential.sign_count
            ),
            name=credential.name,
            transports=list(
                credential.transports
            ),
            created_at=(
                credential.created_at
            ),
            last_used_at=(
                credential.last_used_at
            ),
        )

        with self.session_factory() as session:
            session.add(model)

            try:
                session.commit()

            except IntegrityError as error:
                session.rollback()

                raise ValueError(
                    "Passkey credential "
                    "already exists."
                ) from error

            session.refresh(
                model
            )

            return self._to_credential(
                model
            )

    # ============================================================
    # LOOKUP
    # ============================================================

    def get_by_credential_id(
        self,
        credential_id: bytes,
    ) -> PasskeyCredential | None:
        if not isinstance(
            credential_id,
            bytes,
        ):
            return None

        with self.session_factory() as session:
            statement = (
                select(
                    AuthPasskeyModel
                )
                .where(
                    AuthPasskeyModel
                        .credential_id
                    == credential_id
                )
            )

            model = session.scalar(
                statement
            )

            if model is None:
                return None

            return self._to_credential(
                model
            )

    def list_for_user(
        self,
        user_id: int | str,
    ) -> list[PasskeyCredential]:
        with self.session_factory() as session:
            statement = (
                select(
                    AuthPasskeyModel
                )
                .where(
                    AuthPasskeyModel
                        .user_id
                    == user_id
                )
                .order_by(
                    AuthPasskeyModel
                        .created_at,
                    AuthPasskeyModel.id,
                )
            )

            models = session.scalars(
                statement
            ).all()

            return [
                self._to_credential(
                    model
                )
                for model in models
            ]

    # ============================================================
    # NAME UPDATE
    # ============================================================

    def update_name(
        self,
        user_id: int | str,
        credential_id: bytes,
        *,
        name: str | None,
    ) -> bool:
        with self.session_factory() as session:
            statement = (
                update(
                    AuthPasskeyModel
                )
                .where(
                    AuthPasskeyModel.user_id
                    == user_id,
                    AuthPasskeyModel
                        .credential_id
                    == credential_id,
                )
                .values(
                    name=name
                )
            )

            result = session.execute(
                statement
            )

            updated = (
                result.rowcount or 0
            ) > 0

            session.commit()

            return updated

    # ============================================================
    # USAGE UPDATE
    # ============================================================

    def update_usage(
        self,
        credential_id: bytes,
        *,
        expected_sign_count: int,
        sign_count: int,
        last_used_at: datetime,
    ) -> bool:
        """
        Compare-and-set the WebAuthn signature
        counter.

        The UPDATE succeeds only when the
        database still contains the counter
        value used during assertion
        verification.
        """

        with self.session_factory() as session:
            statement = (
                update(
                    AuthPasskeyModel
                )
                .where(
                    AuthPasskeyModel
                        .credential_id
                    == credential_id,

                    AuthPasskeyModel
                        .sign_count
                    == expected_sign_count,
                )
                .values(
                    sign_count=sign_count,
                    last_used_at=(
                        last_used_at
                    ),
                )
            )

            result = session.execute(
                statement
            )

            updated = (
                result.rowcount or 0
            ) == 1

            if not updated:
                session.rollback()

                return False

            session.commit()

            return True

    # ============================================================
    # DELETE
    # ============================================================

    def delete(
        self,
        user_id: int | str,
        credential_id: bytes,
    ) -> bool:
        with self.session_factory() as session:
            statement = (
                delete(
                    AuthPasskeyModel
                )
                .where(
                    AuthPasskeyModel.user_id
                    == user_id,

                    AuthPasskeyModel
                        .credential_id
                    == credential_id,
                )
            )

            result = session.execute(
                statement
            )

            deleted = (
                result.rowcount or 0
            ) > 0

            session.commit()

            return deleted