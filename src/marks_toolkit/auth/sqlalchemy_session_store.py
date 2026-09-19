from sqlalchemy import (
    select,
    update,
)
from sqlalchemy.exc import IntegrityError

from .session_store import (
    SessionRecord,
    SessionStore,
)
from .sqlalchemy_models import (
    AuthSessionModel,
)


class SQLAlchemySessionStore(
    SessionStore
):

    def __init__(
        self,
        session_factory,
    ):
        self.session_factory = (
            session_factory
        )

    @staticmethod
    def _to_record(
        model: AuthSessionModel,
    ) -> SessionRecord:
        return SessionRecord(
            id=model.id,
            user_id=model.user_id,
            auth_id=model.auth_id,
            created_at=model.created_at,
            last_seen_at=(
                model.last_seen_at
            ),
            ip_address=(
                model.ip_address
            ),
            user_agent=(
                model.user_agent
            ),
            authentication_method=(
                model
                .authentication_method
            ),
            remembered=(
                model.remembered
            ),
            revoked_at=(
                model.revoked_at
            ),
        )

    def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        if not isinstance(
            session,
            SessionRecord,
        ):
            raise TypeError(
                "session must be a "
                "SessionRecord."
            )

        if not session.id:
            raise ValueError(
                "Session ID is required."
            )

        model = AuthSessionModel(
            id=session.id,
            user_id=session.user_id,
            auth_id=session.auth_id,
            created_at=(
                session.created_at
            ),
            last_seen_at=(
                session.last_seen_at
            ),
            ip_address=(
                session.ip_address
            ),
            user_agent=(
                session.user_agent
            ),
            authentication_method=(
                session
                .authentication_method
            ),
            remembered=(
                session.remembered
            ),
            revoked_at=(
                session.revoked_at
            ),
        )

        with self.session_factory() as db:
            db.add(
                model
            )

            try:
                db.commit()

            except IntegrityError as exc:
                db.rollback()

                raise ValueError(
                    "Session ID already "
                    "exists."
                ) from exc

            db.refresh(
                model
            )

            return self._to_record(
                model
            )

    def get(
        self,
        session_id: str,
    ) -> SessionRecord | None:
        with self.session_factory() as db:
            model = db.get(
                AuthSessionModel,
                session_id,
            )

            if model is None:
                return None

            return self._to_record(
                model
            )

    def list_for_user(
        self,
        user_id,
        *,
        include_revoked=False,
    ):
        with self.session_factory() as db:
            statement = (
                select(
                    AuthSessionModel
                )
                .where(
                    AuthSessionModel
                        .user_id
                    == user_id
                )
            )

            if not include_revoked:
                statement = (
                    statement.where(
                        AuthSessionModel
                            .revoked_at
                            .is_(None)
                    )
                )

            statement = (
                statement.order_by(
                    AuthSessionModel
                        .created_at
                        .desc(),
                    AuthSessionModel
                        .id
                        .desc(),
                )
            )

            models = list(
                db.scalars(
                    statement
                )
            )

            return [
                self._to_record(
                    model
                )
                for model in models
            ]

    def touch(
        self,
        session_id,
        *,
        user_id,
        last_seen_at,
    ):
        with self.session_factory() as db:
            result = db.execute(
                update(
                    AuthSessionModel
                )
                .where(
                    AuthSessionModel.id
                    == session_id,

                    AuthSessionModel.user_id
                    == user_id,

                    AuthSessionModel
                        .revoked_at
                        .is_(None),
                )
                .values(
                    last_seen_at=(
                        last_seen_at
                    )
                )
            )

            updated = (
                result.rowcount or 0
            ) == 1

            if not updated:
                db.rollback()
                return False

            db.commit()

            return True

    def revoke(
        self,
        session_id,
        *,
        user_id,
        revoked_at,
    ):
        with self.session_factory() as db:
            result = db.execute(
                update(
                    AuthSessionModel
                )
                .where(
                    AuthSessionModel.id
                    == session_id,

                    AuthSessionModel.user_id
                    == user_id,

                    AuthSessionModel
                        .revoked_at
                        .is_(None),
                )
                .values(
                    revoked_at=(
                        revoked_at
                    )
                )
            )

            revoked = (
                result.rowcount or 0
            ) == 1

            if not revoked:
                db.rollback()
                return False

            db.commit()

            return True

    def revoke_others(
        self,
        user_id,
        *,
        current_session_id,
        revoked_at,
    ):
        with self.session_factory() as db:
            result = db.execute(
                update(
                    AuthSessionModel
                )
                .where(
                    AuthSessionModel.user_id
                    == user_id,

                    AuthSessionModel.id
                    != current_session_id,

                    AuthSessionModel
                        .revoked_at
                        .is_(None),
                )
                .values(
                    revoked_at=(
                        revoked_at
                    )
                )
            )

            count = (
                result.rowcount or 0
            )

            db.commit()

            return count

    def revoke_all(
        self,
        user_id,
        *,
        revoked_at,
    ):
        with self.session_factory() as db:
            result = db.execute(
                update(
                    AuthSessionModel
                )
                .where(
                    AuthSessionModel.user_id
                    == user_id,

                    AuthSessionModel
                        .revoked_at
                        .is_(None),
                )
                .values(
                    revoked_at=(
                        revoked_at
                    )
                )
            )

            count = (
                result.rowcount or 0
            )

            db.commit()

            return count