import secrets

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from .user_store import UserStore
from .sqlalchemy_models import AuthUserModel
from .exceptions import IdentityUnavailableError


class SQLAlchemyUserStore(UserStore):
    def __init__(self, session_factory):
        self.session_factory = session_factory

    def find_by_identity(self, identity_key):
        with self.session_factory() as session:
            statement = select(AuthUserModel).where(
                or_(
                    AuthUserModel.email_key == identity_key,
                    AuthUserModel.username_key == identity_key
                )
            )

            return session.scalar(statement)

    def find_by_auth_id(self, auth_id):
        with self.session_factory() as session:
            statement = select(AuthUserModel).where(
                AuthUserModel.auth_id == auth_id
            )

            return session.scalar(statement)

    def find_by_id(
        self,
        user_id,
    ):
        with self.session_factory() as session:
            return session.get(
                AuthUserModel,
                user_id
            )

    def email_exists(self, email_key):
        with self.session_factory() as session:
            statement = select(AuthUserModel.id).where(
                AuthUserModel.email_key == email_key
            )

            return session.scalar(statement) is not None


    def username_exists(self, username_key):
        with self.session_factory() as session:
            statement = select(AuthUserModel.id).where(
                AuthUserModel.username_key == username_key
            )

            return session.scalar(statement) is not None

    def create_user(
        self,
        email,
        username,
        password_hash
    ):
        email_key = email.casefold()
        username_key = username.casefold()

        user = AuthUserModel(
            auth_id=secrets.token_urlsafe(32),
            email=email,
            email_key=email_key,
            username=username,
            username_key=username_key,
            password_hash=password_hash,
            active=True
        )

        with self.session_factory() as session:
            session.add(user)

            try:
                session.commit()

            except IntegrityError:
                session.rollback()

                raise IdentityUnavailableError(
                    "Email or username is already in use."
                )

            session.refresh(user)

            return user

    def rotate_auth_id(self, user):
        new_auth_id = secrets.token_urlsafe(32)

        with self.session_factory() as session:
            stored_user = session.get(
                AuthUserModel,
                user.id
            )

            if stored_user is None:
                raise RuntimeError(
                    "User no longer exists."
                )

            stored_user.auth_id = new_auth_id

            session.commit()

            user.auth_id = new_auth_id

            return new_auth_id

    def update_password(
        self,
        user,
        password_hash
    ):
        with self.session_factory() as session:
            stored_user = session.get(
                AuthUserModel,
                user.id
            )

            if stored_user is None:
                raise RuntimeError(
                    "User no longer exists."
                )

            stored_user.password_hash = password_hash

            session.commit()

            user.password_hash = password_hash

    def update_password_and_rotate_auth_id(
        self,
        user,
        password_hash
    ):
        new_auth_id = secrets.token_urlsafe(32)

        with self.session_factory() as session:
            stored_user = session.get(
                AuthUserModel,
                user.id
            )

            if stored_user is None:
                raise RuntimeError(
                    "User no longer exists."
                )

            stored_user.password_hash = password_hash
            stored_user.auth_id = new_auth_id

            session.commit()

            user.password_hash = password_hash
            user.auth_id = new_auth_id

            return new_auth_id