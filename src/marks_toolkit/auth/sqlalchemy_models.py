from sqlalchemy.orm import DeclarativeBase
import secrets

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from .user_contract import AuthUser



class AuthBase(DeclarativeBase):
    pass



class AuthUserModel(AuthBase, AuthUser):
    __tablename__ = "marks_auth_users"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    auth_id: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_urlsafe(32)
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False
    )

    email_key: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        nullable=False
    )

    username: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )

    username_key: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False
    )

    password_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False
    )

    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True
    )

    @property
    def is_active(self):
        return self.active