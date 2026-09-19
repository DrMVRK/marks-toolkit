from sqlalchemy.orm import DeclarativeBase
import secrets

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    LargeBinary,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

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


class AuthTotpModel(AuthBase):
    __tablename__ = "marks_auth_totp"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey(
            "marks_auth_users.id",
            ondelete="CASCADE",
        ),
        unique=True,
        nullable=False,
        index=True,
    )

    encrypted_secret: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    last_used_step = mapped_column(
        BigInteger,
        nullable=True,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class AuthPasskeyModel(AuthBase):
    __tablename__ = "marks_auth_passkeys"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey(
            "marks_auth_users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    user_handle: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
        index=True,
    )

    credential_id: Mapped[bytes] = mapped_column(
        LargeBinary,
        unique=True,
        nullable=False,
    )

    public_key: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    sign_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    transports: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class AuthRecoveryCodeModel(AuthBase):
    __tablename__ = "marks_auth_recovery_codes"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey(
            "marks_auth_users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    code_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    used: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )