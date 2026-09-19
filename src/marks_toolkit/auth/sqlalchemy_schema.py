from sqlalchemy import inspect

from .sqlalchemy_models import (
    AuthBase,
)


AUTH_SCHEMA_VERSION = 2


AUTH_TABLES = (
    "marks_auth_users",
    "marks_auth_totp",
    "marks_auth_passkeys",
    "marks_auth_recovery_codes",
    "marks_auth_sessions",
)


def create_auth_schema(
    engine,
) -> None:
    AuthBase.metadata.create_all(
        bind=engine
    )


def get_missing_auth_tables(
    engine,
) -> list[str]:
    inspector = inspect(
        engine
    )

    existing_tables = set(
        inspector.get_table_names()
    )

    return [
        table_name
        for table_name in AUTH_TABLES
        if table_name
        not in existing_tables
    ]


def auth_schema_exists(
    engine,
) -> bool:
    return not bool(
        get_missing_auth_tables(
            engine
        )
    )