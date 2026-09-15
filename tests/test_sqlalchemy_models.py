def test_sqlalchemy_auth_models_import():
    from marks_toolkit.auth.sqlalchemy_models import (
        AuthPasskeyModel,
        AuthRecoveryCodeModel,
        AuthTotpModel,
        AuthUserModel,
    )

    assert AuthUserModel is not None
    assert AuthTotpModel is not None
    assert AuthPasskeyModel is not None
    assert AuthRecoveryCodeModel is not None


def test_sqlalchemy_stores_import():
    from marks_toolkit.auth.sqlalchemy_mfa_store import (
        SQLAlchemyMFAStore,
    )
    from marks_toolkit.auth.sqlalchemy_store import (
        SQLAlchemyUserStore,
    )

    assert SQLAlchemyUserStore is not None
    assert SQLAlchemyMFAStore is not None