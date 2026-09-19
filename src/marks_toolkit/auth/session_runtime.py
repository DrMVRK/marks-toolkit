from flask import (
    current_app,
    g,
    make_response,
    request,
    session,
)
from flask_login import (
    current_user,
    login_user,
    logout_user,
)
from itsdangerous import (
    BadSignature,
    SignatureExpired,
    URLSafeTimedSerializer,
)


SESSION_KEY = "marks_auth_session_id"

DEFAULT_COOKIE_NAME = (
    "marks_auth_device_session"
)

DEFAULT_REMEMBER_SECONDS = (
    60 * 60 * 24 * 30
)


class SessionTokenService:

    def __init__(
        self,
        secret_key,
        *,
        salt="marks-auth-session",
    ):
        if not secret_key:
            raise ValueError(
                "A secret key is required."
            )

        self.serializer = (
            URLSafeTimedSerializer(
                secret_key,
                salt=salt,
            )
        )

    def dumps(
        self,
        session_id,
    ):
        if not session_id:
            raise ValueError(
                "Session ID is required."
            )

        return self.serializer.dumps(
            session_id
        )

    def loads(
        self,
        token,
        *,
        max_age,
    ):
        if not token:
            return None

        try:
            value = (
                self.serializer.loads(
                    token,
                    max_age=max_age,
                )
            )

        except (
            BadSignature,
            SignatureExpired,
        ):
            return None

        if (
            not isinstance(
                value,
                str,
            )
            or not value
        ):
            return None

        return value


def get_current_session_id():
    return session.get(
        SESSION_KEY
    )


def establish_authenticated_session(
    *,
    state,
    user,
    authentication_method,
    remembered=False,
):
    """
    Create a server-side MARKS session and
    bind the current Flask session to it.

    Flask-Login remember cookies are
    intentionally not used here.
    """

    login_user(
        user,
        remember=False,
        fresh=True,
    )

    record = (
        state.session_service
        .create_session(
            user=user,

            ip_address=(
                request.remote_addr
                or "unknown"
            ),

            user_agent=(
                request.headers.get(
                    "User-Agent"
                )
            ),

            authentication_method=(
                authentication_method
            ),

            remembered=(
                bool(remembered)
            ),
        )
    )

    session[
        SESSION_KEY
    ] = record.id

    return record


def clear_authenticated_session():
    session.pop(
        SESSION_KEY,
        None,
    )

    logout_user()


def revoke_current_session(
    state,
):
    session_id = (
        get_current_session_id()
    )

    if (
        session_id
        and current_user
        .is_authenticated
    ):
        state.session_service.revoke_session(
            session_id=session_id,
            user=current_user,
        )

    clear_authenticated_session()


def _cookie_name():
    return current_app.config.get(
        "MARKS_AUTH_SESSION_COOKIE_NAME",
        DEFAULT_COOKIE_NAME,
    )


def _remember_seconds():
    value = current_app.config.get(
        "MARKS_AUTH_SESSION_REMEMBER_SECONDS",
        DEFAULT_REMEMBER_SECONDS,
    )

    try:
        value = int(value)

    except (
        TypeError,
        ValueError,
    ):
        value = (
            DEFAULT_REMEMBER_SECONDS
        )

    return max(
        1,
        value,
    )


def set_persistent_session_cookie(
    response,
    *,
    state,
    session_record,
):
    response = make_response(
        response
    )

    if not session_record.remembered:
        return response

    token = (
        state.session_token_service
        .dumps(
            session_record.id
        )
    )

    response.set_cookie(
        _cookie_name(),
        token,
        max_age=(
            _remember_seconds()
        ),
        httponly=True,
        secure=(
            current_app.config.get(
                "MARKS_AUTH_COOKIE_SECURE",
                True,
            )
        ),
        samesite=(
            current_app.config.get(
                "SESSION_COOKIE_SAMESITE",
                "Lax",
            )
            or "Lax"
        ),
        path="/",
    )

    return response


def clear_persistent_session_cookie(
    response,
):
    response = make_response(
        response
    )

    response.delete_cookie(
        _cookie_name(),
        path="/",
    )

    return response

def _request_persistent_session_id(
    state,
):
    token = request.cookies.get(
        _cookie_name()
    )

    if not token:
        return None

    session_id = (
        state.session_token_service
        .loads(
            token,

            max_age=(
                _remember_seconds()
            ),
        )
    )

    if not session_id:
        g.marks_auth_clear_session_cookie = (
            True
        )

    return session_id


def restore_persistent_session(
    state,
):
    """
    Restore authentication from the
    MARKS persistent-session cookie.

    The cookie contains only a signed
    opaque server-side session ID.
    """

    session_id = (
        _request_persistent_session_id(
            state
        )
    )

    if not session_id:
        return False

    record = (
        state.session_store.get(
            session_id
        )
    )

    if (
        record is None
        or record.revoked_at
        is not None
        or not record.remembered
    ):
        g.marks_auth_clear_session_cookie = (
            True
        )

        return False

    user = (
        state.user_store.find_by_id(
            record.user_id
        )
    )

    if (
        user is None
        or not getattr(
            user,
            "is_active",
            False,
        )
        or getattr(
            user,
            "auth_id",
            None,
        )
        != record.auth_id
    ):
        g.marks_auth_clear_session_cookie = (
            True
        )

        return False

    if not (
        state.session_service
        .validate_session(
            session_id=session_id,
            user=user,
        )
    ):
        g.marks_auth_clear_session_cookie = (
            True
        )

        return False

    login_user(
        user,
        remember=False,
        fresh=False,
    )

    session[
        SESSION_KEY
    ] = session_id

    return True


def validate_current_request_session(
    state,
):
    """
    Validate the server-side session
    associated with the current request.
    """

    if not current_user.is_authenticated:
        return restore_persistent_session(
            state
        )

    session_id = (
        get_current_session_id()
    )

    if not session_id:
        def validate_current_request_session(
            state,
        ):
            """
            Validate the server-side session
            associated with the current request.
            """

            if not current_user.is_authenticated:
                return restore_persistent_session(
                    state
                )

            session_id = (
                get_current_session_id()
            )

            if not session_id:
                clear_authenticated_session()

                g.marks_auth_clear_session_cookie = (
                    True
                )

                return False

            valid = (
                state.session_service
                .validate_session(
                    session_id=session_id,
                    user=current_user,
                )
            )

            if valid:
                return True

            clear_authenticated_session()

            g.marks_auth_clear_session_cookie = (
                True
            )

            return False
        return False