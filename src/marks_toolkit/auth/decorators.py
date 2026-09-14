from functools import wraps

from flask import current_app, request

from .responses import error_response


def csrf_protected(view_function):
    @wraps(view_function)
    def wrapper(*args, **kwargs):
        state = current_app.extensions["marks_auth"]

        if not state.csrf_service.validate_request(request):
            return error_response(
                code="CSRF_FAILED",
                message="Security token missing or invalid.",
                status_code=403
            )

        return view_function(*args, **kwargs)

    return wrapper


def throttle(
    action,
    identities,
    limit_config,
    window_config
):
    def decorator(view_function):
        @wraps(view_function)
        def wrapper(*args, **kwargs):
            state = current_app.extensions["marks_auth"]

            limit = getattr(
                state.config,
                limit_config
            )

            window = getattr(
                state.config,
                window_config
            )

            data = request.get_json(silent=True)

            if not isinstance(data, dict):
                data = {}

            throttle_keys = []

            for identity_type in identities:
                if identity_type == "ip":
                    identity_value = (
                        request.remote_addr or "unknown"
                    )

                elif identity_type == "email":
                    email = data.get("email")

                    if isinstance(email, str):
                        identity_value = (
                            email.strip().casefold()
                        )
                    else:
                        identity_value = "<invalid>"

                else:
                    raise RuntimeError(
                        f"Unsupported throttle identity: "
                        f"{identity_type}"
                    )

                throttle_keys.append(
                    (
                        action,
                        identity_type,
                        identity_value
                    )
                )

            for throttle_key in throttle_keys:
                if state.throttle_service.is_blocked(
                    throttle_key,
                    limit,
                    window
                ):
                    return error_response(
                        code="RATE_LIMITED",
                        message=(
                            "Too many requests. "
                            "Please try again later."
                        ),
                        status_code=429
                    )

            for throttle_key in throttle_keys:
                state.throttle_service.record(
                    throttle_key,
                    window
                )

            return view_function(*args, **kwargs)

        return wrapper

    return decorator