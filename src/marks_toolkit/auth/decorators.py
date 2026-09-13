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