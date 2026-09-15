from flask import request

from .responses import error_response


def get_json_object():
    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return (
            None,
            error_response(
                code="INVALID_REQUEST",
                message=(
                    "Request body must contain "
                    "a JSON object."
                ),
                status_code=400,
            ),
        )

    return data, None


def get_required_string(
    data,
    field_name,
):
    value = data.get(
        field_name
    )

    if not isinstance(value, str):
        return (
            None,
            error_response(
                code="INVALID_REQUEST",
                message=(
                    f"{field_name} must be "
                    "a string."
                ),
                status_code=400,
            ),
        )

    value = value.strip()

    if not value:
        return (
            None,
            error_response(
                code="INVALID_REQUEST",
                message=(
                    f"{field_name} is required."
                ),
                status_code=400,
            ),
        )

    return value, None


def get_optional_string(
    data,
    field_name,
):
    value = data.get(
        field_name
    )

    if value is None:
        return None, None

    if not isinstance(value, str):
        return (
            None,
            error_response(
                code="INVALID_REQUEST",
                message=(
                    f"{field_name} must be "
                    "a string."
                ),
                status_code=400,
            ),
        )

    return value, None


def get_optional_bool(
    data,
    field_name,
    default=False,
):
    value = data.get(
        field_name,
        default,
    )

    if not isinstance(value, bool):
        return (
            None,
            error_response(
                code="INVALID_REQUEST",
                message=(
                    f"{field_name} must be "
                    "a boolean."
                ),
                status_code=400,
            ),
        )

    return value, None