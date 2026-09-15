from flask import make_response


def success_response(
    data=None,
    message=None,
    status_code=200,
):
    response = {
        "ok": True
    }

    if message is not None:
        response["message"] = message

    if data is not None:
        response["data"] = data

    return response, status_code


def error_response(
    code,
    message,
    status_code=400,
):
    return {
        "ok": False,
        "error": {
            "code": code,
            "message": message
        }
    }, status_code


def no_store_response(
    data=None,
    message=None,
    status_code=200,
):
    body, status = success_response(
        data=data,
        message=message,
        status_code=status_code,
    )

    response = make_response(
        body,
        status,
    )

    response.headers[
        "Cache-Control"
    ] = "no-store"

    return response