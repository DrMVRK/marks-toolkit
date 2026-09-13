def success_response(data=None, message=None, status_code=200):
    response = {
        "ok": True
    }

    if message is not None:
        response["message"] = message

    if data is not None:
        response["data"] = data

    return response, status_code

def error_response(code, message, status_code=400):
    return {
        "ok": False,
        "error": {
            "code": code,
            "message": message
        }
    }, status_code