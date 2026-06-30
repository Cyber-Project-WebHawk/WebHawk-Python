from functools import wraps
from flask import request, jsonify
from service.user_service import validate_token


def require_auth(view_func):
    """
    Fix #4: decorator that requires a valid Bearer JWT on the request.

    On success, injects `user_id` as a keyword argument into the wrapped
    view function, so route handlers can scope their work to the
    authenticated caller. On failure, short-circuits with a 401 JSON error.

    Usage:
        @backend_bp.route("/register", methods=["POST"])
        @require_auth
        def register(user_id):
            ...
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()

        if not token:
            return jsonify({"error": "Authorization header is required"}), 401

        payload, error = validate_token(token)
        if error:
            return jsonify({"error": error}), 401

        kwargs["user_id"] = payload["user_id"]
        return view_func(*args, **kwargs)

    return wrapper
