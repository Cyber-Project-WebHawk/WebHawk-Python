from flask import Blueprint, request, jsonify
from Service.user_service import register_user, login_user, logout_user, validate_token

user_bp = Blueprint("user", __name__)

MIN_PASSWORD_LENGTH = 6


def _parse_credentials(data):
    username = data.get("username")
    password = data.get("password")

    if isinstance(username, str):
        username = username.strip()

    if not username or not password:
        return None, None, (jsonify({"error": "username and password are required"}), 400)

    if len(username) > 100:
        return None, None, (jsonify({"error": "username must be at most 100 characters"}), 400)

    if len(password) < MIN_PASSWORD_LENGTH:
        return None, None, (
            jsonify({"error": f"password must be at least {MIN_PASSWORD_LENGTH} characters"}),
            400,
        )

    return username, password, None


def _extract_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:].strip()
    return token or None


@user_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username, password, err = _parse_credentials(data)
    if err:
        return err

    user, error = register_user(username, password)
    if error:
        return jsonify({"error": error}), 409

    return jsonify({"message": "User registered successfully", "user": user}), 201


@user_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username, password, err = _parse_credentials(data)
    if err:
        return err

    ip = request.remote_addr
    result, error = login_user(username, password, ip)
    if error:
        return jsonify({"error": error}), 401

    return jsonify({"message": "Login successful", "token": result["token"], "expires_at": result["expires_at"]}), 200


@user_bp.route("/logout", methods=["POST"])
def logout():
    token = _extract_bearer_token()
    if not token:
        return jsonify({"error": "Authorization header is required"}), 401

    success, error = logout_user(token)
    if not success:
        return jsonify({"error": error}), 404

    return jsonify({"message": "Logged out successfully"}), 200


@user_bp.route("/me", methods=["GET"])
def me():
    token = _extract_bearer_token()
    if not token:
        return jsonify({"error": "Authorization header is required"}), 401

    payload, error = validate_token(token)
    if error:
        return jsonify({"error": error}), 401

    return jsonify({"user_id": payload["user_id"], "username": payload["username"]}), 200
