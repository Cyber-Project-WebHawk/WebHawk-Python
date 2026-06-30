from flask import Blueprint, request, jsonify
from service.user_service import register_user, login_user, logout_user, validate_token

user_bp = Blueprint("user", __name__)


@user_bp.route("/register", methods=["POST"])
def register():
    # Fix #3: never raises, never None - safe even on missing Content-Type,
    # malformed JSON, or a literal `null` body.
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    user, error = register_user(username, password)
    if error:
        return jsonify({"error": error}), 409

    return jsonify({"message": "User registered successfully", "user": user}), 201


@user_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    ip = request.remote_addr
    result, error = login_user(username, password, ip)
    if error == "Could not create session, please try again":
        return jsonify({"error": error}), 500
    if error:
        return jsonify({"error": error}), 401

    return jsonify({"message": "Login successful", "token": result["token"], "expires_at": result["expires_at"]}), 200


@user_bp.route("/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Authorization header is required"}), 401

    success, error = logout_user(token)
    if not success:
        return jsonify({"error": error}), 404

    return jsonify({"message": "Logged out successfully"}), 200


@user_bp.route("/me", methods=["GET"])
def me():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Authorization header is required"}), 401

    payload, error = validate_token(token)
    if error:
        return jsonify({"error": error}), 401

    return jsonify({"user_id": payload["user_id"], "username": payload["username"]}), 200
