from flask import Blueprint, request, jsonify
from Service.backend_service import (
    create_backend,
    activate_backend,
    deactivate_backend,
    list_backends,
    proxy_request,
)
from Service.user_service import validate_token
from security_engine.Service.security_service import scan_request

backend_bp = Blueprint("backend", __name__)


def _get_authenticated_user():
    """Returns (payload, None) on success or (None, error_response) on failure."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None, (jsonify({"error": "Authorization header is required"}), 401)
    payload, error = validate_token(token)
    if error:
        return None, (jsonify({"error": error}), 401)
    return payload, None


@backend_bp.route("/register", methods=["POST"])
def register():
    user, err = _get_authenticated_user()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    name = data.get("name")
    target_url = data.get("target_url")

    if not name or not target_url:
        return jsonify({"error": "name and target_url are required"}), 400

    backend, error = create_backend(name, target_url, user["user_id"])
    if error == "duplicate_name":
        return jsonify({"error": "A backend with this name already exists"}), 409
    if error:
        return jsonify({"error": error}), 400

    return jsonify(backend), 201


@backend_bp.route("/", methods=["GET"])
def list_all():
    user, err = _get_authenticated_user()
    if err:
        return err

    backends = list_backends(user["user_id"])
    return jsonify(backends), 200


@backend_bp.route("/activate", methods=["PATCH"])
def activate():
    user, err = _get_authenticated_user()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key is required"}), 400

    result = activate_backend(api_key, user["user_id"])
    if result is None:
        return jsonify({"error": "Backend not found"}), 404

    return jsonify(result), 200


@backend_bp.route("/deactivate", methods=["PATCH"])
def deactivate():
    user, err = _get_authenticated_user()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key is required"}), 400

    result = deactivate_backend(api_key, user["user_id"])
    if result is None:
        return jsonify({"error": "Backend not found"}), 404

    return jsonify(result), 200


@backend_bp.route("/proxy/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def proxy(path):
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return jsonify({"error": "X-API-Key header is required"}), 401

    ip = request.remote_addr
    method = request.method
    body = request.get_json(silent=True) or {}
    query_params = request.args.to_dict()

    scan_result = scan_request(ip, path, method, body, query_params, path, api_key)
    if scan_result["blocked"]:
        return jsonify({
            "status": "blocked",
            "attack_type": scan_result["attack_type"],
            "message": f"Request blocked: {scan_result['attack_type']} detected"
        }), 403

    response_data, status_code = proxy_request(
        api_key, method, path, dict(request.headers), body, query_params
    )
    return jsonify(response_data), status_code
