from flask import Blueprint, request, jsonify
from Service.backend_service import (
    create_backend,
    activate_backend,
    deactivate_backend,
    list_backends,
    proxy_request,
)
from security_engine.service.security_service import scan_request

backend_bp = Blueprint("backend", __name__)


@backend_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    name = data.get("name")
    target_url = data.get("target_url")

    if not name or not target_url:
        return jsonify({"error": "name and target_url are required"}), 400

    backend = create_backend(name, target_url)
    return jsonify(backend), 201


@backend_bp.route("/", methods=["GET"])
def list_all():
    backends = list_backends()
    return jsonify(backends), 200


@backend_bp.route("/activate", methods=["PATCH"])
def activate():
    api_key = request.json.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key is required"}), 400

    result = activate_backend(api_key)
    if result is None:
        return jsonify({"error": "Backend not found"}), 404

    return jsonify(result), 200


@backend_bp.route("/deactivate", methods=["PATCH"])
def deactivate():
    api_key = request.json.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key is required"}), 400

    result = deactivate_backend(api_key)
    if result is None:
        return jsonify({"error": "Backend not found"}), 404

    return jsonify(result), 200


@backend_bp.route("/proxy/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return jsonify({"error": "X-API-Key header is required"}), 401

    ip = request.remote_addr
    method = request.method
    body = request.json if request.is_json else {}
    query_params = request.args.to_dict()

    scan_result = scan_request(ip, path, method, body, query_params, path)
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
