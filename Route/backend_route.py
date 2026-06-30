from flask import Blueprint, request, jsonify
from service.backend_service import (
    create_backend,
    activate_backend,
    deactivate_backend,
    list_backends,
    proxy_request,
)
from security_engine.service.security_service import scan_request
from route.auth_middleware import require_auth

backend_bp = Blueprint("backend", __name__)


@backend_bp.route("/register", methods=["POST"])
@require_auth
def register(user_id):
    # Fix #3: request.get_json(silent=True) never raises and never returns
    # None for `or {}` to fall back on, even on a missing Content-Type, a
    # malformed JSON body, or a literal `null` body.
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    target_url = data.get("target_url")

    if not name or not target_url:
        return jsonify({"error": "name and target_url are required"}), 400

    # Fix #4: backend is now created under the authenticated caller.
    backend, error = create_backend(name, target_url, user_id)
    if error:
        return jsonify({"error": error}), 409

    return jsonify(backend), 201


@backend_bp.route("/", methods=["GET"])
@require_auth
def list_all(user_id):
    # Fix #4: only the caller's own backends are returned, and the
    # API key is omitted from this listing (see Service/backend_service.py).
    backends = list_backends(user_id)
    return jsonify(backends), 200


@backend_bp.route("/activate", methods=["PATCH"])
@require_auth
def activate(user_id):
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key is required"}), 400

    result = activate_backend(api_key, user_id)
    if result is None:
        return jsonify({"error": "Backend not found"}), 404

    return jsonify(result), 200


@backend_bp.route("/deactivate", methods=["PATCH"])
@require_auth
def deactivate(user_id):
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key is required"}), 400

    result = deactivate_backend(api_key, user_id)
    if result is None:
        return jsonify({"error": "Backend not found"}), 404

    return jsonify(result), 200


@backend_bp.route("/proxy/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def proxy(path):
    # Intentionally NOT behind @require_auth: this endpoint is called by
    # the registered backend's own end users via X-API-Key, not by the
    # WebHawk dashboard owner via a JWT. That auth model is unchanged.
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return jsonify({"error": "X-API-Key header is required"}), 401

    ip = request.remote_addr
    method = request.method
    body = request.get_json(silent=True) or {}
    query_params = request.args.to_dict()

    # Fix #6: pass the caller's api_key through as the rate-limit scope key,
    # so two unrelated backends sharing a route name + source IP no longer
    # share a single rate-limit counter.
    scan_result = scan_request(ip, path, method, body, query_params, path, backend_key=api_key)
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
