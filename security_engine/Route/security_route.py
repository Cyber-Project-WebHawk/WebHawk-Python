from flask import Blueprint, request, jsonify
from security_engine.Service.security_service import scan_request, get_dashboard
from Service.user_service import validate_token

security_bp = Blueprint("security", __name__)


def _require_bearer_token():
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return None, (jsonify({"error": "Authorization header is required"}), 401)
    payload, error = validate_token(token)
    if error:
        return None, (jsonify({"error": error}), 401)
    return payload, None


@security_bp.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    ip = request.remote_addr
    endpoint = data.get("endpoint", "/")
    method = data.get("method", "GET")
    body = data.get("body", {})
    query_params = data.get("query_params", {})
    path = data.get("path", "/")

    result = scan_request(ip, endpoint, method, body, query_params, path)

    if result["blocked"]:
        return jsonify({
            "status": "blocked",
            "attack_type": result["attack_type"],
            "message": f"Request blocked: {result['attack_type']} detected"
        }), 403

    return jsonify({
        "status": "allowed",
        "message": "Request passed security scan"
    }), 200


@security_bp.route("/dashboard", methods=["GET"])
def dashboard():
    _, err = _require_bearer_token()
    if err:
        return err

    backend_key = request.args.get("backend_key") or None
    hours = request.args.get("hours", 24)
    try:
        hours = int(hours)
    except (TypeError, ValueError):
        return jsonify({"error": "hours must be an integer"}), 400

    return jsonify(get_dashboard(backend_key=backend_key, hours=hours)), 200
