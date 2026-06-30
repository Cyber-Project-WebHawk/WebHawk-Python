from flask import Blueprint, request, jsonify
from security_engine.service.security_service import scan_request

security_bp = Blueprint("security", __name__)


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
