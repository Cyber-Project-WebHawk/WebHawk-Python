from flask import Blueprint, request, jsonify
from security_engine.service.security_service import scan_request

security_bp = Blueprint("security", __name__)


@security_bp.route("/scan", methods=["POST"])
def scan():
    ip = request.remote_addr
    endpoint = request.json.get("endpoint", "/")
    method = request.json.get("method", "GET")
    body = request.json.get("body", {})
    query_params = request.json.get("query_params", {})
    path = request.json.get("path", "/")

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
