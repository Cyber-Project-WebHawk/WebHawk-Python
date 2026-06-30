from flask import Blueprint, request, jsonify
from security_engine.service.security_service import scan_request, get_dashboard
from route.auth_middleware import require_auth

security_bp = Blueprint("security", __name__)


@security_bp.route("/scan", methods=["POST"])
def scan():
    ip = request.remote_addr
    # Fix #3: safe even on missing Content-Type, malformed JSON, or `null`.
    data = request.get_json(silent=True) or {}
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
@require_auth
def dashboard(user_id):
    """
    Bonus analytics dashboard (JSON). Requires auth (any logged-in user can
    view platform-wide totals; pass ?backend_key=<api_key> to scope the
    figures to one specific backend instead). ?hours=N controls the
    timeline lookback window (default 24, clamped to 1-720).

    A small visual dashboard that renders this data as charts is served at
    GET /static/dashboard.html.
    """
    backend_key = request.args.get("backend_key")
    hours = request.args.get("hours", default=24, type=int) or 24
    data = get_dashboard(backend_key=backend_key, hours=hours)
    return jsonify(data), 200
