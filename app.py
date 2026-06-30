import os
from flask import Flask, jsonify
from security_engine.route.security_route import security_bp
from route.backend_route import backend_bp
from route.user_route import user_bp

app = Flask(__name__)

app.register_blueprint(security_bp, url_prefix="/security")
app.register_blueprint(backend_bp, url_prefix="/backends")
app.register_blueprint(user_bp, url_prefix="/auth")


# Fix #1: a global error handler so that unexpected failures (a DB hiccup, a
# bug, anything not explicitly caught lower down) return a clean JSON 500
# instead of falling through to Flask/Werkzeug's default HTML error page -
# which, combined with debug=True, was leaking full file paths, stack
# traces, and source code straight into the HTTP response.
@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(415)
def handle_unsupported_media_type(e):
    return jsonify({"error": "Content-Type must be application/json"}), 415


@app.errorhandler(Exception)
def handle_unexpected_error(e):
    app.logger.exception("Unhandled exception")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    # Fix #1: debug mode (which enables the interactive Werkzeug debugger -
    # arbitrary code execution + full source/stack-trace disclosure on any
    # unhandled error) must never be on by default. Set FLASK_DEBUG=true
    # only for local development, never in a deployed/demo environment.
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
