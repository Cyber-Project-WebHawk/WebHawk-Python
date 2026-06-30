import os
from flask import Flask, send_from_directory
from security_engine.Route.security_route import security_bp
from Route.backend_route import backend_bp
from Route.user_route import user_bp

app = Flask(__name__)

app.register_blueprint(security_bp, url_prefix="/security")
app.register_blueprint(backend_bp, url_prefix="/backends")
app.register_blueprint(user_bp, url_prefix="/auth")


@app.route("/dashboard")
def dashboard_page():
    return send_from_directory("static", "dashboard.html")


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    app.run(debug=debug, host="0.0.0.0", port=5000)
