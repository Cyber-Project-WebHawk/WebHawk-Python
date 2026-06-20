from flask import Flask
from security_engine.route.security_route import security_bp
from Route.backend_route import backend_bp

app = Flask(__name__)

app.register_blueprint(security_bp, url_prefix="/security")
app.register_blueprint(backend_bp, url_prefix="/backends")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
