from flask import Flask
from security_engine.route.security_route import security_bp

app = Flask(__name__)

app.register_blueprint(security_bp, url_prefix="/security")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
