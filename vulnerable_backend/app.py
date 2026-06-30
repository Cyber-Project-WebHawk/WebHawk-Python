from flask import Flask, request, jsonify

app = Flask(__name__)

# Fake database of users stored in memory
FAKE_DB = [
    {"id": 1, "username": "admin", "password": "admin123", "role": "admin"},
    {"id": 2, "username": "john", "password": "pass456", "role": "user"},
]

comments = []


# Vulnerable to SQL Injection — simulates a DB query using string formatting
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")

    # INTENTIONALLY VULNERABLE — simulates what raw string SQL would do
    # In a real DB this query would be: SELECT * FROM users WHERE username='{username}' AND password='{password}'
    # An attacker sending username = "admin' OR '1'='1" would bypass the password check
    user = next(
        (u for u in FAKE_DB if u["username"] == username or username.endswith("' OR '1'='1")),
        None,
    )

    if user:
        return jsonify({"message": f"Welcome {user['username']}!", "role": user["role"]}), 200

    return jsonify({"message": "Invalid credentials"}), 401


# Vulnerable to XSS — reflects user input directly without sanitizing
@app.route("/comment", methods=["POST"])
def add_comment():
    data = request.json
    text = data.get("text", "")

    # INTENTIONALLY VULNERABLE — stores and returns raw HTML/script tags
    comments.append(text)
    return jsonify({"message": "Comment added", "comment": text}), 201


@app.route("/comments", methods=["GET"])
def get_comments():
    # Returns raw unsanitized content — XSS payload would execute in a browser
    return jsonify({"comments": comments}), 200


# Open endpoint — used to test Rate Limiting
@app.route("/data", methods=["GET"])
def get_data():
    return jsonify({"data": "This is sensitive data", "status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
