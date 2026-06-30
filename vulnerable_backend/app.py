"""
====================================================================
 INTENTIONALLY VULNERABLE TEST BACKEND - DO NOT USE OUTSIDE OF A
 LOCAL/SANDBOXED DEMO, AND NEVER EXPOSE IT DIRECTLY TO THE INTERNET.
====================================================================

This app exists for exactly one purpose: to be a genuinely exploitable
target that WebHawk's security engine is tested against, so the team can
see both sides of the problem - the attack, and the defense that's
supposed to stop it before it ever reaches here.

Every "vulnerable" query below builds SQL via plain string
formatting/concatenation instead of parameterized placeholders - on
purpose. That is the actual SQL injection bug, not a simulation of one.
Run it standalone (without going through WebHawk) and these payloads work
for real against the local SQLite file:

    curl -X POST http://localhost:5001/login \
      -H "Content-Type: application/json" \
      -d "{\"username\": \"admin' OR '1'='1\", \"password\": \"x\"}"
    -> bypasses the password check entirely

    curl "http://localhost:5001/data?id=1%20UNION%20SELECT%20username,password%20FROM%20users"
    -> exfiltrates every stored credential through an endpoint that was
       only ever meant to return one row by id

Now run WebHawk in front of it and send the same payloads through
/backends/proxy/... - they get blocked before they ever execute.
"""
import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = os.getenv("VULN_DB_PATH", "/tmp/webhawk_vulnerable_backend.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL
        )
    """)
    if conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone() is None:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')"
        )
    if conn.execute("SELECT id FROM users WHERE username = 'john'").fetchone() is None:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES ('john', 'pass456', 'user')"
        )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    """
    GENUINELY VULNERABLE TO SQL INJECTION (intentionally - see module
    docstring). username/password are spliced directly into the query
    string. A username of  admin' OR '1'='1  makes the WHERE clause always
    true, returning the first row in the table regardless of password.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.OperationalError as e:
        conn.close()
        # Deliberately leaking the DB error too - real vulnerable apps
        # often do, and that leak is itself what lets attackers refine an
        # injection payload (classic "error-based" SQLi).
        return jsonify({"error": f"Database error: {e}", "query": query}), 500
    conn.close()

    if row is None:
        return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({"message": f"Welcome {row[1]}!", "role": row[2]}), 200


@app.route("/data", methods=["GET"])
def get_data():
    """
    GENUINELY VULNERABLE TO SQL INJECTION. `id` is concatenated straight
    into the query - ?id=1 UNION SELECT username,password FROM users
    dumps every credential through an endpoint that's only supposed to
    return one record. Also doubles as the rate-limit test target (no
    auth/SQLi payload needed - just hit it repeatedly).
    """
    record_id = request.args.get("id", "1")
    conn = get_db()
    query = f"SELECT id, username, role FROM users WHERE id = {record_id}"
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.OperationalError as e:
        conn.close()
        return jsonify({"error": f"Database error: {e}", "query": query}), 500
    conn.close()

    return jsonify({
        "status": "ok",
        "results": [{"id": r[0], "username": r[1], "role": r[2]} for r in rows],
    }), 200


@app.route("/comment", methods=["POST"])
def add_comment():
    """
    GENUINELY VULNERABLE TO STORED XSS. The comment is saved and echoed
    back completely unsanitized (the insert itself is parameterized -
    that part isn't the bug - the bug is that nothing ever escapes the
    text before it would be rendered as HTML downstream). A payload like
    <script>...</script> would execute in every visitor's browser if any
    frontend ever rendered these comments directly.
    """
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    conn = get_db()
    conn.execute("INSERT INTO comments (text) VALUES (?)", (text,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Comment added", "comment": text}), 201


@app.route("/comments", methods=["GET"])
def get_comments():
    """Returns every stored comment completely unescaped - see add_comment()."""
    conn = get_db()
    rows = conn.execute("SELECT id, text FROM comments ORDER BY id").fetchall()
    conn.close()
    return jsonify({"comments": [r[1] for r in rows]}), 200


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5001)
