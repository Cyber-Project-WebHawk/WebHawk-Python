import bcrypt
import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from Repository.user_repository import (
    create_user,
    get_user_by_username,
    create_session,
    get_session_by_token,
    deactivate_session,
)

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "webhawk_secret_key")
JWT_EXPIRY_HOURS = 24


def register_user(username, password):
    existing = get_user_by_username(username)
    if existing:
        return None, "Username already exists"

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    row = create_user(username, hashed.decode("utf-8"))

    return {
        "id": row[0],
        "username": row[1],
        "created_at": row[2].isoformat(),
    }, None


def login_user(username, password, ip):
    user = get_user_by_username(username)
    if user is None:
        return None, "Invalid credentials"

    user_id, user_name, stored_hash = user

    password_match = bcrypt.checkpw(
        password.encode("utf-8"),
        stored_hash.encode("utf-8")
    )
    if not password_match:
        return None, "Invalid credentials"

    expires_at = datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)

    token = jwt.encode(
        {
            "user_id": user_id,
            "username": user_name,
            "exp": expires_at,
        },
        JWT_SECRET,
        algorithm="HS256",
    )

    create_session(user_id, token, ip, expires_at)

    return {"token": token, "expires_at": expires_at.isoformat()}, None


def logout_user(token):
    row = deactivate_session(token)
    if row is None:
        return False, "Session not found"
    return True, None


def validate_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError:
        return None, "Invalid token"

    session = get_session_by_token(token)
    if session is None or not session[5]:  # is_active
        return None, "Session is not active"

    expires_at = session[4]  # expires_at column
    if expires_at < datetime.utcnow():
        return None, "Session has expired"

    return payload, None
