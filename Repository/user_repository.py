from db.database import get_connection
from datetime import datetime


def create_user(username, hashed_password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO users (username, password, created_at)
        VALUES (%s, %s, %s)
        RETURNING id, username, created_at
        """,
        (username, hashed_password, datetime.utcnow()),
    )
    row = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    return row  # (id, username, created_at)


def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, username, password
        FROM users
        WHERE username = %s
        """,
        (username,),
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row  # (id, username, password) or None


def create_session(user_id, token, ip, expires_at):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO user_sessions (user_id, token, ip, created_at, expires_at, is_active)
        VALUES (%s, %s, %s, %s, %s, true)
        RETURNING id
        """,
        (user_id, token, ip, datetime.utcnow(), expires_at),
    )
    row = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    return row[0]  # session id


def get_session_by_token(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, user_id, token, ip, expires_at, is_active
        FROM user_sessions
        WHERE token = %s
        """,
        (token,),
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row  # (id, user_id, token, ip, expires_at, is_active) or None


def deactivate_session(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE user_sessions
        SET is_active = false
        WHERE token = %s
        RETURNING id
        """,
        (token,),
    )
    row = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    return row  # (id,) or None if token not found
