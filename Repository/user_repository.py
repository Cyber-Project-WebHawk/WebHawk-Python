from db.database import get_connection, release_connection
from datetime import datetime, timezone
import psycopg2


def create_user(username, hashed_password):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO users (username, password, created_at)
            VALUES (%s, %s, %s)
            RETURNING id, username, created_at
            """,
            (username, hashed_password, datetime.now(timezone.utc).replace(tzinfo=None)),
        )
        row = cursor.fetchone()
        conn.commit()
        return row  # (id, username, created_at)
    finally:
        cursor.close()
        release_connection(conn)


def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT id, username, password
            FROM users
            WHERE username = %s
            """,
            (username,),
        )
        return cursor.fetchone()  # (id, username, password) or None
    finally:
        cursor.close()
        release_connection(conn)


def create_session(user_id, token, ip, expires_at):
    """
    Returns the new session's id, or None if the insert failed (e.g. a
    UNIQUE violation on `token` - which the `jti` claim in the JWT payload
    makes vanishingly unlikely, but this is still a real database
    constraint, so we handle it rather than letting it raise unhandled).
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO user_sessions (user_id, token, ip, created_at, expires_at, is_active)
            VALUES (%s, %s, %s, %s, %s, true)
            RETURNING id
            """,
            (user_id, token, ip, datetime.now(timezone.utc).replace(tzinfo=None), expires_at),
        )
        row = cursor.fetchone()
        conn.commit()
        return row[0]  # session id
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return None
    finally:
        cursor.close()
        release_connection(conn)


def get_session_by_token(token):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT id, user_id, token, ip, expires_at, is_active
            FROM user_sessions
            WHERE token = %s
            """,
            (token,),
        )
        return cursor.fetchone()  # (id, user_id, token, ip, expires_at, is_active) or None
    finally:
        cursor.close()
        release_connection(conn)


def deactivate_session(token):
    """
    Only matches a currently-active session. A token that's already logged
    out (or never existed) now consistently returns None either way - no
    information is leaked about which case it was, and the Route layer can
    return a clean 404 instead of a false "Logged out successfully".
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            UPDATE user_sessions
            SET is_active = false
            WHERE token = %s AND is_active = true
            RETURNING id
            """,
            (token,),
        )
        row = cursor.fetchone()
        conn.commit()
        return row  # (id,) or None if no active session matched
    finally:
        cursor.close()
        release_connection(conn)
