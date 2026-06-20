from db.database import get_connection
from datetime import datetime


def log_security_event(ip, endpoint, method, attack_type, was_blocked):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO security_logs (ip, endpoint, method, attack_type, was_blocked, created_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (ip, endpoint, method, attack_type, was_blocked, datetime.utcnow()),
    )
    conn.commit()
    cursor.close()
    conn.close()


def get_request_count(ip, endpoint, window_seconds=60):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT request_count, is_blocked
        FROM rate_limit
        WHERE ip = %s AND endpoint = %s
          AND window_start > NOW() - INTERVAL '%s seconds'
        """,
        (ip, endpoint, window_seconds),
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row  # (request_count, is_blocked) or None


def upsert_rate_limit(ip, endpoint, window_seconds=60):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO rate_limit (ip, endpoint, request_count, window_start, is_blocked)
        VALUES (%s, %s, 1, NOW(), false)
        ON CONFLICT (ip, endpoint)
        DO UPDATE SET
            request_count = CASE
                WHEN rate_limit.window_start > NOW() - INTERVAL '%s seconds'
                THEN rate_limit.request_count + 1
                ELSE 1
            END,
            window_start = CASE
                WHEN rate_limit.window_start > NOW() - INTERVAL '%s seconds'
                THEN rate_limit.window_start
                ELSE NOW()
            END,
            is_blocked = CASE
                WHEN rate_limit.window_start > NOW() - INTERVAL '%s seconds'
                     AND rate_limit.request_count + 1 > 100
                THEN true
                ELSE false
            END
        RETURNING request_count, is_blocked
        """,
        (ip, endpoint, window_seconds, window_seconds, window_seconds),
    )
    row = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    return row  # (request_count, is_blocked)
