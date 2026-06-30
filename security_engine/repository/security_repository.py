from db.database import get_connection
from datetime import datetime


def log_security_event(ip, endpoint, method, attack_type, was_blocked, backend_key="direct"):
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


def upsert_rate_limit(ip, endpoint, backend_key="direct", window_seconds=60):
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


def get_dashboard_data(backend_key=None, hours=24):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*) FROM security_logs
        WHERE created_at >= NOW() - INTERVAL '%s hours'
        """,
        (hours,),
    )
    total_requests = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*) FROM security_logs
        WHERE was_blocked = true
          AND created_at >= NOW() - INTERVAL '%s hours'
        """,
        (hours,),
    )
    total_blocked = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT attack_type, COUNT(*) FROM security_logs
        WHERE was_blocked = true
          AND created_at >= NOW() - INTERVAL '%s hours'
        GROUP BY attack_type
        """,
        (hours,),
    )
    attacks_by_type = {row[0]: row[1] for row in cursor.fetchall()}

    cursor.execute(
        """
        SELECT DATE_TRUNC('hour', created_at) AS hour, COUNT(*) FROM security_logs
        WHERE was_blocked = true
          AND created_at >= NOW() - INTERVAL '%s hours'
        GROUP BY hour
        ORDER BY hour
        """,
        (hours,),
    )
    hourly_timeline = [
        {"hour": str(row[0]), "blocked": row[1]} for row in cursor.fetchall()
    ]

    cursor.close()
    conn.close()

    return {
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "attacks_by_type": attacks_by_type,
        "hourly_timeline": hourly_timeline,
    }
