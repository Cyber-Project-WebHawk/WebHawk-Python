from db.database import get_connection, release_connection
from datetime import datetime


def log_security_event(ip, endpoint, method, attack_type, was_blocked, backend_key="direct"):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO security_logs
                (ip, endpoint, method, attack_type, was_blocked, backend_key, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (ip, endpoint, method, attack_type, was_blocked, backend_key, datetime.utcnow()),
        )
        conn.commit()
    finally:
        cursor.close()
        release_connection(conn)


def upsert_rate_limit(ip, endpoint, backend_key="direct", window_seconds=60):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO rate_limit (ip, endpoint, backend_key, request_count, window_start, is_blocked)
            VALUES (%s, %s, %s, 1, NOW(), false)
            ON CONFLICT (ip, endpoint, backend_key)
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
            (ip, endpoint, backend_key, window_seconds, window_seconds, window_seconds),
        )
        row = cursor.fetchone()
        conn.commit()
        return row  # (request_count, is_blocked)
    finally:
        cursor.close()
        release_connection(conn)


def get_dashboard_data(backend_key=None, hours=24):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        time_filter = "created_at >= NOW() - INTERVAL '%s hours'"
        time_params = [hours]
        scope_filter = ""
        scope_params = []
        if backend_key:
            scope_filter = " AND backend_key = %s"
            scope_params = [backend_key]

        cursor.execute(
            f"SELECT COUNT(*) FROM security_logs WHERE {time_filter}{scope_filter}",
            time_params + scope_params,
        )
        total_requests = cursor.fetchone()[0]

        cursor.execute(
            f"""
            SELECT COUNT(*) FROM security_logs
            WHERE was_blocked = true AND {time_filter}{scope_filter}
            """,
            time_params + scope_params,
        )
        total_blocked = cursor.fetchone()[0]

        cursor.execute(
            f"""
            SELECT attack_type, COUNT(*) FROM security_logs
            WHERE was_blocked = true AND {time_filter}{scope_filter}
            GROUP BY attack_type
            """,
            time_params + scope_params,
        )
        attacks_by_type = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(
            f"""
            SELECT DATE_TRUNC('hour', created_at) AS hour, COUNT(*) FROM security_logs
            WHERE was_blocked = true AND {time_filter}{scope_filter}
            GROUP BY hour
            ORDER BY hour
            """,
            time_params + scope_params,
        )
        hourly_timeline = [
            {"hour": str(row[0]), "blocked": row[1]} for row in cursor.fetchall()
        ]

        return {
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "attacks_by_type": attacks_by_type,
            "hourly_timeline": hourly_timeline,
        }
    finally:
        cursor.close()
        release_connection(conn)
