from db.database import get_connection, release_connection
from datetime import datetime, timezone


def log_security_event(ip, endpoint, method, attack_type, was_blocked, backend_key="direct"):
    """
    Logs every scanned request now, not just blocked ones (attack_type is
    the literal string "None" for clean traffic). This is what makes
    "total requests scanned" computable for the analytics dashboard -
    previously, only blocked events were ever recorded, so there was no way
    to know how much traffic had been scanned in total.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO security_logs (ip, endpoint, method, attack_type, was_blocked, backend_key, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (ip, endpoint, method, attack_type, was_blocked, backend_key, datetime.now(timezone.utc).replace(tzinfo=None)),
        )
        conn.commit()
    finally:
        cursor.close()
        release_connection(conn)


def get_request_count(ip, endpoint, backend_key="direct", window_seconds=60):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT request_count, is_blocked
            FROM rate_limit
            WHERE ip = %s AND endpoint = %s AND backend_key = %s
              AND window_start > NOW() - INTERVAL '%s seconds'
            """,
            (ip, endpoint, backend_key, window_seconds),
        )
        return cursor.fetchone()  # (request_count, is_blocked) or None
    finally:
        cursor.close()
        release_connection(conn)


def upsert_rate_limit(ip, endpoint, backend_key="direct", window_seconds=60):
    """
    Fix #6: the rate-limit bucket is now keyed by (ip, endpoint, backend_key)
    instead of just (ip, endpoint). Previously, two unrelated registered
    backends that both happened to expose a route with the same name (e.g.
    both have a `/data` endpoint) and were called from the same source IP
    would silently share one counter - a noisy/malicious client of backend A
    could trigger blocking of legitimate traffic to backend B's `/data` too.
    Scoping by backend_key (the caller's API key, or "direct" for calls made
    straight to /security/scan) isolates each backend's traffic.
    """
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
    """
    Bonus analytics dashboard data: total requests scanned vs. blocked,
    a breakdown of blocked requests by attack type, and an hourly timeline
    of blocked attacks over the requested lookback window.

    backend_key=None returns platform-wide totals across every backend;
    pass a specific backend's API key to scope the figures to just that
    backend.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        if backend_key:
            cursor.execute(
                """
                SELECT COUNT(*), COUNT(*) FILTER (WHERE was_blocked)
                FROM security_logs
                WHERE backend_key = %s
                """,
                (backend_key,),
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*), COUNT(*) FILTER (WHERE was_blocked)
                FROM security_logs
                """
            )
        total_scanned, total_blocked = cursor.fetchone()

        if backend_key:
            cursor.execute(
                """
                SELECT attack_type, COUNT(*)
                FROM security_logs
                WHERE was_blocked = true AND backend_key = %s
                GROUP BY attack_type
                ORDER BY COUNT(*) DESC
                """,
                (backend_key,),
            )
        else:
            cursor.execute(
                """
                SELECT attack_type, COUNT(*)
                FROM security_logs
                WHERE was_blocked = true
                GROUP BY attack_type
                ORDER BY COUNT(*) DESC
                """
            )
        breakdown = [{"attack_type": row[0], "count": row[1]} for row in cursor.fetchall()]

        if backend_key:
            cursor.execute(
                """
                SELECT date_trunc('hour', created_at) AS bucket, COUNT(*)
                FROM security_logs
                WHERE was_blocked = true
                  AND backend_key = %s
                  AND created_at > NOW() - INTERVAL '1 hour' * %s
                GROUP BY bucket
                ORDER BY bucket
                """,
                (backend_key, hours),
            )
        else:
            cursor.execute(
                """
                SELECT date_trunc('hour', created_at) AS bucket, COUNT(*)
                FROM security_logs
                WHERE was_blocked = true
                  AND created_at > NOW() - INTERVAL '1 hour' * %s
                GROUP BY bucket
                ORDER BY bucket
                """,
                (hours,),
            )
        timeline = [{"bucket": row[0].isoformat(), "count": row[1]} for row in cursor.fetchall()]

        return {
            "total_scanned": total_scanned or 0,
            "total_blocked": total_blocked or 0,
            "breakdown_by_attack_type": breakdown,
            "timeline": timeline,
        }
    finally:
        cursor.close()
        release_connection(conn)
