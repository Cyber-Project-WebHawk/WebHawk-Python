import psycopg2
from db.database import get_connection, release_connection


def register_backend(name, target_url, api_key, user_id):
    """
    Fix #4/#9: backends are now owned by a user, and name uniqueness is
    enforced per-owner at the database level (see create_tables.py). We
    INSERT directly and let the UNIQUE constraint catch collisions rather
    than doing a separate "check then insert" - that avoids a race condition
    where two concurrent requests could both pass a pre-check and then both
    insert.

    Returns (row, error). On success: (row, None) where row is
    (id, name, target_url, api_key, is_active, user_id).
    On a name collision: (None, "duplicate_name").
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO backend_registration (name, target_url, api_key, is_active, user_id)
            VALUES (%s, %s, %s, true, %s)
            RETURNING id, name, target_url, api_key, is_active, user_id
            """,
            (name, target_url, api_key, user_id),
        )
        row = cursor.fetchone()
        conn.commit()
        return row, None
    except psycopg2.errors.UniqueViolation as e:
        conn.rollback()
        constraint = getattr(e.diag, "constraint_name", "") or ""
        if "name" in constraint:
            return None, "duplicate_name"
        return None, "duplicate_key"
    finally:
        cursor.close()
        release_connection(conn)


def get_backend_by_api_key(api_key):
    """
    Used by the proxy. Intentionally NOT scoped by user_id - the proxy is
    called by the *backend's own end users* using the X-API-Key header, not
    by the WebHawk dashboard owner, so there is no JWT/user context here.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT id, name, target_url, api_key, is_active, user_id
            FROM backend_registration
            WHERE api_key = %s
            """,
            (api_key,),
        )
        return cursor.fetchone()  # (id, name, target_url, api_key, is_active, user_id) or None
    finally:
        cursor.close()
        release_connection(conn)


def get_backends_by_user(user_id):
    """
    Fix #4: listing is now scoped to the authenticated caller's own backends.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT id, name, target_url, api_key, is_active, user_id
            FROM backend_registration
            WHERE user_id = %s
            ORDER BY id
            """,
            (user_id,),
        )
        return cursor.fetchall()
    finally:
        cursor.close()
        release_connection(conn)


def update_backend_status(api_key, is_active, user_id):
    """
    Fix #4: activate/deactivate now requires matching BOTH the api_key AND
    the owning user_id, so one tenant can no longer disable another
    tenant's backend just by knowing (or guessing/scraping) its API key.
    If the api_key exists but belongs to someone else, this returns None,
    same as if it didn't exist at all - so the endpoint can't be used to
    enumerate which API keys are valid for other accounts.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            UPDATE backend_registration
            SET is_active = %s
            WHERE api_key = %s AND user_id = %s
            RETURNING id, name, is_active
            """,
            (is_active, api_key, user_id),
        )
        row = cursor.fetchone()
        conn.commit()
        return row  # (id, name, is_active) or None
    finally:
        cursor.close()
        release_connection(conn)
