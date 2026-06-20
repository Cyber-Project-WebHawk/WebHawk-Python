from db.database import get_connection


def register_backend(name, target_url, api_key):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO backend_registration (name, target_url, api_key, is_active)
        VALUES (%s, %s, %s, true)
        RETURNING id, name, target_url, api_key, is_active
        """,
        (name, target_url, api_key),
    )
    row = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    return row  # (id, name, target_url, api_key, is_active)


def get_backend_by_api_key(api_key):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, name, target_url, api_key, is_active
        FROM backend_registration
        WHERE api_key = %s
        """,
        (api_key,),
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row  # (id, name, target_url, api_key, is_active) or None


def get_all_backends():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, name, target_url, api_key, is_active
        FROM backend_registration
        ORDER BY id
        """
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def update_backend_status(api_key, is_active):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE backend_registration
        SET is_active = %s
        WHERE api_key = %s
        RETURNING id, name, is_active
        """,
        (is_active, api_key),
    )
    row = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    return row  # (id, name, is_active) or None if api_key not found
