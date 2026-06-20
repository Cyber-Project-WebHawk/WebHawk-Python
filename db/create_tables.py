from database import get_connection


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id          SERIAL PRIMARY KEY,
            ip          VARCHAR(45)  NOT NULL,
            endpoint    VARCHAR(255) NOT NULL,
            method      VARCHAR(10)  NOT NULL,
            attack_type VARCHAR(50)  NOT NULL,
            was_blocked BOOLEAN      NOT NULL,
            created_at  TIMESTAMP    NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rate_limit (
            id            SERIAL PRIMARY KEY,
            ip            VARCHAR(45)  NOT NULL,
            endpoint      VARCHAR(255) NOT NULL,
            request_count INTEGER      NOT NULL DEFAULT 1,
            window_start  TIMESTAMP    NOT NULL DEFAULT NOW(),
            is_blocked    BOOLEAN      NOT NULL DEFAULT false,
            UNIQUE (ip, endpoint)
        );
    """)

    conn.commit()
    cursor.close()
    conn.close()
    print("Tables created successfully.")


if __name__ == "__main__":
    create_tables()
