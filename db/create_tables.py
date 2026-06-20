from database import get_connection


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            username   VARCHAR(100) NOT NULL UNIQUE,
            password   VARCHAR(255) NOT NULL,
            created_at TIMESTAMP    NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER      NOT NULL REFERENCES users(id),
            token      TEXT         NOT NULL UNIQUE,
            ip         VARCHAR(45)  NOT NULL,
            created_at TIMESTAMP    NOT NULL,
            expires_at TIMESTAMP    NOT NULL,
            is_active  BOOLEAN      NOT NULL DEFAULT true
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backend_registration (
            id         SERIAL PRIMARY KEY,
            name       VARCHAR(100) NOT NULL,
            target_url VARCHAR(255) NOT NULL,
            api_key    VARCHAR(100) NOT NULL UNIQUE,
            is_active  BOOLEAN      NOT NULL DEFAULT true
        );
    """)

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
