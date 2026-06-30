"""Integration tests for /auth/* using a real Flask test client + test DB."""


class TestRegistration:
    def test_register_success(self, client):
        resp = client.post("/auth/register", json={"username": "alice", "password": "secret123"})
        assert resp.status_code == 201

    def test_register_duplicate_username(self, client):
        client.post("/auth/register", json={"username": "alice", "password": "secret123"})
        resp = client.post("/auth/register", json={"username": "alice", "password": "secret123"})
        assert resp.status_code == 409

    def test_register_missing_password(self, client):
        resp = client.post("/auth/register", json={"username": "alice"})
        assert resp.status_code == 400

    def test_register_null_body_does_not_crash(self, client):
        """Regression test for Fix #3 (request.json None guard)."""
        resp = client.post("/auth/register", data="null", content_type="application/json")
        assert resp.status_code == 400
        assert resp.is_json

    def test_register_malformed_json_returns_json_error_not_html(self, client):
        resp = client.post(
            "/auth/register", data='{"username": "bad", "password": }', content_type="application/json"
        )
        assert resp.status_code == 400
        assert resp.is_json


class TestLogin:
    def test_login_success(self, client):
        client.post("/auth/register", json={"username": "alice", "password": "secret123"})
        resp = client.post("/auth/login", json={"username": "alice", "password": "secret123"})
        assert resp.status_code == 200
        assert "token" in resp.get_json()

    def test_login_wrong_password(self, client):
        client.post("/auth/register", json={"username": "alice", "password": "secret123"})
        resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
        assert resp.status_code == 401

    def test_login_unknown_and_wrong_password_give_same_error(self, client):
        """No username-enumeration leak: both failure modes look identical."""
        resp1 = client.post("/auth/login", json={"username": "ghost", "password": "x"})
        client.post("/auth/register", json={"username": "alice", "password": "secret123"})
        resp2 = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
        assert resp1.status_code == resp2.status_code == 401
        assert resp1.get_json()["error"] == resp2.get_json()["error"]

    def test_rapid_repeated_logins_produce_distinct_tokens(self, client):
        """Regression test for the jti fix - two logins within the same
        second used to produce a byte-identical JWT and crash with an
        unhandled UNIQUE-constraint violation."""
        client.post("/auth/register", json={"username": "alice", "password": "secret123"})
        tokens = set()
        for _ in range(5):
            resp = client.post("/auth/login", json={"username": "alice", "password": "secret123"})
            assert resp.status_code == 200
            tokens.add(resp.get_json()["token"])
        assert len(tokens) == 5


class TestMe:
    def test_me_with_valid_token(self, auth_client):
        client, token = auth_client
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_me_without_token(self, client):
        resp = client.get("/auth/me")
        assert resp.status_code == 401

    def test_me_with_garbage_token(self, client):
        resp = client.get("/auth/me", headers={"Authorization": "Bearer not.a.real.token"})
        assert resp.status_code == 401

    def test_me_with_expired_token(self, client):
        import jwt
        from datetime import datetime, timedelta, timezone

        expired = jwt.encode(
            {
                "user_id": 1,
                "username": "alice",
                "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            },
            "pytest-test-secret-do-not-use-in-production",
            algorithm="HS256",
        )
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {expired}"})
        assert resp.status_code == 401
        assert "expired" in resp.get_json()["error"].lower()

    def test_me_with_token_signed_by_wrong_secret(self, client):
        import jwt
        from datetime import datetime, timedelta, timezone

        forged = jwt.encode(
            {
                "user_id": 1,
                "username": "alice",
                "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            },
            "a-different-secret-the-attacker-guessed",
            algorithm="HS256",
        )
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})
        assert resp.status_code == 401

    def test_me_rejects_alg_none_attack(self, client):
        import jwt
        from datetime import datetime, timedelta, timezone

        unsigned = jwt.encode(
            {
                "user_id": 1,
                "username": "alice",
                "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            },
            None,
            algorithm="none",
        )
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {unsigned}"})
        assert resp.status_code == 401


class TestLogout:
    def test_logout_then_me_fails(self, auth_client):
        client, token = auth_client
        client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_double_logout_is_404_not_200(self, auth_client):
        """Regression test for the logout-idempotency fix."""
        client, token = auth_client
        first = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        second = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert first.status_code == 200
        assert second.status_code == 404
