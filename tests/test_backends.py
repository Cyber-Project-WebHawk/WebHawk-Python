"""Integration tests for /backends/* ownership, auth, and uniqueness."""


def _register_and_login(client, username):
    client.post("/auth/register", json={"username": username, "password": "secret123"})
    resp = client.post("/auth/login", json={"username": username, "password": "secret123"})
    return resp.get_json()["token"]


class TestBackendAuth:
    def test_register_requires_auth(self, client):
        resp = client.post(
            "/backends/register", json={"name": "x", "target_url": "http://localhost:5001"}
        )
        assert resp.status_code == 401

    def test_list_requires_auth(self, client):
        resp = client.get("/backends/")
        assert resp.status_code == 401

    def test_activate_requires_auth(self, client):
        resp = client.patch("/backends/activate", json={"api_key": "whatever"})
        assert resp.status_code == 401

    def test_deactivate_requires_auth(self, client):
        resp = client.patch("/backends/deactivate", json={"api_key": "whatever"})
        assert resp.status_code == 401


class TestBackendRegistrationAndListing:
    def test_register_and_list(self, auth_client):
        client, token = auth_client
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.post(
            "/backends/register",
            json={"name": "my-api", "target_url": "http://localhost:5001"},
            headers=headers,
        )
        assert resp.status_code == 201
        assert "api_key" in resp.get_json()

        listing = client.get("/backends/", headers=headers)
        assert listing.status_code == 200
        backends = listing.get_json()
        assert len(backends) == 1
        assert "api_key" not in backends[0]  # only shown once, at creation

    def test_list_only_shows_own_backends(self, client):
        t1 = _register_and_login(client, "u1")
        t2 = _register_and_login(client, "u2")

        client.post(
            "/backends/register",
            json={"name": "u1-api", "target_url": "http://localhost:5001"},
            headers={"Authorization": f"Bearer {t1}"},
        )

        listing = client.get("/backends/", headers={"Authorization": f"Bearer {t2}"})
        assert listing.status_code == 200
        assert listing.get_json() == []


class TestBackendNameUniqueness:
    def test_duplicate_name_same_user_rejected(self, auth_client):
        client, token = auth_client
        headers = {"Authorization": f"Bearer {token}"}
        client.post(
            "/backends/register", json={"name": "dup", "target_url": "http://localhost:5001"}, headers=headers
        )
        resp = client.post(
            "/backends/register", json={"name": "dup", "target_url": "http://localhost:5001"}, headers=headers
        )
        assert resp.status_code == 409

    def test_same_name_different_owner_allowed(self, client):
        t1 = _register_and_login(client, "u1")
        t2 = _register_and_login(client, "u2")

        r1 = client.post(
            "/backends/register",
            json={"name": "shared-name", "target_url": "http://localhost:5001"},
            headers={"Authorization": f"Bearer {t1}"},
        )
        r2 = client.post(
            "/backends/register",
            json={"name": "shared-name", "target_url": "http://localhost:5001"},
            headers={"Authorization": f"Bearer {t2}"},
        )
        assert r1.status_code == 201
        assert r2.status_code == 201


class TestBackendOwnershipEnforcement:
    def test_cannot_deactivate_other_users_backend(self, client):
        t_owner = _register_and_login(client, "owner")
        reg = client.post(
            "/backends/register",
            json={"name": "private-api", "target_url": "http://localhost:5001"},
            headers={"Authorization": f"Bearer {t_owner}"},
        )
        api_key = reg.get_json()["api_key"]

        t_intruder = _register_and_login(client, "intruder")
        resp = client.patch(
            "/backends/deactivate",
            json={"api_key": api_key},
            headers={"Authorization": f"Bearer {t_intruder}"},
        )
        # 404, not 403 - doesn't reveal that the key exists for someone else.
        assert resp.status_code == 404

    def test_owner_can_deactivate_and_reactivate_own_backend(self, auth_client):
        client, token = auth_client
        headers = {"Authorization": f"Bearer {token}"}
        reg = client.post(
            "/backends/register",
            json={"name": "my-api", "target_url": "http://localhost:5001"},
            headers=headers,
        )
        api_key = reg.get_json()["api_key"]

        deactivate_resp = client.patch("/backends/deactivate", json={"api_key": api_key}, headers=headers)
        assert deactivate_resp.status_code == 200

        activate_resp = client.patch("/backends/activate", json={"api_key": api_key}, headers=headers)
        assert activate_resp.status_code == 200
