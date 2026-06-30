"""
Integration tests for the proxy's security scanning. These don't require a
live upstream backend - a blocked request never gets forwarded, so the
assertions only depend on WebHawk's own detection logic, not on
vulnerable_backend actually running.
"""


def _get_api_key(client):
    client.post("/auth/register", json={"username": "proxytester", "password": "secret123"})
    token = client.post(
        "/auth/login", json={"username": "proxytester", "password": "secret123"}
    ).get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    reg = client.post(
        "/backends/register",
        json={"name": "proxy-target", "target_url": "http://localhost:5001"},
        headers=headers,
    )
    return reg.get_json()["api_key"]


class TestProxyAuth:
    def test_proxy_requires_api_key(self, client):
        resp = client.post("/backends/proxy/login", json={"username": "admin", "password": "x"})
        assert resp.status_code == 401

    def test_proxy_rejects_unknown_api_key(self, client):
        resp = client.post(
            "/backends/proxy/login",
            json={"username": "admin", "password": "x"},
            headers={"X-API-Key": "not-a-real-key"},
        )
        assert resp.status_code == 401


class TestProxyAttackDetection:
    def test_blocks_sqli_in_body(self, client):
        api_key = _get_api_key(client)
        resp = client.post(
            "/backends/proxy/login",
            json={"username": "admin' OR 1=1 --", "password": "x"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 403
        assert resp.get_json()["attack_type"] == "SQLi"

    def test_blocks_xss_in_body(self, client):
        api_key = _get_api_key(client)
        resp = client.post(
            "/backends/proxy/comment",
            json={"text": "<script>alert(1)</script>"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 403
        assert resp.get_json()["attack_type"] == "XSS"

    def test_blocks_sqli_in_query_params(self, client):
        api_key = _get_api_key(client)
        resp = client.get(
            "/backends/proxy/data?id=1+UNION+SELECT+username%2Cpassword+FROM+users",
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 403

    def test_blocks_sqli_hidden_in_nested_json(self, client):
        """Regression test for the nested-JSON-traversal fix."""
        api_key = _get_api_key(client)
        resp = client.post(
            "/backends/proxy/comment",
            json={"meta": {"user": {"bio": "admin' OR 1=1 --"}}},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 403

    def test_does_not_block_clean_login_attempt(self, client):
        api_key = _get_api_key(client)
        # Whether the upstream is actually reachable in this environment
        # doesn't matter for this test - we're only asserting the security
        # layer doesn't flag it as an attack (a 502 from an unreachable
        # upstream is fine; a 403 attack block would not be).
        resp = client.post(
            "/backends/proxy/login",
            json={"username": "admin", "password": "admin123"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code != 403

    def test_allows_previously_false_positive_text(self, client):
        """Regression test for Fix #7 (SQLi false-positive reduction)."""
        api_key = _get_api_key(client)
        resp = client.post(
            "/backends/proxy/comment",
            json={"text": "width and height=100, please confirm"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code != 403
