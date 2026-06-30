"""
WebHawk — Project Test Suite
Run from the project root: pytest tests/ -v
"""

import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Shared Flask test client
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    from app import app
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ===========================================================================
# 1. SECURITY ENGINE — unit tests (no DB required, pure logic)
# ===========================================================================

class TestSQLiDetection:
    """Tests for check_sqli() pattern matching."""

    def test_detects_or_1_equals_1(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("admin' OR 1=1 --") is True

    def test_detects_or_with_strings(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("' OR 'a'='a") is True

    def test_detects_union_select(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("' UNION SELECT * FROM users --") is True

    def test_detects_double_dash_comment(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("admin'--") is True

    def test_detects_hash_comment(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("admin'#") is True

    def test_detects_drop_table(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("DROP TABLE users") is True

    def test_detects_select_keyword(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("SELECT password FROM users") is True

    def test_detects_insert_keyword(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("INSERT INTO users VALUES (1,'x')") is True

    def test_allows_clean_username(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("john_doe123") is False

    def test_allows_normal_sentence(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("hello world this is a comment") is False

    def test_allows_email(self):
        from security_engine.service.security_service import check_sqli
        assert check_sqli("user@example.com") is False


class TestXSSDetection:
    """Tests for check_xss() pattern matching."""

    def test_detects_script_tag(self):
        from security_engine.service.security_service import check_xss
        assert check_xss("<script>alert(1)</script>") is True

    def test_detects_script_tag_with_spaces(self):
        from security_engine.service.security_service import check_xss
        assert check_xss("< script >alert(1)</ script >") is True

    def test_detects_javascript_protocol(self):
        from security_engine.service.security_service import check_xss
        assert check_xss("javascript:alert(1)") is True

    def test_detects_onerror_event(self):
        from security_engine.service.security_service import check_xss
        assert check_xss('<img onerror="alert(1)">') is True

    def test_detects_onclick_event(self):
        from security_engine.service.security_service import check_xss
        assert check_xss('<a onclick="steal()">click</a>') is True

    def test_detects_img_onerror_no_quotes(self):
        from security_engine.service.security_service import check_xss
        assert check_xss("<img src=x onerror=alert(1)>") is True

    def test_allows_clean_comment(self):
        from security_engine.service.security_service import check_xss
        assert check_xss("Great product, highly recommended!") is False

    def test_allows_plain_html_bold(self):
        from security_engine.service.security_service import check_xss
        assert check_xss("<b>bold text</b>") is False

    def test_allows_numbers(self):
        from security_engine.service.security_service import check_xss
        assert check_xss("12345") is False


class TestScanRequest:
    """Tests for scan_request() — the full detection pipeline."""

    @patch("security_engine.Service.security_service.upsert_rate_limit", return_value=(1, False))
    @patch("security_engine.Service.security_service.log_security_event")
    def test_blocks_sqli_in_body(self, mock_log, mock_rate):
        from security_engine.service.security_service import scan_request
        result = scan_request("127.0.0.1", "/login", "POST",
                              {"username": "admin' OR 1=1 --"}, {}, "/login")
        assert result["blocked"] is True
        assert result["attack_type"] == "SQLi"
        mock_log.assert_called_once()

    @patch("security_engine.Service.security_service.upsert_rate_limit", return_value=(1, False))
    @patch("security_engine.Service.security_service.log_security_event")
    def test_blocks_xss_in_body(self, mock_log, mock_rate):
        from security_engine.service.security_service import scan_request
        result = scan_request("127.0.0.1", "/comment", "POST",
                              {"text": "<script>alert(1)</script>"}, {}, "/comment")
        assert result["blocked"] is True
        assert result["attack_type"] == "XSS"

    @patch("security_engine.Service.security_service.upsert_rate_limit", return_value=(1, False))
    @patch("security_engine.Service.security_service.log_security_event")
    def test_blocks_sqli_in_query_params(self, mock_log, mock_rate):
        from security_engine.service.security_service import scan_request
        result = scan_request("127.0.0.1", "/search", "GET",
                              {}, {"q": "' OR 1=1 --"}, "/search")
        assert result["blocked"] is True
        assert result["attack_type"] == "SQLi"

    @patch("security_engine.Service.security_service.upsert_rate_limit", return_value=(101, True))
    @patch("security_engine.Service.security_service.log_security_event")
    def test_blocks_rate_limit(self, mock_log, mock_rate):
        from security_engine.service.security_service import scan_request
        result = scan_request("127.0.0.1", "/data", "GET", {}, {}, "/data")
        assert result["blocked"] is True
        assert result["attack_type"] == "Rate Limiting"

    @patch("security_engine.Service.security_service.upsert_rate_limit", return_value=(1, False))
    def test_allows_clean_request(self, mock_rate):
        from security_engine.service.security_service import scan_request
        result = scan_request("127.0.0.1", "/data", "GET", {}, {}, "/data")
        assert result["blocked"] is False
        assert result["attack_type"] is None

    @patch("security_engine.Service.security_service.upsert_rate_limit", return_value=(101, True))
    @patch("security_engine.Service.security_service.log_security_event")
    def test_sqli_takes_priority_over_rate_limit(self, mock_log, mock_rate):
        from security_engine.service.security_service import scan_request
        result = scan_request("127.0.0.1", "/login", "POST",
                              {"username": "admin' OR 1=1 --"}, {}, "/login")
        assert result["attack_type"] == "SQLi"

    @patch("security_engine.Service.security_service.upsert_rate_limit", return_value=(1, False))
    def test_logs_clean_request_as_unblocked(self, mock_rate):
        from security_engine.service.security_service import scan_request
        with patch("security_engine.Service.security_service.log_security_event") as mock_log:
            scan_request("127.0.0.1", "/data", "GET", {}, {}, "/data")
            mock_log.assert_called_once()
            assert mock_log.call_args[0][4] is False  # was_blocked = False


# ===========================================================================
# 2. AUTH ENDPOINTS — /auth/*
# ===========================================================================

class TestRegister:
    @patch("Route.user_route.register_user",
           return_value=({"id": 1, "username": "romi", "created_at": "2026-01-01T00:00:00"}, None))
    def test_success_returns_201(self, mock_reg, client):
        resp = client.post("/auth/register", json={"username": "romi", "password": "pass123"})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["message"] == "User registered successfully"
        assert data["user"]["username"] == "romi"

    @patch("Route.user_route.register_user", return_value=(None, "Username already exists"))
    def test_duplicate_username_returns_409(self, mock_reg, client):
        resp = client.post("/auth/register", json={"username": "romi", "password": "pass123"})
        assert resp.status_code == 409
        assert "error" in resp.get_json()

    def test_missing_username_returns_400(self, client):
        resp = client.post("/auth/register", json={"password": "pass123"})
        assert resp.status_code == 400

    def test_missing_password_returns_400(self, client):
        resp = client.post("/auth/register", json={"username": "romi"})
        assert resp.status_code == 400

    def test_empty_body_returns_400(self, client):
        resp = client.post("/auth/register", json={})
        assert resp.status_code == 400


class TestLogin:
    @patch("Route.user_route.login_user",
           return_value=({"token": "abc.def.ghi", "expires_at": "2026-06-30T12:00:00"}, None))
    def test_success_returns_200_with_token(self, mock_login, client):
        resp = client.post("/auth/login", json={"username": "romi", "password": "pass123"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert "expires_at" in data

    @patch("Route.user_route.login_user", return_value=(None, "Invalid credentials"))
    def test_wrong_credentials_returns_401(self, mock_login, client):
        resp = client.post("/auth/login", json={"username": "romi", "password": "wrong"})
        assert resp.status_code == 401

    def test_missing_password_returns_400(self, client):
        resp = client.post("/auth/login", json={"username": "romi"})
        assert resp.status_code == 400

    def test_missing_username_returns_400(self, client):
        resp = client.post("/auth/login", json={"password": "pass123"})
        assert resp.status_code == 400


class TestLogout:
    @patch("Route.user_route.logout_user", return_value=(True, None))
    def test_success_returns_200(self, mock_logout, client):
        resp = client.post("/auth/logout",
                           headers={"Authorization": "Bearer sometoken"})
        assert resp.status_code == 200
        assert resp.get_json()["message"] == "Logged out successfully"

    @patch("Route.user_route.logout_user", return_value=(False, "Session not found"))
    def test_unknown_token_returns_404(self, mock_logout, client):
        resp = client.post("/auth/logout",
                           headers={"Authorization": "Bearer badtoken"})
        assert resp.status_code == 404

    def test_no_authorization_header_returns_401(self, client):
        resp = client.post("/auth/logout")
        assert resp.status_code == 401


class TestMe:
    @patch("Route.user_route.validate_token",
           return_value=({"user_id": 1, "username": "romi"}, None))
    def test_valid_token_returns_user(self, mock_validate, client):
        resp = client.get("/auth/me",
                          headers={"Authorization": "Bearer validtoken"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["user_id"] == 1
        assert data["username"] == "romi"

    @patch("Route.user_route.validate_token", return_value=(None, "Token has expired"))
    def test_expired_token_returns_401(self, mock_validate, client):
        resp = client.get("/auth/me",
                          headers={"Authorization": "Bearer expiredtoken"})
        assert resp.status_code == 401

    @patch("Route.user_route.validate_token", return_value=(None, "Invalid token"))
    def test_invalid_token_returns_401(self, mock_validate, client):
        resp = client.get("/auth/me",
                          headers={"Authorization": "Bearer garbage"})
        assert resp.status_code == 401

    def test_no_token_returns_401(self, client):
        resp = client.get("/auth/me")
        assert resp.status_code == 401


# ===========================================================================
# 3. BACKEND ENDPOINTS — /backends/*
# ===========================================================================

AUTH_HEADER = {"Authorization": "Bearer validtoken"}
VALID_USER_PAYLOAD = {"user_id": 1, "username": "romi"}


class TestBackendRegister:
    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    @patch("Route.backend_route.create_backend", return_value=(
        {"id": 1, "name": "my-api",
         "target_url": "http://localhost:5001",
         "api_key": "test-uuid-key", "is_active": True},
        None
    ))
    def test_success_returns_201_with_api_key(self, mock_create, mock_auth, client):
        resp = client.post("/backends/register", headers=AUTH_HEADER,
                           json={"name": "my-api", "target_url": "http://localhost:5001"})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "my-api"
        assert "api_key" in data
        assert data["is_active"] is True

    def test_no_token_returns_401(self, client):
        resp = client.post("/backends/register",
                           json={"name": "my-api", "target_url": "http://localhost:5001"})
        assert resp.status_code == 401

    @patch("Route.backend_route.validate_token", return_value=(None, "Invalid token"))
    def test_invalid_token_returns_401(self, mock_auth, client):
        resp = client.post("/backends/register", headers={"Authorization": "Bearer bad"},
                           json={"name": "my-api", "target_url": "http://localhost:5001"})
        assert resp.status_code == 401

    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    def test_missing_name_returns_400(self, mock_auth, client):
        resp = client.post("/backends/register", headers=AUTH_HEADER,
                           json={"target_url": "http://localhost:5001"})
        assert resp.status_code == 400

    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    def test_missing_target_url_returns_400(self, mock_auth, client):
        resp = client.post("/backends/register", headers=AUTH_HEADER,
                           json={"name": "my-api"})
        assert resp.status_code == 400

    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    def test_empty_body_returns_400(self, mock_auth, client):
        resp = client.post("/backends/register", headers=AUTH_HEADER, json={})
        assert resp.status_code == 400


class TestBackendList:
    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    @patch("Route.backend_route.list_backends", return_value=[
        {"id": 1, "name": "api1", "target_url": "http://localhost:5001",
         "api_key": "key1", "is_active": True},
        {"id": 2, "name": "api2", "target_url": "http://localhost:5002",
         "api_key": "key2", "is_active": False},
    ])
    def test_returns_all_backends(self, mock_list, mock_auth, client):
        resp = client.get("/backends/", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 2

    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    @patch("Route.backend_route.list_backends", return_value=[])
    def test_returns_empty_list_when_no_backends(self, mock_list, mock_auth, client):
        resp = client.get("/backends/", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_no_token_returns_401(self, client):
        resp = client.get("/backends/")
        assert resp.status_code == 401


class TestBackendActivate:
    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    @patch("Route.backend_route.activate_backend",
           return_value={"id": 1, "name": "api1", "is_active": True})
    def test_activate_success(self, mock_activate, mock_auth, client):
        resp = client.patch("/backends/activate", headers=AUTH_HEADER,
                            json={"api_key": "key1"})
        assert resp.status_code == 200
        assert resp.get_json()["is_active"] is True

    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    @patch("Route.backend_route.activate_backend", return_value=None)
    def test_activate_unknown_key_returns_404(self, mock_activate, mock_auth, client):
        resp = client.patch("/backends/activate", headers=AUTH_HEADER,
                            json={"api_key": "nonexistent"})
        assert resp.status_code == 404

    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    def test_activate_missing_key_returns_400(self, mock_auth, client):
        resp = client.patch("/backends/activate", headers=AUTH_HEADER, json={})
        assert resp.status_code == 400

    def test_activate_no_token_returns_401(self, client):
        resp = client.patch("/backends/activate", json={"api_key": "key1"})
        assert resp.status_code == 401


class TestBackendDeactivate:
    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    @patch("Route.backend_route.deactivate_backend",
           return_value={"id": 1, "name": "api1", "is_active": False})
    def test_deactivate_success(self, mock_deactivate, mock_auth, client):
        resp = client.patch("/backends/deactivate", headers=AUTH_HEADER,
                            json={"api_key": "key1"})
        assert resp.status_code == 200
        assert resp.get_json()["is_active"] is False

    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    @patch("Route.backend_route.deactivate_backend", return_value=None)
    def test_deactivate_unknown_key_returns_404(self, mock_deactivate, mock_auth, client):
        resp = client.patch("/backends/deactivate", headers=AUTH_HEADER,
                            json={"api_key": "nonexistent"})
        assert resp.status_code == 404

    @patch("Route.backend_route.validate_token", return_value=(VALID_USER_PAYLOAD, None))
    def test_deactivate_missing_key_returns_400(self, mock_auth, client):
        resp = client.patch("/backends/deactivate", headers=AUTH_HEADER, json={})
        assert resp.status_code == 400

    def test_deactivate_no_token_returns_401(self, client):
        resp = client.patch("/backends/deactivate", json={"api_key": "key1"})
        assert resp.status_code == 401


class TestProxy:
    @patch("Route.backend_route.scan_request",
           return_value={"blocked": True, "attack_type": "SQLi", "request_count": 1})
    def test_blocks_sqli(self, mock_scan, client):
        resp = client.post(
            "/backends/proxy/login",
            headers={"X-API-Key": "somekey"},
            json={"username": "admin' OR 1=1 --", "password": "x"},
        )
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["status"] == "blocked"
        assert data["attack_type"] == "SQLi"
        assert "message" in data

    @patch("Route.backend_route.scan_request",
           return_value={"blocked": True, "attack_type": "XSS", "request_count": 1})
    def test_blocks_xss(self, mock_scan, client):
        resp = client.post(
            "/backends/proxy/comment",
            headers={"X-API-Key": "somekey"},
            json={"text": "<script>alert(1)</script>"},
        )
        assert resp.status_code == 403
        assert resp.get_json()["attack_type"] == "XSS"

    @patch("Route.backend_route.scan_request",
           return_value={"blocked": True, "attack_type": "Rate Limiting", "request_count": 101})
    def test_blocks_rate_limit(self, mock_scan, client):
        resp = client.get("/backends/proxy/data", headers={"X-API-Key": "somekey"})
        assert resp.status_code == 403
        assert resp.get_json()["attack_type"] == "Rate Limiting"

    def test_missing_api_key_returns_401(self, client):
        resp = client.post("/backends/proxy/login",
                           json={"username": "admin", "password": "pass"})
        assert resp.status_code == 401

    @patch("Route.backend_route.scan_request",
           return_value={"blocked": False, "attack_type": None, "request_count": 1})
    @patch("Route.backend_route.proxy_request",
           return_value=({"message": "Welcome admin!", "role": "admin"}, 200))
    def test_clean_request_forwarded_to_backend(self, mock_proxy, mock_scan, client):
        resp = client.post(
            "/backends/proxy/login",
            headers={"X-API-Key": "validkey"},
            json={"username": "admin", "password": "admin123"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["message"] == "Welcome admin!"

    @patch("Route.backend_route.scan_request",
           return_value={"blocked": False, "attack_type": None, "request_count": 1})
    @patch("Route.backend_route.proxy_request",
           return_value=({"error": "Unknown API key"}, 401))
    def test_invalid_api_key_rejected_by_proxy(self, mock_proxy, mock_scan, client):
        resp = client.post(
            "/backends/proxy/login",
            headers={"X-API-Key": "badkey"},
            json={"username": "admin", "password": "admin123"},
        )
        assert resp.status_code == 401


# ===========================================================================
# 4. SECURITY SCAN ENDPOINT — /security/scan
# ===========================================================================

class TestSecurityScanEndpoint:
    @patch("security_engine.Route.security_route.scan_request",
           return_value={"blocked": True, "attack_type": "SQLi", "request_count": 1})
    def test_scan_blocks_sqli(self, mock_scan, client):
        resp = client.post("/security/scan", json={
            "endpoint": "/login", "method": "POST",
            "body": {"username": "admin' OR 1=1 --"},
            "query_params": {}, "path": "/login",
        })
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["status"] == "blocked"
        assert data["attack_type"] == "SQLi"

    @patch("security_engine.Route.security_route.scan_request",
           return_value={"blocked": True, "attack_type": "XSS", "request_count": 1})
    def test_scan_blocks_xss(self, mock_scan, client):
        resp = client.post("/security/scan", json={
            "endpoint": "/comment", "method": "POST",
            "body": {"text": "<script>alert(1)</script>"},
            "query_params": {}, "path": "/comment",
        })
        assert resp.status_code == 403
        assert resp.get_json()["attack_type"] == "XSS"

    @patch("security_engine.Route.security_route.scan_request",
           return_value={"blocked": False, "attack_type": None, "request_count": 1})
    def test_scan_allows_clean_request(self, mock_scan, client):
        resp = client.post("/security/scan", json={
            "endpoint": "/data", "method": "GET",
            "body": {}, "query_params": {}, "path": "/data",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "allowed"
        assert data["message"] == "Request passed security scan"
