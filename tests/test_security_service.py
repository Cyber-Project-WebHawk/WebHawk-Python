"""
Pure unit tests for the attack-detection engine - no database, no Flask app,
just the detection functions themselves. These are fast and a good first
line of defense; the slower integration tests in test_proxy.py exercise the
same logic through the real HTTP layer.
"""
from security_engine.service.security_service import check_sqli, check_xss, _extract_strings


class TestSQLiDetection:
    def test_detects_classic_or_tautology(self):
        assert check_sqli("admin' OR 1=1 --") is True

    def test_detects_union_select(self):
        assert check_sqli("1 UNION SELECT username, password FROM users") is True

    def test_detects_drop_table(self):
        assert check_sqli("1; DROP TABLE users;") is True

    def test_detects_sql_comment_marker(self):
        assert check_sqli("admin'--") is True

    def test_detects_insert_into(self):
        assert check_sqli("'; INSERT INTO users (username) VALUES ('hacker'); --") is True

    # Regression tests for Fix #7 (false-positive reduction)
    def test_allows_ordinary_text_with_and_equals(self):
        assert check_sqli("width and height=100, please confirm") is False

    def test_allows_select_as_ordinary_verb(self):
        assert check_sqli("please select your country") is False

    def test_allows_update_as_ordinary_verb(self):
        assert check_sqli("update your profile settings") is False

    def test_allows_delete_as_ordinary_verb_without_from(self):
        assert check_sqli("delete this item") is False


class TestXSSDetection:
    def test_detects_script_tag(self):
        assert check_xss("<script>alert(1)</script>") is True

    def test_detects_img_onerror(self):
        assert check_xss('<img src=x onerror="alert(1)">') is True

    def test_detects_javascript_protocol(self):
        assert check_xss("javascript:alert(1)") is True

    def test_allows_clean_text(self):
        assert check_xss("just a normal comment, nothing weird here") is False


class TestExtractStringsRecursion:
    """Regression tests for the nested-JSON-traversal fix."""

    def test_flat_dict_values(self):
        result = _extract_strings({"a": "hello", "b": "world"})
        assert "hello" in result and "world" in result

    def test_nested_dict_two_levels_deep(self):
        result = _extract_strings({"meta": {"user": {"bio": "payload"}}})
        assert "payload" in result

    def test_list_inside_dict(self):
        result = _extract_strings({"tags": ["a", "payload"]})
        assert "payload" in result

    def test_dict_inside_list_inside_dict(self):
        result = _extract_strings({"items": [{"name": "ok"}, {"name": "payload"}]})
        assert "payload" in result

    def test_dict_keys_are_scanned_too(self):
        result = _extract_strings({"<script>alert(1)</script>": "harmless value"})
        assert any("<script>" in s for s in result)

    def test_non_string_scalars_do_not_crash(self):
        result = _extract_strings({"count": 5, "active": True, "ratio": 1.5, "nothing": None})
        assert isinstance(result, list)

    def test_pathological_depth_does_not_crash_or_hang(self):
        deeply_nested = {}
        current = deeply_nested
        for _ in range(50):
            current["next"] = {}
            current = current["next"]
        current["payload"] = "deep value"
        result = _extract_strings(deeply_nested)  # must return, not raise/hang
        assert isinstance(result, list)
