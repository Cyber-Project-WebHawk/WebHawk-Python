import re
from security_engine.repository.security_repository import log_security_event, upsert_rate_limit

SQLI_PATTERNS = [
    r"(\s|'|\")(or|and)\s+[\w'\"]+\s*=\s*[\w'\"]+",  # OR 1=1, AND 'a'='a'
    r"(--|#|/\*)",                                      # SQL comments
    r"(drop|insert|delete|update|select)\s+",           # SQL keywords
    r"union\s+select",                                  # UNION SELECT
]

XSS_PATTERNS = [
    r"<\s*script.*?>",           # <script>
    r"javascript\s*:",           # javascript:
    r"on\w+\s*=\s*['\"].*?['\"]",  # onerror="...", onclick="..."
    r"<\s*img.*?onerror",        # <img onerror=...>
]


def check_sqli(value: str) -> bool:
    value = value.lower()
    return any(re.search(p, value, re.IGNORECASE) for p in SQLI_PATTERNS)


def check_xss(value: str) -> bool:
    return any(re.search(p, value, re.IGNORECASE) for p in XSS_PATTERNS)


def _extract_strings(data) -> list[str]:
    """Flatten any dict/list/str into a list of string values to scan."""
    if isinstance(data, str):
        return [data]
    if isinstance(data, dict):
        return [str(v) for v in data.values()]
    if isinstance(data, list):
        return [str(item) for item in data]
    return []


def scan_request(ip: str, endpoint: str, method: str, body: dict, query_params: dict, path: str) -> dict:
    """
    Runs all security checks on the incoming request.
    Returns {"blocked": bool, "attack_type": str | None}
    """
    all_values = (
        _extract_strings(body)
        + _extract_strings(query_params)
        + [path]
    )

    attack_type = None

    for value in all_values:
        if check_sqli(value):
            attack_type = "SQLi"
            break
        if check_xss(value):
            attack_type = "XSS"
            break

    # Rate limit check — runs regardless of attack type
    request_count, is_rate_blocked = upsert_rate_limit(ip, endpoint)
    if is_rate_blocked and attack_type is None:
        attack_type = "Rate Limiting"

    was_blocked = attack_type is not None

    if was_blocked:
        log_security_event(ip, endpoint, method, attack_type, was_blocked)

    return {
        "blocked": was_blocked,
        "attack_type": attack_type,
        "request_count": request_count,
    }
