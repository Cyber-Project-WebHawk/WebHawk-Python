import re
from security_engine.Repository.security_repository import (
    log_security_event,
    upsert_rate_limit,
    get_dashboard_data,
)

# Fix #7: tightened to reduce false positives on ordinary English text while
# still catching the classic attack payloads. Notably:
#  - the OR/AND tautology pattern now requires a preceding quote character
#    (the actual injection "breakout" context), instead of matching any
#    "<word> and/or <word>=<word>" substring - which previously flagged
#    completely normal text like "width and height=100".
#  - the bare keyword pattern (drop/insert/delete/update/select followed by
#    whitespace) previously matched ordinary phrases like "select an option",
#    "update your profile", or "delete this item". Each keyword now requires
#    a recognizable SQL object-reference context next to it.
#
# Regex-based detection can never be 100% precise (that's fundamentally why
# production WAFs combine tokenization/parsing with many heuristics, not just
# regex) - this is a meaningful improvement, not a claim of perfect accuracy.
# The SELECT...FROM pattern in particular still has some residual risk on
# long sentences that happen to contain both words; the bounded gap below
# reduces, but does not eliminate, that risk.
SQLI_PATTERNS = [
    r"['\"]\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",  # ' OR 1=1, " AND 'a'='a'
    r"(--|#|/\*)",                                                 # SQL comment markers
    r"\b(drop|truncate)\s+table\b",                                # DROP/TRUNCATE TABLE
    r"\binsert\s+into\b",                                          # INSERT INTO
    r"\bdelete\s+from\b",                                          # DELETE FROM
    r"\bupdate\s+\w+\s+set\b",                                     # UPDATE <table> SET
    r"\bselect\b[\w\s,*.()]{0,40}\bfrom\b",                        # SELECT ... FROM (bounded gap)
    r"\bunion\b\s+(all\s+)?select\b",                              # UNION [ALL] SELECT
]

XSS_PATTERNS = [
    r"<\s*script.*?>",            # <script>
    r"javascript\s*:",            # javascript:
    r"on\w+\s*=\s*['\"].*?['\"]",  # onerror="...", onclick="..."
    r"<\s*img.*?onerror",         # <img onerror=...>
]

# How deep _extract_strings will recurse into nested dict/list structures.
# Bounded to guard against pathological/deeply-nested payloads being used as
# a resource-exhaustion vector.
MAX_SCAN_DEPTH = 10


def check_sqli(value: str) -> bool:
    value = value.lower()
    return any(re.search(p, value, re.IGNORECASE) for p in SQLI_PATTERNS)


def check_xss(value: str) -> bool:
    return any(re.search(p, value, re.IGNORECASE) for p in XSS_PATTERNS)


def _extract_strings(data, _depth: int = 0) -> list[str]:
    """
    Recursively flattens any combination of nested dicts/lists/strings into
    a flat list of string values to scan.

    Previously this only looked at top-level dict/list values and relied on
    Python's str() representation of any nested object to incidentally
    surface attacks buried deeper - which worked by accident for some
    payloads but wasn't a deliberate traversal. This walks the full
    structure explicitly, including dict keys (an attacker-controlled key
    name is just as valid an injection point as a value).
    """
    if _depth > MAX_SCAN_DEPTH:
        return []

    if isinstance(data, str):
        return [data]

    if isinstance(data, dict):
        values = []
        for k, v in data.items():
            values.append(str(k))
            values.extend(_extract_strings(v, _depth + 1))
        return values

    if isinstance(data, list):
        values = []
        for item in data:
            values.extend(_extract_strings(item, _depth + 1))
        return values

    if data is None or isinstance(data, (int, float, bool)):
        return []

    # Fallback for any other type - keeps behavior safe rather than silently
    # skipping a value we don't otherwise know how to walk.
    return [str(data)]


def scan_request(
    ip: str,
    endpoint: str,
    method: str,
    body: dict,
    query_params: dict,
    path: str,
    backend_key: str = "direct",
) -> dict:
    """
    Runs all security checks on the incoming request.
    Returns {"blocked": bool, "attack_type": str | None}

    Fix #6: `backend_key` scopes the rate-limit counter so that two
    unrelated backends sharing a Route name + source IP no longer share a
    single bucket. Calls made directly to /security/scan (with no
    associated registered backend) use the default "direct" scope.

    Every request is now logged to security_logs (both allowed and
    blocked), not just blocked ones - this is what powers the analytics
    dashboard's "total requests scanned" figure, which previously had no
    way to be computed since clean traffic was never recorded anywhere.
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
    request_count, is_rate_blocked = upsert_rate_limit(ip, endpoint, backend_key)
    if is_rate_blocked and attack_type is None:
        attack_type = "Rate Limiting"

    was_blocked = attack_type is not None

    log_security_event(ip, endpoint, method, attack_type or "None", was_blocked, backend_key)

    return {
        "blocked": was_blocked,
        "attack_type": attack_type,
        "request_count": request_count,
    }


def get_dashboard(backend_key=None, hours=24):
    """
    Bonus analytics dashboard: total requests scanned/blocked, a breakdown
    by attack type, and an hourly timeline of blocked attacks. Clamps
    `hours` to a sane range so a caller can't request an absurdly expensive
    aggregation window.
    """
    hours = max(1, min(int(hours), 24 * 30))  # 1 hour .. 30 days
    return get_dashboard_data(backend_key=backend_key, hours=hours)
