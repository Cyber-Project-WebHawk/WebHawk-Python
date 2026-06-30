# WebHawk — Fixes Applied

This documents the 10 fixes from the audit report, what changed, which files
were touched, and how each one was verified. Every fix below was tested live
against a real PostgreSQL database and both Flask services — not just read
for syntax — including re-running the full Postman collection through
`newman` end-to-end with all 15 requests passing.

---

## Fix #1 — Global error handler + debug mode off by default

**Problem:** `app.run(debug=True, ...)` was hardcoded, and there was no
`@app.errorhandler` anywhere. Any unhandled exception (a `None` body, a dead
upstream, a DB hiccup) returned the full interactive Werkzeug debugger —
source code, file paths, and a stack trace — straight in the HTTP response.

**Changed:** `app.py`

- Added `@app.errorhandler` for 400/404/405/415 and a catch-all
  `@app.errorhandler(Exception)`, all returning clean JSON.
- `debug=True` is now read from `FLASK_DEBUG` (default `"false"`). Set
  `FLASK_DEBUG=true` only for local development; `docker-compose.yml` now
  explicitly sets it to `"false"`.

**Verified:** sent a literal `null` JSON body to `/auth/register` — used to
return a full debugger HTML page; now returns
`{"error": "username and password are required"}` with status 400.

---

## Fix #2 — Proxy no longer crashes on unreachable/non-JSON upstreams

**Problem:** `proxy_request()` called `requests.request(...)` and
`response.json()` with no error handling. A dead backend or a backend
returning plain HTML (e.g. a 404 page) crashed WebHawk with an unhandled
`ConnectionError` or `JSONDecodeError`.

**Changed:** `Service/backend_service.py`

- Wrapped the outbound call: `ConnectionError` → `502`, `Timeout` → `504`,
  any other `RequestException` → `502`.
- Wrapped `response.json()`: on failure, returns a JSON envelope with the
  upstream's raw text/content-type instead of crashing.
- Added a `timeout=10` to the outbound request (it had none before).

**Verified:** registered a backend pointing at a dead port → proxying to it
now returns `502 {"error": "Could not reach the target backend"}` instead of
a 500 + debugger leak. Proxying to a route the upstream doesn't have now
returns the upstream's actual 404 body wrapped in clean JSON, status
preserved.

---

## Fix #3 — `request.json` no longer crashes on `None`

**Problem:** Every route did `data = request.json` then `data.get(...)`. A
literal JSON `null` body, a missing `Content-Type`, or malformed JSON syntax
made `data` `None`, and `.get()` on `None` raised an unhandled
`AttributeError`.

**Changed:** `Route/user_route.py`, `Route/backend_route.py`,
`security_engine/route/security_route.py`

- Every occurrence of `request.json` replaced with
  `request.get_json(silent=True) or {}`, which never raises and never
  returns `None`.

**Verified:** `null` body, missing `Content-Type`, and malformed JSON syntax
all now fall through to the existing validation logic and return a clean
`400` instead of crashing, on every affected route.

---

## Fix #4 — Authentication + ownership on backend management

**Problem:** `GET /backends/` (which included every backend's plaintext
`api_key`), `PATCH /backends/activate`, and `PATCH /backends/deactivate` had
no authentication at all. `backend_registration` had no link to any user.

**Changed:**
- `db/create_tables.py` — added `user_id INTEGER REFERENCES users(id)` to
  `backend_registration` (idempotent `ALTER TABLE ... ADD COLUMN IF NOT
  EXISTS` for already-existing databases).
- `Route/auth_middleware.py` *(new file)* — a `@require_auth` decorator that
  validates the `Authorization: Bearer <token>` header and injects
  `user_id` into the view.
- `Route/backend_route.py` — `register`, `list_all`, `activate`,
  `deactivate` are now decorated with `@require_auth`.
- `Repository/backend_repository.py` / `Service/backend_service.py` —
  every backend-management function now takes `user_id` and scopes its
  query to it. `update_backend_status` matches `api_key AND user_id`, so a
  valid key for someone else's backend behaves identically to an unknown
  key (no enumeration). `list_backends` never returns `api_key` — it's
  shown once, at creation, like most platforms handle a freshly-issued
  secret.
- `/backends/proxy/<path>` is **unchanged** — it's called by the backend's
  own end users via `X-API-Key`, not by the dashboard owner, so it
  intentionally has a different auth model.

**Verified:** anonymous `GET /backends/` → `401`. A second user's JWT trying
to deactivate the first user's backend → `404` (not `403` — doesn't reveal
that the key exists). The owning user's JWT → `200` and it actually
deactivates.

---

## Fix #5 — Postman collection

**Problem:** the assignment's submission requirements explicitly ask for a
Postman collection covering all endpoints. None existed anywhere in the
repo.

**Added:** `WebHawk.postman_collection.json` — covers every endpoint
(Auth, Backend Management, Proxy, Security Engine), using collection
variables (`base_url`, `token`, `api_key`) so Login and Register Backend
automatically populate the variables later requests need.

**Verified:** installed `newman` (Postman's CLI runner) and ran the entire
collection top-to-bottom against the live app: **all 15 requests returned
exactly the expected status code** (201/200s for the happy path, 401 for
missing auth, 403 for the SQLi/XSS attack samples). This is a real,
importable, working collection, not just a JSON file that happens to
validate against the schema.

---

## Fix #6 — Rate limiting scoped per-backend

**Problem:** `rate_limit` was keyed by `(ip, endpoint)` only. Two unrelated
registered backends that both happened to expose a route with the same name
(e.g. both have a `/data` endpoint) and were hit from the same source IP
shared a single counter — a noisy client of backend A could get backend B
rate-limited too.

**Changed:**
- `db/create_tables.py` — `rate_limit` now has a `backend_key` column,
  `UNIQUE (ip, endpoint, backend_key)` instead of `UNIQUE (ip, endpoint)`
  (idempotent migration included for existing databases).
- `security_engine/repository/security_repository.py` —
  `upsert_rate_limit()` takes `backend_key` and includes it in the
  `ON CONFLICT` target.
- `security_engine/service/security_service.py` — `scan_request()` takes
  `backend_key` (default `"direct"` for calls made straight to
  `/security/scan` with no associated backend).
- `Route/backend_route.py` — the proxy passes the caller's `api_key` through
  as `backend_key`, so each registered backend gets its own bucket.

**Verified:** hammered one backend's `/data` endpoint past the 100-request
threshold (confirmed blocked). Immediately registered a brand-new,
never-before-used backend and hit its `/data` endpoint once, from the same
IP — it returned `200`, not blocked, because it's scoped to a different
`backend_key`. Confirmed via direct DB query that `rate_limit` now holds
separate rows per backend for the same `(ip, endpoint)` pair.

---

## Fix #7 — SQLi regex false positives reduced

**Problem:** the OR/AND tautology pattern matched any
`<word> and/or <word>=<word>` substring with no requirement that it actually
look like an injection breakout (e.g. `"width and height=100"` was blocked
as SQLi). The bare-keyword pattern (`drop|insert|delete|update|select`
followed by whitespace) matched ordinary English verbs (e.g. "please select
your country", "update your profile", "delete this item").

**Changed:** `security_engine/service/security_service.py` —
`SQLI_PATTERNS` rewritten:
- OR/AND tautology now requires a preceding quote character (the actual
  injection breakout context), not just any whitespace.
- `drop`/`truncate` require `table` right after them.
- `insert` requires `into`, `delete` requires `from`, `update` requires
  `<word> set` — each anchored to its real SQL object-reference context
  instead of matching as a bare verb.
- `select ... from` kept, with a bounded character-class gap (≤40 chars) to
  reduce (not eliminate — see code comment) false positives on long
  sentences that happen to contain both words.

**Verified:** `' OR 1=1 --`, `1' UNION SELECT * FROM users--`, and
`<script>` attacks via body/query/path are all still blocked. The previously
false-flagged text (`"width and height=100, please confirm"`) and a second
check (`"Please select your country, then update your profile, then delete
this draft."`) both now pass through as `201 Created` instead of being
blocked.

This is a meaningful improvement, not a claim of perfect accuracy — regex
can't fully replace a real SQL tokenizer, which is why production WAFs
combine many heuristics. The residual risk (a sentence containing both
"select" and, within 40 characters, "from") is called out in a code comment.

---

## Fix #8 — Pinned `requirements.txt`

**Problem:** dependencies were only declared as an unpinned list inline in
the `Dockerfile`, duplicated by hand in the README. No version pinning
anywhere — a future `pip install` could silently pull a breaking version.

**Added:** `requirements.txt` (root) and `vulnerable_backend/requirements.txt`,
both with pinned versions. Both Dockerfiles now `COPY requirements.txt .` and
`RUN pip install -r requirements.txt` instead of an inline package list.
README's non-Docker setup instructions updated to `pip install -r
requirements.txt`.

---

## Fix #9 — Backend name uniqueness enforced (per-owner)

**Problem:** nothing stopped two backends from being registered with the
identical `name` — only `api_key` was unique.

**Changed:**
- `db/create_tables.py` — added `UNIQUE (user_id, name)` on
  `backend_registration` (idempotent migration for existing databases).
- `Repository/backend_repository.py` — `register_backend()` now INSERTs
  directly and catches `psycopg2.errors.UniqueViolation`, inspecting
  `e.diag.constraint_name` to distinguish a name collision from an (almost
  impossible) `api_key` collision. This also closes a check-then-insert
  race condition that would otherwise exist.
- Names are unique **per owner**, not globally — the same way two different
  GitHub users can each have a repo named the same thing. This is a
  deliberate design choice given Fix #4 added real ownership; document and
  adjust if your grader expects global uniqueness instead.

**Verified:** registering the same name twice under the same JWT → `409
{"error": "A backend with this name already exists on your account"}`. A
second user registering that same name → `201 Created` (different owner).

---

## Fix #10 — Repo hygiene

- Deleted three stray, empty (0-byte) `app.py` files sitting in
  `Repository/`, `Route/`, and `Service/` since the initial scaffolding
  commit.
- Added `.dockerignore` (`.git`, `.env*`, `__pycache__/`, venvs, etc.) so
  `docker build`'s `COPY . .` doesn't risk pulling in a local `.env` or other
  unwanted files.
- `docker-compose.yml` — added a `healthcheck` to the `db` service
  (`pg_isready`) and changed `webhawk`'s `depends_on` to
  `condition: service_healthy`, so the app container only starts once
  Postgres is actually accepting connections, not just "started."
- `db/database.py` — added bounded retry/backoff (`DB_CONNECT_MAX_RETRIES`,
  `DB_CONNECT_RETRY_DELAY`, both env-configurable) around the initial
  connection attempt, as defense-in-depth alongside the healthcheck.

---

## Re-verification summary

After all 10 fixes, the entire previous crash/security-finding list was
re-tested live against the modified code:

| Previous finding | Now |
|---|---|
| `null` body crashes 5 endpoints | Fixed — clean 400 on all of them |
| Proxy crashes on dead/non-JSON upstream | Fixed — 502/wrapped JSON response |
| `GET /backends/` leaks all API keys, no auth | Fixed — 401 without auth; scoped + key omitted with auth |
| Activate/deactivate, no auth | Fixed — 401 without auth, 404 for wrong owner |
| Cross-tenant rate-limit bleed | Fixed — confirmed separate buckets per backend |
| SQLi false positive on ordinary text | Fixed — confirmed two previously-flagged phrases now pass |
| No Postman collection | Fixed — added, and verified via `newman` (15/15 requests pass) |
| Duplicate backend names | Fixed — enforced per-owner, with race-condition-safe insert |
| No `requirements.txt` | Fixed — added, pinned, wired into both Dockerfiles |
| Stray files / no `.dockerignore` / no DB healthcheck | Fixed |

All previously-passing functionality (JWT expiry/forgery/`alg:none`
rejection, SQLi/XSS detection on real attacks, rate limiting at the correct
threshold, the full proxy round-trip) was re-confirmed working after these
changes — nothing in this pass broke existing behavior.

---

# Round 2 — Closing the remaining gaps

The fixes above closed every Critical and High severity issue. This round
closes everything left on the list: the Medium and Low severity bugs, plus
the items the audit named as gaps but weren't formal bugs — no automated
tests, a simulated (not real) vulnerable backend, and the unbuilt bonus
analytics dashboard.

One genuinely new bug was found and fixed *during* this round, by
continuing to test live rather than just writing code — see "Bonus find"
below.

## Medium severity fixes

**Logout idempotency.** `deactivate_session()` now only matches a
currently-*active* session (`WHERE token = %s AND is_active = true`).
Logging out an already-inactive token now correctly returns `404`
instead of a false `200 "Logged out successfully"`.
*Changed: `repository/user_repository.py`.*

**Proxy method coverage.** Added `PATCH` to the proxy's registered
methods and corrected the README to state the exact supported set instead
of overclaiming `ANY`.
*Changed: `route/backend_route.py`, `README.md`.*

**Nested JSON is now deliberately scanned, not incidentally.**
`_extract_strings()` is now a real recursive walk through nested
dicts/lists (depth-bounded at 10 to avoid a pathological-payload DoS
vector), and now scans dict **keys** too, not just values — an
attacker-controlled key name is just as valid an injection point as a
value. Previously, nested attacks were only caught as an accidental side
effect of Python's `str()` representation of nested objects.
*Changed: `security_engine/service/security_service.py`.*

**`security_logs` now records every scanned request, not just blocked
ones.** Previously `was_blocked` was always `true` in practice, because
`log_security_event()` was only ever called from inside `if was_blocked:`.
This made "total requests scanned" uncomputable — which is also what
unblocked the bonus dashboard below. `security_logs` gained a
`backend_key` column (mirroring `rate_limit`'s scoping) and an index on
`created_at` for the dashboard's timeline query.
*Changed: `db/create_tables.py`, `security_engine/repository/security_repository.py`,
`security_engine/service/security_service.py`.*

## Low severity fixes

**JWT secret hardening.** The hardcoded fallback secret
(`"webhawk_secret_key"`) is gone. If `JWT_SECRET` isn't set, the app now
fails fast at import time with a clear `RuntimeError` instead of silently
signing tokens with a secret that's sitting in plain sight in this
project's own git history.
*Changed: `service/user_service.py`.*

**Connection pooling.** Every repository function used to open a brand-new
TCP connection to Postgres and close it immediately after - on every
single call. `db/database.py` now maintains a `ThreadedConnectionPool`
(`get_connection()` borrows, `release_connection()` returns), with the
same retry/backoff as before applied once, at pool-creation time, rather
than per-call. All three repository modules were updated to use
`release_connection()` instead of `conn.close()`, including in `finally`
blocks so a connection is never leaked on an exception path.
*Changed: `db/database.py`, `repository/user_repository.py`,
`repository/backend_repository.py`, `security_engine/repository/security_repository.py`.*

**PEP 8 package naming.** `Route/`, `Service/`, `Repository/` are now
`route/`, `service/`, `repository/` — matching the lowercase convention
`security_engine`'s own subpackages already used. All imports updated
accordingly; `__init__.py` added to each for consistency.
*If you're merging this into a git history on a case-insensitive
filesystem (default on Windows and macOS), a straight `git mv Route route`
won't register as a rename - do it in two steps
(`git mv Route Route_tmp && git mv Route_tmp route`), which is exactly
how this rename was performed here.*

## Bonus find: a real, newly-discovered crash bug

While re-testing the above live, two logins by the same user within the
same wall-clock second produced a **byte-identical JWT** — `exp` is
truncated to whole seconds, and with the same `user_id`/`username`, the
entire token matched exactly. The second login then crashed with an
unhandled `psycopg2.errors.UniqueViolation` on `user_sessions.token`'s
UNIQUE constraint (confirmed via direct reproduction with a tight loop of
back-to-back logins). This bug pre-dates every fix in this document — it
was always there, just never triggered by manual testing.

**Fixed with a `jti` claim** (JWT ID — the standard RFC 7519 claim for
exactly this purpose): every token now includes a fresh `uuid4`, so two
tokens for the same user are never identical regardless of timing.
`create_session()` also now defensively catches a `UniqueViolation` as a
backstop (returns a clean error instead of raising), even though `jti`
makes that path essentially unreachable in practice.
*Changed: `service/user_service.py`, `repository/user_repository.py`,
`route/user_route.py` (maps the new failure mode to `500`, not the
misleading `401`).*

## Real automated test suite

Added `tests/` (pytest), `requirements-dev.txt`, `pytest.ini`. **55 tests,
all passing:**
- `test_security_service.py` — pure unit tests for `check_sqli`,
  `check_xss`, and the recursive `_extract_strings` (no DB needed).
- `test_auth.py` — registration, login, the `jti` regression, JWT
  expiry/forgery/`alg:none` rejection, logout idempotency.
- `test_backends.py` — auth requirements, per-owner name uniqueness,
  cross-user ownership enforcement (404, not 403 — no enumeration).
- `test_proxy.py` — SQLi/XSS blocking including the nested-JSON case and
  the false-positive regression check.

`conftest.py` spins up an isolated `webhawk_test` database (drops and
rebuilds it by actually invoking `db/create_tables.py` as a subprocess —
exercising the real documented setup path, not a parallel
reimplementation of it), truncating tables before every test for
isolation regardless of execution order.

## Vulnerable backend is now genuinely vulnerable

`vulnerable_backend/app.py` previously "detected" SQLi via a hardcoded
`username.endswith("' OR '1'='1")` string check — it never ran a real
query, so it didn't actually demonstrate how the attack works, only that
WebHawk's pattern matcher recognized the same string. It's been rewritten
to use a small SQLite database with **real, intentionally unparameterized
queries**:
- `/login` builds its `WHERE username = '...' AND password = '...'` clause
  via plain string formatting — `admin' OR '1'='1` genuinely bypasses
  authentication.
- `/data?id=...` concatenates `id` directly into the query —
  `?id=1 UNION SELECT username,password FROM users` genuinely exfiltrates
  every stored credential.
- `/comment` stores input completely unescaped (real stored-XSS pattern).

Verified live: both payloads work for real when sent directly to port
5001, and are both blocked when sent through WebHawk's proxy on port
5000 — the actual before/after demo the assignment asks for.
*Changed: `vulnerable_backend/app.py`.*

## Bonus analytics dashboard — now implemented

Two parts, matching the spec's three asks (totals, breakdown by type, a
timeline graph):
- **`GET /security/dashboard`** (JWT-protected) — returns
  `total_scanned`, `total_blocked`, `breakdown_by_attack_type`, and an
  hourly `timeline` of blocked attacks. Optional `?backend_key=` scopes
  the figures to one specific backend instead of the whole platform;
  `?hours=` controls the timeline window (clamped to 1–720 hours).
- **`static/dashboard.html`** — a small dark-themed page (vanilla JS +
  Chart.js from a CDN, no build step) that calls the endpoint above and
  renders a bar chart (breakdown by type) and a line chart (timeline),
  plus three summary stat cards. Served automatically by Flask's default
  static-file handling at `/static/dashboard.html`.
*Added: `security_engine/repository/security_repository.py`
(`get_dashboard_data`), `security_engine/service/security_service.py`
(`get_dashboard`), `security_engine/route/security_route.py`
(`GET /security/dashboard`), `static/dashboard.html`.*

## Datetime deprecation cleanup

`pytest`'s own warning output flagged `datetime.utcnow()` as deprecated
(scheduled for removal in a future Python version). Replaced with
`datetime.now(timezone.utc).replace(tzinfo=None)` everywhere it appeared —
same naive-UTC value as before (matching the `TIMESTAMP` *without* time
zone columns), just via the non-deprecated path. Re-verified the full test
suite and the JWT expiry tests both still pass after the change.
*Changed: `repository/user_repository.py`, `service/user_service.py`,
`security_engine/repository/security_repository.py`.*

## Re-verification summary (round 2)

| Item | Verified via |
|---|---|
| Logout idempotency | Live curl: 200 then 404 on a second logout; `tests/test_auth.py::TestLogout::test_double_logout_is_404_not_200` |
| Nested JSON scanning | Live curl: SQLi/XSS buried 2 levels deep, inside lists, and inside dict keys, all blocked; 7 tests in `tests/test_security_service.py::TestExtractStringsRecursion` |
| `security_logs` always-log + dashboard | Live curl against `/security/dashboard`, both global and `?backend_key=`-scoped |
| JWT secret fail-fast | Reproduced with `.env` genuinely absent (not just scrubbed from `os.environ`, which `load_dotenv()` would otherwise repopulate) |
| Connection pooling | App stayed healthy across 50 rapid sequential requests; full Postman collection (15/15) and full pytest suite (55/55) both pass under the pooled connection |
| PEP 8 renaming | `python3 -c "import app"` succeeds; full regression suite passes |
| `jti` collision fix | 5 rapid back-to-back logins in a tight loop now produce 5 distinct tokens (previously crashed on the 2nd); `test_rapid_repeated_logins_produce_distinct_tokens` |
| Real vulnerable backend | Direct exploit (auth bypass + UNION-based credential dump) confirmed working against port 5001 directly, and confirmed blocked through WebHawk's proxy on port 5000 |
| Test suite | 55/55 passing, run fresh as the very last step before packaging |
| Dashboard | Full data flow verified: attack → blocked → logged → aggregated correctly in both the JSON endpoint and the rendered chart contract |

The full original 15-request Postman collection was re-run via `newman`
after every major change in this round and passed 15/15 each time, with
zero tracebacks in the server log throughout.
