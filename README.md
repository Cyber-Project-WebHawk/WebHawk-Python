# WebHawk — SaaS Middleware Security Platform

A smart middleware service that protects backend applications from common web attacks in real time — similar to how Cloudflare WAF works.

Developers register their backend with WebHawk. From that point, every incoming request passes through WebHawk first — scanned for attacks before being forwarded to the real server.

> See [`CHANGELOG.md`](./CHANGELOG.md) for a list of hardening fixes applied to this codebase (auth on backend management, crash-safe error handling, per-backend rate limiting, etc.).

---

## Team

| Student | Responsibility |
|---|---|
| Student 1 — OrRam | User management — register, login, JWT, sessions |
| Student 2 — Romi | Security engine — SQLi, XSS, Rate Limiting |
| Student 3 — Noam | Backend registration, middleware proxy, vulnerable backend |

---

## Architecture

```
Client Request
      ↓
 WebHawk (port 5000)
      ↓
 ┌─────────────────────────────┐
 │  1. Authenticate API Key    │
 │  2. Scan for attacks        │
 │     - SQL Injection         │
 │     - XSS                  │
 │     - Rate Limiting         │
 └─────────────────────────────┘
      ↓ clean          ↓ attack
 Forward to         Block + Log
 real backend       (403 response)
      ↓
 Real Backend (port 5001)
```

### Layer Structure

```
WebHawk-Python/
├── app.py                          # Flask entry point + global error handlers
├── requirements.txt                # Pinned dependencies
├── requirements-dev.txt            # + pytest, for running the test suite
├── pytest.ini
├── .dockerignore
├── WebHawk.postman_collection.json # Importable Postman collection (all endpoints)
├── static/
│   └── dashboard.html              # Visual analytics dashboard (bonus feature)
├── tests/                          # pytest suite — unit + integration tests
│   ├── conftest.py                 # isolated test DB + Flask test client fixtures
│   ├── test_security_service.py    # SQLi/XSS detection, nested-JSON scanning
│   ├── test_auth.py                # register/login/logout/JWT edge cases
│   ├── test_backends.py            # ownership, auth, name-uniqueness
│   └── test_proxy.py               # attack blocking through the proxy
├── db/
│   ├── database.py                 # PostgreSQL connection pool (with retry/backoff)
│   └── create_tables.py            # Creates/migrates all 5 DB tables
├── route/                          # HTTP endpoints
│   ├── auth_middleware.py          # @require_auth decorator (JWT on backend mgmt routes)
│   ├── user_route.py               # /auth/*
│   └── backend_route.py            # /backends/*
├── service/                        # Business logic
│   ├── user_service.py             # bcrypt + JWT
│   └── backend_service.py          # API key generation + proxy (with error handling)
├── repository/                     # Database queries
│   ├── user_repository.py          # users + user_sessions
│   └── backend_repository.py       # backend_registration (owned per-user)
├── security_engine/                # Attack detection
│   ├── route/security_route.py     # /security/* (+ /security/dashboard)
│   ├── service/security_service.py # SQLi, XSS, Rate Limit logic
│   └── repository/security_repository.py # security_logs + rate_limit + dashboard queries
└── vulnerable_backend/
    └── app.py                      # Genuinely vulnerable test target (port 5001) - see warning below
```

---

## Database Tables

| Table | Description |
|---|---|
| `users` | Username, encrypted password, join date |
| `user_sessions` | JWT token, IP, expiry, active status |
| `backend_registration` | Service name, target URL, API key, active status, owning user |
| `security_logs` | Every scanned request — IP, endpoint, attack type, blocked?, which backend, timestamp |
| `rate_limit` | Request count per IP per endpoint per backend per time window |

---

## Running with Docker (Recommended)

### Requirements
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running

### Step 1 — Start all services
Open a terminal in the project root and run:
```bash
docker-compose up -d
```
This starts 3 containers:
| Container | What it is | Port |
|---|---|---|
| `webhawk_db` | PostgreSQL database | 5432 |
| `webhawk_app` | WebHawk security middleware | 5000 |
| `webhawk_vulnerable` | Vulnerable test backend | 5001 |

### Step 2 — Create the database tables (first time only)
```bash
docker exec webhawk_app python db/create_tables.py
```
Expected output: `Tables created successfully.`

### Step 3 — Verify everything is running
```bash
docker-compose ps
```
All 3 containers should show `Up`.

### Step 4 — Stop the project
```bash
docker-compose down
```

### Useful commands
| Action | Command |
|---|---|
| Start | `docker-compose up -d` |
| Stop | `docker-compose down` |
| View app logs | `docker logs webhawk_app` |
| View DB | `docker exec -it webhawk_db psql -U postgres -d webhawk -c "SELECT * FROM security_logs;"` |

---

## Setup (Without Docker)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Create `.env` file in the project root
```
DB_HOST=localhost
DB_NAME=webhawk
DB_USER=postgres
DB_PASSWORD=your_password
DB_PORT=5432
JWT_SECRET=your_long_random_secret
# Never set this to true outside of local development - it enables the
# interactive Werkzeug debugger, which leaks source code and stack traces
# on any unhandled error. Omit it (defaults to false) for any shared/demo use.
FLASK_DEBUG=true
```

### 3. Create the database tables
```bash
cd db
python create_tables.py
```

### 4. Run WebHawk
```bash
python app.py
```
Runs on `http://localhost:5000`

### 5. Run the vulnerable backend (for testing)
Open a second terminal:
```bash
python vulnerable_backend/app.py
```
Runs on `http://localhost:5001`

> ⚠️ **This backend is genuinely vulnerable, not a simulation.** Its
> `/login` and `/data` endpoints build real SQL queries via string
> formatting, and `/comment` stores unsanitized input. Hitting it directly
> (bypassing WebHawk) really does let you bypass auth with
> `admin' OR '1'='1` or exfiltrate every stored password with a UNION
> SELECT — that's the point: it's the "before" half of the demo. Never run
> it anywhere reachable from outside your own machine.

### 6. Run the test suite (optional)
```bash
pip install -r requirements-dev.txt
pytest
```
Tests spin up an isolated `webhawk_test` database (never your real one),
truncating tables between tests for isolation. Override `TEST_DB_HOST`,
`TEST_DB_NAME`, etc. as environment variables if your Postgres setup needs
different connection details than the defaults.

---

## API Endpoints

### Auth — `/auth`

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Login and receive JWT token |
| POST | `/auth/logout` | Invalidate session |
| GET | `/auth/me` | Get current user info |

**Register example:**
```json
POST /auth/register
{
  "username": "romi",
  "password": "securepass123"
}
```

**Login example:**
```json
POST /auth/login
{
  "username": "romi",
  "password": "securepass123"
}
```
Response:
```json
{
  "token": "eyJhbGc...",
  "expires_at": "2026-06-21T10:00:00"
}
```

---

### Backends — `/backends`

`/register`, `/` (list), `/activate`, and `/deactivate` now require a valid
JWT (`Authorization: Bearer <token>` from `/auth/login`) and are scoped to
the authenticated caller — you can only see, activate, or deactivate your
**own** backends. `/proxy/<path>` is unchanged and still uses `X-API-Key`,
since it's called by the backend's own end users, not by the dashboard owner.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/backends/register` | JWT | Register a backend and get an API key |
| GET | `/backends/` | JWT | List **your own** registered backends (no API keys returned — see below) |
| PATCH | `/backends/activate` | JWT | Activate one of **your own** backends |
| PATCH | `/backends/deactivate` | JWT | Deactivate one of **your own** backends |
| ANY (GET/POST/PUT/PATCH/DELETE) | `/backends/proxy/<path>` | `X-API-Key` | Proxy a request through WebHawk |

**Register a backend:**
```json
POST /backends/register
Headers: Authorization: Bearer <your JWT token>
{
  "name": "my-api",
  "target_url": "http://localhost:5001"
}
```
Response:
```json
{
  "api_key": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "name": "my-api",
  "target_url": "http://localhost:5001",
  "is_active": true
}
```
The API key is only ever shown **once**, in this response — `GET /backends/`
deliberately omits it, the same way most platforms only display a freshly
generated secret a single time. Backend names are unique per-account (two
different users may each register a backend with the same name).

**Proxy a request:**
```
POST /backends/proxy/login
Headers: X-API-Key: f47ac10b-58cc-4372-a567-0e02b2c3d479
Body: { "username": "admin", "password": "pass" }
```

---

### Security — `/security`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/security/scan` | none | Manually scan a request for attacks |
| GET | `/security/dashboard` | JWT | Analytics: totals, breakdown by attack type, timeline |

**Scan example:**
```json
POST /security/scan
{
  "endpoint": "/login",
  "method": "POST",
  "body": { "username": "admin' OR 1=1 --" },
  "query_params": {},
  "path": "/login"
}
```

**Dashboard example:**
```json
GET /security/dashboard?hours=24
Headers: Authorization: Bearer <your JWT token>
```
```json
{
  "total_scanned": 142,
  "total_blocked": 17,
  "breakdown_by_attack_type": [
    { "attack_type": "SQLi", "count": 10 },
    { "attack_type": "XSS", "count": 7 }
  ],
  "timeline": [
    { "bucket": "2026-06-25T14:00:00", "count": 5 },
    { "bucket": "2026-06-25T15:00:00", "count": 12 }
  ]
}
```
Add `?backend_key=<api_key>` to scope these figures to one specific
backend instead of the whole platform.

**A small visual dashboard** (bar chart of attack types + a timeline
graph, using Chart.js) is served at `http://localhost:5000/static/dashboard.html`
— paste a JWT token from `/auth/login` into the page to load it.

---

## Attack Detection

| Attack | Where Checked | Example |
|---|---|---|
| SQL Injection | Body, Query Params, Path (recursively through nested JSON) | `' OR 1=1 --` |
| XSS | Body, Query Params (recursively through nested JSON) | `<script>alert(1)</script>` |
| Rate Limiting | IP per endpoint per backend | 100+ requests/min from the same IP to the same path on the same backend |

Blocked requests return:
```json
HTTP 403
{
  "status": "blocked",
  "attack_type": "SQLi",
  "message": "Request blocked: SQLi detected"
}
```

---

## Testing with Postman

A ready-to-import collection covering every endpoint is included:
[`WebHawk.postman_collection.json`](./WebHawk.postman_collection.json).
Import it into Postman (File → Import) and run it top-to-bottom — Login and
Register Backend automatically save their token/api_key for the rest of the
collection to use.

Postman is a free app for sending HTTP requests. Download it from [postman.com/downloads](https://www.postman.com/downloads/).

If you'd rather build requests manually instead of importing the collection,
for every request:
1. Select the **method** (GET, POST, PATCH)
2. Enter the **URL**
3. Go to **Body → raw → JSON** and paste the JSON body
4. Click **Send**

---

### Test 1 — Register a user
```
Method: POST
URL: http://localhost:5000/auth/register
Body:
{
  "username": "romi",
  "password": "securepass123"
}
```
Expected `201`:
```json
{ "message": "User registered successfully", "user": { "id": 1, "username": "romi" } }
```

---

### Test 2 — Login and get a JWT token
```
Method: POST
URL: http://localhost:5000/auth/login
Body:
{
  "username": "romi",
  "password": "securepass123"
}
```
Expected `200`:
```json
{ "token": "eyJhbGc...", "expires_at": "..." }
```
**Copy the token value — you will need it for protected routes.**

---

### Test 3 — Register a backend
```
Method: POST
URL: http://localhost:5000/backends/register
Headers tab → add: Authorization = Bearer <your JWT token from Test 2>
Body:
{
  "name": "my-vulnerable-backend",
  "target_url": "http://vulnerable_backend:5001"
}
```
Expected `201`:
```json
{ "api_key": "f47ac10b-...", "name": "my-vulnerable-backend", "is_active": true }
```
**Copy the api_key value — you will need it for proxy requests.** This is
the only time the API key is returned; `GET /backends/` won't show it again.

---

### Test 4 — Send a clean request through the proxy
```
Method: POST
URL: http://localhost:5000/backends/proxy/login
Headers tab → add: X-API-Key = <your api_key>
Body:
{
  "username": "admin",
  "password": "admin123"
}
```
Expected `200` — request passed through to the real backend:
```json
{ "message": "Welcome admin!", "role": "admin" }
```

---

### Test 5 — SQL Injection attack (should be BLOCKED)
```
Method: POST
URL: http://localhost:5000/backends/proxy/login
Headers tab → add: X-API-Key = <your api_key>
Body:
{
  "username": "admin' OR 1=1 --",
  "password": "anything"
}
```
Expected `403`:
```json
{ "status": "blocked", "attack_type": "SQLi", "message": "Request blocked: SQLi detected" }
```

---

### Test 6 — XSS attack (should be BLOCKED)
```
Method: POST
URL: http://localhost:5000/backends/proxy/comment
Headers tab → add: X-API-Key = <your api_key>
Body:
{
  "text": "<script>alert(1)</script>"
}
```
Expected `403`:
```json
{ "status": "blocked", "attack_type": "XSS", "message": "Request blocked: XSS detected" }
```

---

### Test 7 — Check security logs in the DB
After running the attack tests, check what was logged:
```bash
docker exec -it webhawk_db psql -U postgres -d webhawk -c "SELECT * FROM security_logs;"
```
You should see one row per blocked attack.

---

## Technologies

| Technology | Purpose |
|---|---|
| Python + Flask | Web framework |
| PostgreSQL | Main database |
| bcrypt | Password hashing |
| PyJWT | JWT token generation and validation |
| requests | HTTP forwarding (proxy) |
| python-dotenv | Environment variable management |
