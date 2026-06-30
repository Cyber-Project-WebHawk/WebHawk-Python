# WebHawk — SaaS Middleware Security Platform

A smart middleware service that protects backend applications from common web attacks in real time — similar to how Cloudflare WAF works.

Developers register their backend with WebHawk. From that point, every incoming request passes through WebHawk first — scanned for attacks before being forwarded to the real server.

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
├── app.py                          # Flask entry point
├── db/
│   ├── database.py                 # PostgreSQL connection
│   └── create_tables.py            # Creates all 5 DB tables
├── Route/                          # HTTP endpoints
│   ├── user_route.py               # /auth/*
│   └── backend_route.py            # /backends/*
├── Service/                        # Business logic
│   ├── user_service.py             # bcrypt + JWT
│   └── backend_service.py          # API key generation + proxy
├── Repository/                     # Database queries
│   ├── user_repository.py          # users + user_sessions
│   └── backend_repository.py       # backend_registration
├── security_engine/                # Attack detection
│   ├── route/security_route.py     # /security/*
│   ├── service/security_service.py # SQLi, XSS, Rate Limit logic
│   └── repository/security_repository.py # security_logs + rate_limit
└── vulnerable_backend/
    └── app.py                      # Intentionally vulnerable test target (port 5001)
```

---

## Database Tables

| Table | Description |
|---|---|
| `users` | Username, encrypted password, join date |
| `user_sessions` | JWT token, IP, expiry, active status |
| `backend_registration` | Service name, target URL, API key, active status |
| `security_logs` | Blocked requests — IP, endpoint, attack type, timestamp |
| `rate_limit` | Request count per IP per endpoint per time window |

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
| `webhawk_db` | PostgreSQL database | 5433 (host) → 5432 (container) |
| `webhawk_app` | WebHawk security middleware | 5000 |
| `webhawk_vulnerable` | Vulnerable test backend | 5001 |

### Step 2 — Create the database tables (first time only)

Tables are created **automatically** when the `webhawk_app` container starts.

If you need to run it manually (non-Docker setup):
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
| Stop + wipe database | `docker-compose down -v` |
| Rebuild after code changes | `docker-compose up -d --build` |
| View app logs | `docker logs webhawk_app` |
| View DB logs | `docker logs webhawk_db` |
| Query security logs | `docker exec -it webhawk_db psql -U postgres -d webhawk -c "SELECT * FROM security_logs;"` |

---

## Setup (Without Docker)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Create `.env` file in the project root
Copy `.env.example` and fill in your values:
```bash
cp .env.example .env
```
```
DB_HOST=localhost
DB_NAME=webhawk
DB_USER=postgres
DB_PASSWORD=your_password
DB_PORT=5432
JWT_SECRET=your_long_random_secret
```

### 3. Create the database tables
Run from the **project root**:
```bash
python db/create_tables.py
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

> **All `/backends/register`, `/backends/`, `/backends/activate`, and `/backends/deactivate` endpoints require a valid JWT token.**
> Add the header: `Authorization: Bearer <token>` (token from `/auth/login`).
> The proxy endpoint `/backends/proxy/<path>` uses `X-API-Key` instead.

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| POST | `/backends/register` | JWT token | Register a backend and get API key |
| GET | `/backends/` | JWT token | List all registered backends |
| PATCH | `/backends/activate` | JWT token | Activate a backend |
| PATCH | `/backends/deactivate` | JWT token | Deactivate a backend |
| ANY | `/backends/proxy/<path>` | X-API-Key header | Proxy a request through WebHawk |

**Register a backend:**
```
POST /backends/register
Headers: Authorization: Bearer <your_jwt_token>
Body:
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

**Proxy a request:**
```
POST /backends/proxy/login
Headers: X-API-Key: f47ac10b-58cc-4372-a567-0e02b2c3d479
Body: { "username": "admin", "password": "pass" }
```

---

### Security — `/security`

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| POST | `/security/scan` | None | Manually scan a request for attacks |
| GET | `/security/dashboard` | JWT token | Analytics: scanned/blocked counts, breakdown, timeline |

Open the visual dashboard at `http://localhost:5000/dashboard` (paste a JWT from `/auth/login`).

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

---

## Attack Detection

| Attack | Where Checked | Example |
|---|---|---|
| SQL Injection | Body, Query Params, Path | `' OR 1=1 --` |
| XSS | Body, Query Params | `<script>alert(1)</script>` |
| Rate Limiting | IP + endpoint + backend (API key) | 100+ requests/min from same IP |

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

Postman is a free app for sending HTTP requests. Download it from [postman.com/downloads](https://www.postman.com/downloads/).

In Postman, for every request:
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

### Test 2b — Verify current user (`/auth/me`)
```
Method: GET
URL: http://localhost:5000/auth/me
Headers tab → add: Authorization = Bearer <your_token_from_test_2>
```
Expected `200`:
```json
{ "user_id": 1, "username": "romi" }
```

---

### Test 3 — Register a backend
```
Method: POST
URL: http://localhost:5000/backends/register
Headers tab → add: Authorization = Bearer <your_token_from_test_2>
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
**Copy the api_key value — you will need it for proxy requests.**

---

### Test 3b — List all registered backends
```
Method: GET
URL: http://localhost:5000/backends/
Headers tab → add: Authorization = Bearer <your_token_from_test_2>
```
Expected `200`:
```json
[{ "id": 1, "name": "my-vulnerable-backend", "target_url": "...", "is_active": true }]
```
Note: `api_key` is only returned once at registration, not in the list response.

---

### Test 3c — Deactivate a backend
```
Method: PATCH
URL: http://localhost:5000/backends/deactivate
Headers tab → add: Authorization = Bearer <your_token_from_test_2>
Body:
{
  "api_key": "<your_api_key_from_test_3>"
}
```
Expected `200`:
```json
{ "id": 1, "name": "my-vulnerable-backend", "is_active": false }
```
Re-activate it before continuing:
```
Method: PATCH
URL: http://localhost:5000/backends/activate
Headers tab → add: Authorization = Bearer <your_token_from_test_2>
Body: { "api_key": "<your_api_key>" }
```

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

### Test 8 — Logout
```
Method: POST
URL: http://localhost:5000/auth/logout
Headers tab → add: Authorization = Bearer <your_token_from_test_2>
```
Expected `200`:
```json
{ "message": "Logged out successfully" }
```
After logout, using the same token on any protected route returns `401 Session is not active`.

---

## Running Tests

### Option A — Docker (recommended)

```bash
docker compose up -d db
docker compose --profile test run --rm tester
```

### Option B — Local PostgreSQL

Install test dependencies and ensure PostgreSQL is running with credentials matching `tests/conftest.py` (defaults: user `postgres`, password `webhawk1234`, database recreated as `webhawk_test`):

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Expected output: **127 tests passed** (integration tests use a real PostgreSQL test database).

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
| pytest | Test suite (`pip install -r requirements-dev.txt`) |
