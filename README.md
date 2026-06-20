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

## Setup

### 1. Install dependencies
```bash
pip install flask psycopg2-binary python-dotenv bcrypt pyjwt requests
```

### 2. Create `.env` file in the project root
```
DB_HOST=localhost
DB_NAME=webhawk
DB_USER=postgres
DB_PASSWORD=your_password
DB_PORT=5432
JWT_SECRET=your_long_random_secret
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

| Method | Endpoint | Description |
|---|---|---|
| POST | `/backends/register` | Register a backend and get API key |
| GET | `/backends/` | List all registered backends |
| PATCH | `/backends/activate` | Activate a backend |
| PATCH | `/backends/deactivate` | Deactivate a backend |
| ANY | `/backends/proxy/<path>` | Proxy a request through WebHawk |

**Register a backend:**
```json
POST /backends/register
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

| Method | Endpoint | Description |
|---|---|---|
| POST | `/security/scan` | Manually scan a request for attacks |

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
| Rate Limiting | IP per endpoint | 100+ requests/min from same IP |

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

1. Register a user → `POST /auth/register`
2. Login → `POST /auth/login` → copy the token
3. Register a backend pointing to `http://localhost:5001` → copy the API key
4. Send an attack through the proxy:
```
POST /backends/proxy/login
X-API-Key: <your api key>
Body: { "username": "admin' OR 1=1 --", "password": "anything" }
```
Expected: `403 Blocked — SQLi detected`

5. Send a clean request:
```
POST /backends/proxy/login
X-API-Key: <your api key>
Body: { "username": "admin", "password": "admin123" }
```
Expected: `200 OK` — forwarded to the real backend

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
