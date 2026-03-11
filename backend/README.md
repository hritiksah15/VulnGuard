# VulnGuard Backend API

> Enterprise vulnerability management REST API built with **Flask 3.1** and **MongoDB 8.2**.
>
> **Module:** COM661 – Full Stack Strategies and Development  
> **Author:** Hritik Sah  
> **Version:** 1.0  
> **Last Updated:** March 11, 2026

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Database Seeding](#database-seeding)
- [Document Schema](#document-schema)
- [Authentication & Authorization](#authentication--authorization)
- [API Endpoints Reference](#api-endpoints-reference)
  - [Authentication Endpoints](#authentication-endpoints)
  - [Vulnerability Endpoints](#vulnerability-endpoints)
  - [Remediation Steps Endpoints](#remediation-steps-endpoints)
  - [Activity Log Endpoints](#activity-log-endpoints)
  - [Analytics Endpoints](#analytics-endpoints)
  - [Admin Endpoints](#admin-endpoints)
- [Query Parameters](#query-parameters)
- [Request & Response Examples](#request--response-examples)
- [MongoDB Patterns Demonstrated](#mongodb-patterns-demonstrated)
- [Validation & Error Handling](#validation--error-handling)
- [Testing](#testing)
- [Scripts & Data Import](#scripts--data-import)
- [Production Deployment](#production-deployment)

---

## Architecture Overview

```
Client (Angular / Postman / curl)
  │
  ▼
┌──────────────────────────────────────────────────────┐
│  Flask Application (app.py – factory pattern)        │
│  ├─ CORS middleware                                  │
│  ├─ Request timing / structured logging              │
│  ├─ Error handler (JSON 400–500 responses)           │
│  └─ Blueprint router (/api/v1/*)                     │
│       ├─ auth_bp         → /api/v1/auth              │
│       ├─ vulnerabilities_bp → /api/v1/vulnerabilities │
│       ├─ remediation_bp  → /api/v1/vulnerabilities   │
│       ├─ activity_log_bp → /api/v1/vulnerabilities   │
│       ├─ analytics_bp    → /api/v1/analytics         │
│       └─ admin_bp        → /api/v1/admin             │
│                                                      │
│  Middleware chain:                                    │
│  ┌─────────────┐  ┌────────────────┐                │
│  │token_required│→│role_required(*) │→ route handler │
│  └─────────────┘  └────────────────┘                │
└──────────────────────────────────────────────────────┘
  │
  ▼
┌──────────────────┐
│  MongoDB 8.2     │
│  ├─ users        │
│  ├─ vulnerabilities (with sub-docs: remediation_steps, activity_log) │
│  ├─ blacklist    │  (TTL index – auto-expires after 24h)
│  └─ reports      │  (generated via $out aggregation)
└──────────────────┘
```

---

## Tech Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Framework | Flask | 3.1.0 | Application factory, blueprints, routing, `jsonify` |
| Database | MongoDB | 8.2.4 | Document store (CRUD, aggregation, geospatial, TTL) |
| Driver | PyMongo | 4.11.3 | Official MongoDB driver (find, insert_many, $geoNear) |
| Auth | PyJWT | 2.10.1 | JWT token encode/decode (HS256, jti claim) |
| Password | bcrypt | 4.2.1 | Password hashing (gensalt(12), hashpw, checkpw) |
| CORS | Flask-CORS | 5.0.1 | Cross-Origin Resource Sharing headers |
| Config | python-dotenv | 1.0.1 | Loads `.env` into `os.environ` |
| Server | Gunicorn | 23.0.0 | Production WSGI HTTP server |
| Language | Python | 3.14 | Runtime |

---

## Quick Start

### Prerequisites

- Python 3.10+
- MongoDB 6.0+ running on `localhost:27017`

### Installation

```bash
# Clone the repository
git clone <repo-url> && cd VulnGuard/backend

# Create virtual environment
python -m venv ../venv
source ../venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Copy environment config
cp .env.example .env
# Edit .env with your SECRET_KEY and MONGO_URI
```

### Seed the Database

```bash
python -m seeds.seed_data
```

This creates:
- **3 users** — admin, analyst, guest (bcrypt-hashed passwords)
- **109 vulnerabilities** with remediation steps, activity logs, and GeoJSON locations
- All required indexes (single-field, compound, text, 2dsphere, TTL)

### Document Schema

Each vulnerability document stored in MongoDB follows this structure:

```json
{
  "_id": "ObjectId",
  "cve_id": "CVE-2024-12345",
  "vulnerability_title": "SQL Injection in Login Form",
  "description": "Detailed description of the vulnerability",
  "severity": "Critical | High | Medium | Low",
  "cvss_score": 9.8,
  "status": "Open | In Progress | Patched | Accepted Risk",
  "vulnerability_type": "Software | Configuration | Access Control",
  "discovery_method": "Scan | Audit | Manual",
  "affected_product": "Product Name v1.0",
  "department": "Engineering",
  "asset_type": "Server | Workstation | Network Device | Application | Database | Cloud Service | IoT Device | Endpoint",
  "attack_vector": "Network | Adjacent | Local | Physical",
  "exploitability": "Active | Proof of Concept | Theoretical | Unproven",
  "patch_due_date": "2025-06-01T00:00:00",
  "location": {
    "type": "Point",
    "coordinates": [-1.4746, 53.3811]
  },
  "remediation_steps": [
    {
      "step_id": "ObjectId",
      "step_number": 1,
      "step_description": "Apply security patch version 2.1.1",
      "priority": "Critical | High | Medium | Low",
      "status": "Pending | In Progress | Completed | Verified",
      "recommended_by": "analyst",
      "added_at": "2025-01-15T10:30:00"
    }
  ],
  "activity_log": [
    {
      "log_id": "ObjectId",
      "user": "admin",
      "action": "Status changed to In Progress",
      "performed_at": "2025-01-15T10:30:00"
    }
  ],
  "created_at": "2025-01-01T00:00:00",
  "updated_at": "2025-01-15T10:30:00"
}
```

**Key Field Notes:**

| Field | Constraint |
|-------|-----------|
| `vulnerability_title` | Required, 5–200 characters |
| `vulnerability_type` | Required, enum: Software, Configuration, Access Control |
| `discovery_method` | Required, enum: Scan, Audit, Manual |
| `status` | Enum: Open, In Progress, Patched, Accepted Risk |
| `severity` | Enum: Critical, High, Medium, Low |
| `cvss_score` | Float 0.0–10.0 |
| `patch_due_date` | ISO 8601 datetime |
| `remediation_steps.step_description` | Required when adding a step |
| `remediation_steps.recommended_by` | Required when adding a step |
| `remediation_steps.added_at` | Auto-set on creation (UTC) |
| `activity_log.performed_at` | Auto-set on creation (UTC) |

### Run the Server

```bash
python run.py --port 5001
```

The API will be available at `http://localhost:5001/api/v1/`.

### Verify

```bash
curl http://localhost:5001/api/v1/health
# {"status": "success", "message": "VulnGuard API is running"}
```

---

## Project Structure

```
backend/
├── app.py                 # Application factory (create_app), index creation
├── config.py              # Config classes (Development, Testing, Production)
├── run.py                 # CLI entry point (--host, --port, --no-debug)
├── requirements.txt       # All Python dependencies with comments
├── .env                   # Environment variables (git-ignored)
├── .env.example           # Template for .env
│
├── middleware/             # Request processing pipeline
│   ├── auth_middleware.py  # @token_required — JWT validation + blacklist check
│   ├── rbac_middleware.py  # @role_required — role-based access control
│   └── error_handler.py   # Centralised JSON error responses (400–500)
│
├── routes/                # API endpoint definitions (6 Blueprints)
│   ├── __init__.py        # register_blueprints(app)
│   ├── auth/              # Registration, login, logout, profile, refresh, change-password
│   ├── vulnerabilities/   # Full CRUD + bulk + geospatial + advanced filters
│   ├── remediation/       # Sub-document CRUD ($push, $pull, positional $)
│   ├── activity_log/      # Sub-document CRUD for audit trail
│   ├── analytics/         # 11 aggregation pipeline endpoints + $out reports
│   └── admin/             # User management (list, update role, deactivate, delete)
│
├── utils/                 # Shared helper functions
│   ├── helpers.py         # get_db, serialize_doc, pagination, risk score
│   └── validators.py      # Type/range/enum/date/regex validation, constants
│
├── seeds/                 # Database seeding
│   └── seed_data.py       # 109 vulns, 3 users, GeoJSON locations, indexes
│
├── scripts/               # Data import utilities
│   ├── download_dataset.py   # Download CISA KEV catalog
│   ├── import_kev_data.py    # Import KEV data into VulnGuard format
│   └── import_cve_data.py    # Import NIST NVD CVE data
│
├── tests/                 # Test suites
│   ├── test_new_features.sh  # 37-test bash suite (all features)
│   ├── verify_endpoints.sh   # Basic endpoint verification
│   └── postman/              # Postman collection + environment
│       ├── VulnGuard.postman_collection.json  # 81 automated requests
│       └── VulnGuard.postman_environment.json # Environment variables
│
├── data/                  # Downloaded datasets (CISA KEV catalog)
└── logs/                  # Application logs (rotating, 10 MB × 5 backups)
```

---

## Configuration

Configuration is loaded via environment variables (`.env` file) into Python config classes.

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-in-production` | JWT signing key (HS256) |
| `MONGO_URI` | `mongodb://localhost:27017/vulnguard` | MongoDB connection string |
| `TEST_MONGO_URI` | `mongodb://localhost:27017/vulnguard_test` | Test database URI |
| `JWT_EXPIRY_HOURS` | `1` | Token expiry time in hours |
| `ITEMS_PER_PAGE` | `10` | Default pagination page size (max: 100) |
| `FLASK_ENV` | `development` | Environment mode |
| `FLASK_DEBUG` | `1` | Enable debug mode |

Three config classes in `config.py`:
- **DevelopmentConfig** — DEBUG enabled
- **TestingConfig** — separate test database
- **ProductionConfig** — DEBUG disabled

---

## Authentication & Authorization

### Authentication Flow

1. **Login** → `POST /api/v1/auth/login` with `{email, password}`
2. Server verifies bcrypt hash, returns JWT token with claims: `user_id`, `username`, `role`, `exp`, `iat`, `jti`
3. Client sends token via **`x-access-token`** header on protected routes
4. **Logout** → `POST /api/v1/auth/logout` — adds token to blacklist collection

### Token Details

- **Algorithm:** HS256
- **Uniqueness:** Every token includes a `jti` (JWT ID) claim using `uuid4()`
- **Header Name:** `x-access-token: <jwt_token>` 
- **Important:** This project does **NOT** use `Authorization: Bearer` scheme
- **Blacklisting:** Logged-out tokens stored in `blacklist` collection with TTL auto-cleanup (24h)

### Role-Based Access Control (RBAC)

| Role | Permissions |
|------|------------|
| **admin** | Full access — all CRUD, user management, analytics, delete operations |
| **analyst** | Create/update vulnerabilities, remediation steps, activity logs, analytics |
| **guest** | Read-only access to vulnerabilities and profile |

### Seeded Users

| Username | Email | Password | Role |
|----------|-------|----------|------|
| admin | admin@vulnguard.test | Admin@Secure123! | admin |
| analyst | analyst@vulnguard.test | Analyst@Secure123! | analyst |
| guest | guest@vulnguard.test | Guest@Secure123! | guest |

---

## API Endpoints Reference

**Base URL:** `http://localhost:5001/api/v1`  
**Content-Type:** `application/json`

### Authentication Endpoints

#### POST `/auth/register`
Register a new user account.

**Authentication:** None required  
**Authorization:** Public

**Request Body:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecureP@ss123!"
}
```

**Validation Rules:**
- `username`: 3–50 characters, alphanumeric + underscore
- `email`: Valid email format
- `password`: Minimum 8 characters, must include uppercase, lowercase, digit, and special character

**Response Codes:**
- `201` – User created successfully
- `400` – Missing required fields or duplicate email/username
- `422` – Validation error (weak password, invalid email format)

---

#### POST `/auth/login`
Authenticate user and receive JWT token.

**Authentication:** None required  
**Authorization:** Public

**Request Body:**
```json
{
  "email": "admin@vulnguard.test",
  "password": "Admin@Secure123!"
}
```

**Response (200):**
```json
{
  "status": "success",
  "message": "Login successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "username": "admin",
    "email": "admin@vulnguard.test",
    "role": "admin"
  }
}
```

**Response Codes:**
- `200` – Login successful
- `400` – Missing email or password
- `401` – Invalid credentials or account deactivated

---

#### POST `/auth/logout`
Blacklist current JWT token (invalidates it).

**Authentication:** Required (x-access-token)  
**Authorization:** Any authenticated user

**Request Headers:**
```
x-access-token: <jwt_token>
```

**Response (200):**
```json
{
  "status": "success",
  "message": "Logged out successfully"
}
```

**Response Codes:**
- `200` – Token blacklisted
- `401` – No token provided or invalid token

---

#### GET `/auth/profile`
Get current authenticated user's profile.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "id": "507f1f77bcf86cd799439011",
    "username": "admin",
    "email": "admin@vulnguard.test",
    "role": "admin",
    "is_active": true,
    "created_at": "2025-01-01T00:00:00Z"
  }
}
```

---

#### PUT `/auth/profile`
Update current user's profile details.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Request Body:**
```json
{
  "username": "new_username",
  "email": "new_email@example.com"
}
```

**Response Codes:**
- `200` – Profile updated
- `400` – Invalid input or duplicate email/username
- `401` – Authentication required
- `422` – Validation error

---

#### PUT `/auth/change-password`
Change current user's password.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Request Body:**
```json
{
  "current_password": "Admin@Secure123!",
  "new_password": "NewSecure@Pass456!"
}
```

**Response Codes:**
- `200` – Password changed successfully
- `400` – Incorrect current password
- `401` – Authentication required
- `422` – New password doesn't meet requirements

---

#### POST `/auth/refresh`
Refresh JWT token before expiry.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Response (200):**
```json
{
  "status": "success",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "message": "Token refreshed successfully"
}
```

---

### Vulnerability Endpoints

#### GET `/vulnerabilities`
Retrieve paginated list of vulnerabilities with filtering, sorting, and search.

**Authentication:** None required  
**Authorization:** Public

**Query Parameters:** See [Query Parameters](#query-parameters) section below.

**Response (200):**
```json
{
  "status": "success",
  "data": [
    {
      "_id": "507f1f77bcf86cd799439011",
      "cve_id": "CVE-2024-12345",
      "vulnerability_title": "SQL Injection in Login Form",
      "severity": "Critical",
      "cvss_score": 9.8,
      "status": "Open",
      "department": "Engineering",
      "created_at": "2025-01-15T10:30:00Z",
      ...
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 109,
    "pages": 11,
    "next_after": "507f1f77bcf86cd799439012"
  }
}
```

---

#### GET `/vulnerabilities/:id`
Retrieve a single vulnerability by ID.

**Authentication:** None required  
**Authorization:** Public

**Path Parameters:**
- `id` – MongoDB ObjectId (24-character hex string)

**Response Codes:**
- `200` – Vulnerability found
- `404` – Vulnerability not found

---

#### POST `/vulnerabilities`
Create a new vulnerability record.

**Authentication:** Required  
**Authorization:** admin, analyst

**Request Body:**
```json
{
  "cve_id": "CVE-2026-12345",
  "vulnerability_title": "SQL Injection in Login Form",
  "description": "The login form is vulnerable to SQL injection through the username field. Allows authentication bypass and potential data exfiltration.",
  "severity": "Critical",
  "cvss_score": 9.8,
  "status": "Open",
  "vulnerability_type": "Software",
  "discovery_method": "Scan",
  "affected_product": "WebApp v1.0.5",
  "department": "Engineering",
  "asset_type": "Application",
  "attack_vector": "Network",
  "exploitability": "Proof of Concept",
  "patch_due_date": "2026-04-01T00:00:00Z",
  "location": {
    "type": "Point",
    "coordinates": [-1.4746, 53.3811]
  }
}
```

**Required Fields:**
- `cve_id`, `vulnerability_title`, `description`, `severity`, `cvss_score`, `status`, `vulnerability_type`, `discovery_method`, `affected_product`, `department`, `asset_type`

**Validation Rules:**
- `cve_id`: Format `CVE-YYYY-NNNNN` (regex: `^CVE-\d{4}-\d{4,}$`)
- `vulnerability_title`: 5–200 characters
- `description`: 10–5000 characters
- `severity`: Enum – `Critical`, `High`, `Medium`, `Low`
- `cvss_score`: Float 0.0–10.0
- `status`: Enum – `Open`, `In Progress`, `Patched`, `Accepted Risk`
- `vulnerability_type`: Enum – `Software`, `Configuration`, `Access Control`
- `discovery_method`: Enum – `Scan`, `Audit`, `Manual`
- `asset_type`: Enum – `Server`, `Workstation`, `Network Device`, `Application`, `Database`, `Cloud Service`, `IoT Device`, `Endpoint`

**Response Codes:**
- `201` – Vulnerability created
- `400` – Missing required fields
- `401` – Authentication required
- `403` – Insufficient permissions (guest role)
- `422` – Validation error (invalid enum, CVSS out of range, etc.)

---

#### POST `/vulnerabilities/bulk`
Bulk create 2–50 vulnerabilities using `insert_many`.

**Authentication:** Required  
**Authorization:** admin, analyst

**Request Body:**
```json
{
  "vulnerabilities": [
    { /* vulnerability 1 */ },
    { /* vulnerability 2 */ },
    ...
  ]
}
```

**Validation:**
- Array must contain 2–50 vulnerability objects
- Each object validated as per single create

**Response (201):**
```json
{
  "status": "success",
  "message": "25 vulnerabilities created",
  "inserted_ids": ["507f...", "507f...", ...]
}
```

**Response Codes:**
- `201` – Bulk insert successful
- `400` – Array size out of bounds or missing
- `401` – Authentication required
- `403` – Insufficient permissions
- `422` – Validation error in one or more items

---

#### PUT `/vulnerabilities/:id`
Update an existing vulnerability.

**Authentication:** Required  
**Authorization:** admin, analyst

**Request Body:** (all fields optional, partial update supported)
```json
{
  "status": "Patched",
  "patch_due_date": "2026-03-15T00:00:00Z"
}
```

**Response Codes:**
- `200` – Vulnerability updated
- `400` – Invalid input
- `401` – Authentication required
- `403` – Insufficient permissions
- `404` – Vulnerability not found
- `422` – Validation error

---

#### DELETE `/vulnerabilities/:id`
Delete a vulnerability permanently.

**Authentication:** Required  
**Authorization:** admin only

**Response Codes:**
- `204` – Vulnerability deleted (no content)
- `401` – Authentication required
- `403` – Insufficient permissions (only admin can delete)
- `404` – Vulnerability not found

---

#### GET `/vulnerabilities/nearby`
Find vulnerabilities near a geographic location using `$geoNear` aggregation.

**Authentication:** None required  
**Authorization:** Public

**Query Parameters:**
- `lng` (required) – Longitude (float)
- `lat` (required) – Latitude (float)
- `radius` (required) – Search radius in kilometers (float)
- `limit` (optional) – Max results (default: 10, max: 100)

**Example:**
```
GET /vulnerabilities/nearby?lng=-1.4746&lat=53.3811&radius=50&limit=10
```

**Response (200):**
```json
{
  "status": "success",
  "data": [
    {
      "_id": "507f1f77bcf86cd799439011",
      "vulnerability_title": "XSS in Web Portal",
      "location": {
        "type": "Point",
        "coordinates": [-1.5, 53.4]
      },
      "distance_km": 3.2,
      ...
    }
  ],
  "count": 5
}
```

**Response Codes:**
- `200` – Results returned (may be empty array)
- `400` – Missing required parameters (lng, lat, radius)

---

### Remediation Steps Endpoints

Remediation steps are sub-documents within vulnerability documents. These endpoints use MongoDB `$push`, `$pull`, and positional `$` operators.

#### GET `/vulnerabilities/:vuln_id/remediation-steps`
List all remediation steps for a vulnerability.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "vulnerability_id": "507f1f77bcf86cd799439011",
    "remediation_steps": [
      {
        "step_id": "507f1f77bcf86cd799439012",
        "step_number": 1,
        "step_description": "Apply security patch version 2.1.1",
        "priority": "Critical",
        "status": "Completed",
        "recommended_by": "analyst",
        "added_at": "2025-01-15T10:30:00Z"
      }
    ]
  }
}
```

---

#### GET `/vulnerabilities/:vuln_id/remediation-steps/:step_id`
Retrieve a single remediation step.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Response Codes:**
- `200` – Step found
- `404` – Vulnerability or step not found

---

#### POST `/vulnerabilities/:vuln_id/remediation-steps`
Add a new remediation step (MongoDB `$push` operator).

**Authentication:** Required  
**Authorization:** admin, analyst

**Request Body:**
```json
{
  "step_number": 1,
  "step_description": "Apply vendor security patch KB5025221",
  "priority": "Critical",
  "status": "Pending",
  "recommended_by": "j.smith"
}
```

**Required Fields:**
- `step_number`, `step_description`, `priority`, `status`, `recommended_by`

**Validation:**
- `step_number`: Positive integer ≥ 1
- `step_description`: 5–1000 characters
- `priority`: Enum – `Critical`, `High`, `Medium`, `Low`
- `status`: Enum – `Pending`, `In Progress`, `Completed`, `Verified`

**Response Codes:**
- `201` – Step added
- `400` – Missing required fields
- `401` – Authentication required
- `403` – Insufficient permissions
- `404` – Vulnerability not found
- `422` – Validation error

---

#### PUT `/vulnerabilities/:vuln_id/remediation-steps/:step_id`
Update a specific remediation step (MongoDB positional `$` operator).

**Authentication:** Required  
**Authorization:** admin, analyst

**Request Body:** (all fields optional)
```json
{
  "status": "Completed",
  "step_description": "Updated step description"
}
```

**Response Codes:**
- `200` – Step updated
- `400` – Invalid input
- `401` – Authentication required
- `403` – Insufficient permissions
- `404` – Vulnerability or step not found
- `422` – Validation error

---

#### DELETE `/vulnerabilities/:vuln_id/remediation-steps/:step_id`
Remove a remediation step (MongoDB `$pull` operator).

**Authentication:** Required  
**Authorization:** admin, analyst

**Response Codes:**
- `204` – Step removed (no content)
- `401` – Authentication required
- `403` – Insufficient permissions
- `404` – Vulnerability or step not found

---

### Activity Log Endpoints

Activity log entries are sub-documents tracking audit trail.

#### GET `/vulnerabilities/:vuln_id/activity-log`
List all activity log entries for a vulnerability.

**Authentication:** Required  
**Authorization:** Any authenticated user

---

#### GET `/vulnerabilities/:vuln_id/activity-log/:log_id`
Retrieve a single activity log entry.

**Authentication:** Required  
**Authorization:** Any authenticated user

---

#### POST `/vulnerabilities/:vuln_id/activity-log`
Add a new activity log entry (MongoDB `$push` operator).

**Authentication:** Required  
**Authorization:** admin, analyst

**Request Body:**
```json
{
  "user": "admin",
  "action": "Status changed from Open to In Progress"
}
```

**Required Fields:**
- `user`, `action`

**Response Codes:**
- `201` – Entry added
- `400` – Missing required fields
- `401` – Authentication required
- `403` – Insufficient permissions
- `404` – Vulnerability not found

---

#### DELETE `/vulnerabilities/:vuln_id/activity-log/:log_id`
Delete an activity log entry.

**Authentication:** Required  
**Authorization:** admin only

**Response Codes:**
- `204` – Entry deleted (no content)
- `401` – Authentication required
- `403` – Insufficient permissions (admin only)
- `404` – Vulnerability or log entry not found

---

### Analytics Endpoints

All analytics endpoints use MongoDB aggregation pipelines with stages like `$match`, `$group`, `$project`, `$unwind`, `$facet`, `$sort`, `$limit`.

#### GET `/analytics/severity-distribution`
Group vulnerabilities by severity level.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Aggregation Pipeline:** `$group` by `severity`, `$sort` by count descending

**Response (200):**
```json
{
  "status": "success",
  "data": [
    {"_id": "Critical", "count": 25, "percentage": 22.9},
    {"_id": "High", "count": 42, "percentage": 38.5},
    {"_id": "Medium", "count": 30, "percentage": 27.5},
    {"_id": "Low", "count": 12, "percentage": 11.0}
  ]
}
```

---

#### GET `/analytics/department-risk`
Calculate risk exposure by department.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Aggregation Pipeline:** `$group` by `department`, calculate average CVSS, count vulnerabilities

**Response (200):**
```json
{
  "status": "success",
  "data": [
    {
      "_id": "Engineering",
      "vulnerability_count": 45,
      "avg_cvss": 7.8,
      "risk_score": 351.0
    },
    ...
  ]
}
```

---

#### GET `/analytics/overdue-patches`
List vulnerabilities with patch deadlines in the past.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Aggregation Pipeline:** `$match` where `patch_due_date < now` and `status != Patched`

---

#### GET `/analytics/patch-compliance`
Calculate patch compliance rate.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Aggregation Pipeline:** `$facet` separating patched vs not patched, calculate percentage

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "total_vulnerabilities": 109,
    "patched_count": 42,
    "unpatched_count": 67,
    "compliance_rate": 38.5
  }
}
```

---

#### GET `/analytics/vulnerability-trends`
Group vulnerabilities by creation month.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Aggregation Pipeline:** `$group` by year and month, `$sort` chronologically

---

#### GET `/analytics/top-affected-assets`
Rank assets by number of vulnerabilities.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Aggregation Pipeline:** `$group` by `affected_product`, `$sort` by count, `$limit` top 10

---

#### GET `/analytics/mean-time-to-remediation`
Calculate average time from discovery to patch.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Aggregation Pipeline:** `$match` patched items, `$project` with `$dateDiff`, `$group` with `$avg`

---

#### GET `/analytics/risk-scores`
Calculate and rank vulnerabilities by risk score.

**Authentication:** Required  
**Authorization:** admin, analyst

**Aggregation Pipeline:** `$project` with risk calculation formula, `$sort` descending

**Risk Score Formula:**
```
risk_score = cvss_score * severity_multiplier * exploitability_multiplier
```

---

#### GET `/analytics/summary`
Dashboard KPIs summary.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Aggregation Pipeline:** `$facet` with multiple sub-pipelines for different metrics

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "total_vulnerabilities": 109,
    "critical_count": 25,
    "open_count": 55,
    "avg_cvss": 6.8,
    "patched_count": 42,
    "overdue_count": 12
  }
}
```

---

#### POST `/analytics/generate-report`
Generate and persist analytics report using `$out` aggregation stage.

**Authentication:** Required  
**Authorization:** admin, analyst

**Aggregation Pipeline:** `$group` by department and severity → `$out` to `reports` collection

**Response (201):**
```json
{
  "status": "success",
  "message": "Report generated with 24 rows",
  "data": [
    {"department": "Engineering", "severity": "Critical", "count": 12},
    ...
  ]
}
```

---

#### GET `/analytics/reports`
Retrieve persisted reports from the `reports` collection.

**Authentication:** Required  
**Authorization:** Any authenticated user

**Response (200):**
```json
{
  "status": "success",
  "data": [
    {"department": "Engineering", "severity": "Critical", "count": 12},
    ...
  ],
  "count": 24
}
```

---

### Admin Endpoints

User management endpoints (admin only).

#### GET `/admin/users`
List all users.

**Authentication:** Required  
**Authorization:** admin only

**Response (200):**
```json
{
  "status": "success",
  "data": [
    {
      "_id": "507f1f77bcf86cd799439011",
      "username": "admin",
      "email": "admin@vulnguard.test",
      "role": "admin",
      "is_active": true,
      "created_at": "2025-01-01T00:00:00Z"
    },
    ...
  ]
}
```

---

#### GET `/admin/users/:id`
Get user details by ID.

**Authentication:** Required  
**Authorization:** admin only

---

#### PUT `/admin/users/:id/role`
Update user role.

**Authentication:** Required  
**Authorization:** admin only

**Request Body:**
```json
{
  "role": "analyst"
}
```

**Validation:**
- `role`: Enum – `admin`, `analyst`, `guest`

---

#### PUT `/admin/users/:id/status`
Activate or deactivate user account.

**Authentication:** Required  
**Authorization:** admin only

**Request Body:**
```json
{
  "is_active": false
}
```

---

#### DELETE `/admin/users/:id`
Delete user account.

**Authentication:** Required  
**Authorization:** admin only

**Response Codes:**
- `204` – User deleted
- `401` – Authentication required
- `403` – Insufficient permissions
- `404` – User not found

---

## Query Parameters

The `GET /vulnerabilities` endpoint supports extensive filtering, sorting, pagination, and search.

### Pagination

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number for skip/limit pagination |
| `per_page` | int | 10 | Items per page (max: 100) |
| `after` | ObjectId | — | Cursor for keyset pagination (use last item's `_id`) |

**Examples:**
- Skip/limit: `?page=2&per_page=25`
- Keyset: `?after=507f1f77bcf86cd799439011&per_page=25`

### Sorting

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sort_by` | string | `created_at` | Field to sort by |
| `sort_order` | string | `desc` | `asc` or `desc` |

**Sortable fields:** `cvss_score`, `created_at`, `updated_at`, `patch_due_date`, `severity`, `status`

### Exact Filters

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Exact severity match |
| `status` | string | Exact status match |
| `department` | string | Exact department match |
| `asset_type` | string | Exact asset type match |
| `vulnerability_type` | string | Exact vulnerability type match |
| `discovery_method` | string | Exact discovery method match |

**Example:** `?severity=Critical&status=Open`

### `$in` Filters (Multiple Values)

| Parameter | Type | MongoDB Operator | Description |
|-----------|------|-----------------|-------------|
| `severity_in` | string | `$in` | Comma-separated severities |
| `status_in` | string | `$in` | Comma-separated statuses |

**Example:** `?severity_in=Critical,High&status_in=Open,In Progress`

### Pattern Matching

| Parameter | Type | MongoDB Operator | Description |
|-----------|------|-----------------|-------------|
| `title_regex` | string | `$regex` | Case-insensitive regex on `vulnerability_title` |

**Example:** `?title_regex=SQL.*Injection`

### Full-Text Search

| Parameter | Type | MongoDB Operator | Description |
|-----------|------|-----------------|-------------|
| `search` | string | `$text` | Full-text search on `vulnerability_title` and `description` |

**Example:** `?search=buffer overflow`

### Range Filters

| Parameter | Type | MongoDB Operator | Description |
|-----------|------|-----------------|-------------|
| `min_cvss` | float | `$gte` | Minimum CVSS score |
| `max_cvss` | float | `$lte` | Maximum CVSS score |

**Example:** `?min_cvss=7.0&max_cvss=10.0`

### `$or` Combined Filters

Use multiple `or_*` parameters to create an `$or` query combining conditions.

| Parameter | Type | Description |
|-----------|------|-------------|
| `or_severity` | string | OR condition on severity |
| `or_status` | string | OR condition on status |
| `or_min_cvss` | float | OR condition on CVSS ≥ value |
| `or_department` | string | OR condition on department |

**Example:** `?or_severity=Critical&or_status=Open&or_min_cvss=9.0`  
**MongoDB Query:** `{"$or": [{"severity": "Critical"}, {"status": "Open"}, {"cvss_score": {"$gte": 9.0}}]}`

---

## Request & Response Examples

### Example 1: Login and Create Vulnerability

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:5001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vulnguard.test","password":"Admin@Secure123!"}' \
  | jq -r '.access_token')

# 2. Create vulnerability
curl -X POST http://localhost:5001/api/v1/vulnerabilities \
  -H "x-access-token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2026-99999",
    "vulnerability_title": "Remote Code Execution in API",
    "description": "Unauthenticated remote code execution vulnerability in REST API endpoint",
    "severity": "Critical",
    "cvss_score": 10.0,
    "status": "Open",
    "vulnerability_type": "Software",
    "discovery_method": "Manual",
    "affected_product": "API Gateway v2.1",
    "department": "Engineering",
    "asset_type": "Application",
    "attack_vector": "Network",
    "exploitability": "Active",
    "patch_due_date": "2026-03-20T00:00:00Z"
  }'
```

### Example 2: Advanced Filtering

```bash
# Find all Critical or High severity vulnerabilities that are Open or In Progress
curl "http://localhost:5001/api/v1/vulnerabilities?severity_in=Critical,High&status_in=Open,In%20Progress&sort_by=cvss_score&sort_order=desc"
```

### Example 3: Geospatial Search

```bash
# Find vulnerabilities within 100 km of Manchester, UK
curl "http://localhost:5001/api/v1/vulnerabilities/nearby?lng=-2.2426&lat=53.4808&radius=100&limit=20"
```

### Example 4: Add Remediation Step

```bash
curl -X POST http://localhost:5001/api/v1/vulnerabilities/507f1f77bcf86cd799439011/remediation-steps \
  -H "x-access-token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "step_number": 1,
    "step_description": "Upgrade to version 2.2.0 which includes security fix",
    "priority": "Critical",
    "status": "Pending",
    "recommended_by": "security_team"
  }'
```

### Example 5: Generate Analytics Report

```bash
# Generate report (persists to reports collection using $out)
curl -X POST http://localhost:5001/api/v1/analytics/generate-report \
  -H "x-access-token: $TOKEN"

# Retrieve persisted reports
curl http://localhost:5001/api/v1/analytics/reports \
  -H "x-access-token: $TOKEN"
```

---

```json
{
  "status": "error",
  "message": "Description of the error",
  "code": 400
}
```

| Code | Meaning |
|------|---------|
| 400 | Bad request (invalid JSON, missing required fields) |
| 401 | Authentication required or token invalid/expired/blacklisted |
| 403 | Insufficient role permissions |
| 404 | Resource not found |
| 422 | Validation error (invalid field values, enum, range) |
| 500 | Internal server error |

---

## MongoDB Patterns Demonstrated

| Pattern | Where Used | MongoDB Feature |
|---------|-----------|-----------------|
| Full CRUD | All resource routes | `find`, `find_one`, `insert_one`, `update_one`, `delete_one` |
| Bulk Operations | `POST /vulnerabilities/bulk` | `insert_many` |
| Sub-Document CRUD | Remediation steps, activity log | `$push`, `$pull`, positional `$` operator |
| Aggregation Pipelines | 11 analytics endpoints | `$match`, `$group`, `$project`, `$unwind`, `$sort`, `$facet`, `$dateDiff`, `$cond`, `$round` |
| `$out` Stage | `POST /analytics/generate-report` | Writes pipeline results to `reports` collection |
| Geospatial | `GET /vulnerabilities/nearby` | `2dsphere` index + `$geoNear` aggregation |
| Text Search | `?search=keyword` | `$text` index on `vulnerability_title` + `description` |
| Advanced Filters | Query params | `$in`, `$regex`, `$or`, `$gte`, `$lte` |
| Cursor Pagination | `?after=<objectid>` | Keyset pagination on `_id` (no skip) |
| Skip/Limit Pagination | `?page=N&per_page=N` | Traditional offset pagination |
| TTL Index | Token blacklist | `expireAfterSeconds: 86400` on `blacklisted_at` |
| Compound Index | Vulnerability filters | `(severity, status, department)` |
| Unique Index | Users | `email`, `username` |

---

## Validation & Error Handling

### Input Validation

Every write endpoint validates input with specific rules:

- **Type checking** — `isinstance()` for strings, numbers, booleans
- **Range checking** — CVSS score 0–10, string lengths, step_number ≥ 1
- **Enum validation** — severity, status, asset_type, attack_vector, exploitability, vulnerability_type, discovery_method, remediation statuses
- **Pattern validation** — CVE ID (`CVE-YYYY-NNNNN`), email regex, password strength (8+ chars, upper, lower, digit, special)
- **Date validation** — ISO 8601 parsing with error handling
- **ObjectId validation** — 24-character hex string check

### Centralised Error Handler

`middleware/error_handler.py` registers JSON handlers for all common HTTP error codes (400, 401, 403, 404, 405, 413, 422, 429, 500) plus a catch-all `Exception` handler. Every error response uses the same `{"status": "error", "message": ..., "code": ...}` format.

---

## Testing

### Bash Test Suite (`tests/test_new_features.sh`)

37 automated tests covering all implemented features:

```bash
cd backend && bash tests/test_new_features.sh
```

| Test Group | Tests | Covers |
|-----------|:-----:|--------|
| Login & tokens | 2 | Admin + analyst login |
| x-access-token | 2 | Profile via header |
| Logout & blacklist | 4 | Logout, blacklisted token rejection |
| Advanced filters | 4 | `$in`, `$regex`, `$text` |
| Cursor pagination | 3 | Keyset pagination, no duplicates |
| Geospatial | 4 | `/nearby`, missing params |
| `$or` filter | 3 | Combined OR query |
| Bulk create | 5 | `insert_many`, validation, auth |
| `$out` report | 4 | Generate + retrieve reports |
| Regression | 4 | Existing CRUD + analytics |
| **Total** | **37** | |

### Postman Collection (`tests/postman/`)

- **81 automated requests** with test scripts and Markdown descriptions
- **Seeded-data only** — starts from login, no registration required
- Sequential flow: Setup → Auth → CRUD → Remediation → Activity → Analytics → Admin → Cleanup
- Import `VulnGuard.postman_collection.json` and `VulnGuard.postman_environment.json` into Postman

---

## Scripts & Data Import

```bash
# Download CISA KEV catalog
python -m scripts.download_dataset

# Import KEV data
python -m scripts.import_kev_data --limit 50

# Import NIST NVD CVE data
python -m scripts.import_cve_data --year 2024
```

---

## Running in Production

```bash
gunicorn "app:create_app('production')" --bind 0.0.0.0:5000 --workers 4
```

---

## License

See [LICENSE](../LICENSE) in the project root.
